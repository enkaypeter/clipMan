package controllers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"clipMan/config"
	"clipMan/database"
	"clipMan/models"
	"clipMan/routes" // Assuming SetupClipboardRoutes is here
	"clipMan/utils"  // For JWT generation

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/suite"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

// ClipboardTestSuite holds the state for the test suite
type ClipboardTestSuite struct {
	suite.Suite
	Router    *gin.Engine
	TestUser  *models.User
	AuthToken string
}

// SetupSuite runs once before all tests in the suite
func (suite *ClipboardTestSuite) SetupSuite() {
	config.LoadConfig()
	// Override DB name for testing
	originalDBName := config.AppConfig.MongoDB
	config.AppConfig.MongoDB = "clipboardDB_test"
	log.Printf("Using test database: %s", config.AppConfig.MongoDB)

	// Ensure JWT Secret is set for tests, if not already by LoadConfig
	if config.AppConfig.JWTSecret == "" {
		config.AppConfig.JWTSecret = "test_secret_key_for_jwt_1234567890" // Use a consistent test secret
		log.Println("Using a default JWT_SECRET for testing as it was not set.")
	}


	_, err := database.Connect()
	suite.Require().NoError(err, "Failed to connect to MongoDB")

	gin.SetMode(gin.TestMode)
	suite.Router = gin.New() // Use gin.New() for a clean router
	routes.SetupClipboardRoutes(suite.Router) // Setup only clipboard routes for focused testing
	// If user routes are needed for user creation within tests via API:
	// routes.SetupUserRoutes(suite.Router)


	// Create a default test user for the suite
	suite.TestUser = suite.createTestUser("testuser", "test@example.com", "password123")
	suite.AuthToken, err = utils.GenerateJWT(suite.TestUser) // Corrected call
	suite.Require().NoError(err, "Failed to generate test user token")

	// Restore original DB name if other tests depend on it, though ideally tests run isolated
	// For now, we assume this suite is the only one running or other suites handle their DB config
	 config.AppConfig.MongoDB = originalDBName
}

// TearDownSuite runs once after all tests in the suite
func (suite *ClipboardTestSuite) TearDownSuite() {
	// It's good practice to clean up the test database
	// config.LoadConfig() // Reload to get test DB name if changed
	// config.AppConfig.MongoDB = "clipboardDB_test" // Ensure correct DB name
	// _, err := database.Connect() // Reconnect if necessary
	// if err == nil {
	// 	log.Printf("Attempting to drop test database: %s", config.AppConfig.MongoDB)
	// 	err = database.MongoClient.Database(config.AppConfig.MongoDB).Drop(context.Background())
	// 	suite.NoError(err, "Failed to drop test database")
	// } else {
	// 	log.Printf("Could not connect to DB to drop test database: %v", err)
	// }
	// database.Disconnect()
	// Above drop logic can be problematic if Connection is not robust or config is tricky.
	// A safer bet for teardown is clearing collections if Drop is an issue.

	// Restore original DB name after tests
	// Note: This assumes AppConfig is a pointer and changes are seen globally.
	// If AppConfig was copied, this wouldn't work as expected.
	// For now, we are directly modifying the global AppConfig.
	// A better approach might be to pass config around or use a test-specific config file.

	// Let's ensure the test database is properly cleaned up without dropping if that's safer
	client, err := database.Connect()
	if err == nil {
		dbToClean := client.Database("clipboardDB_test") // Use the explicit test DB name
		err = dbToClean.Collection(string(config.DB_Collection.Entries)).Drop(context.Background())
		log.Printf("Dropped entries collection from clipboardDB_test: %v", err)
		err = dbToClean.Collection(string(config.DB_Collection.Users)).Drop(context.Background())
		log.Printf("Dropped users collection from clipboardDB_test: %v", err)
		database.Disconnect()
	} else {
		log.Printf("Failed to connect to DB for teardown clean: %v", err)
	}
}

// SetupTest runs before each test
func (suite *ClipboardTestSuite) SetupTest() {
	// Clear clipboard entries before each test for isolation
	// User collection is usually kept unless tests specifically modify users
	collection := database.GetCollection(config.DB_Collection.Entries)
	_, err := collection.DeleteMany(context.Background(), bson.M{})
	suite.Require().NoError(err, "Failed to clear 'entries' collection before test")

	// Re-generate token or re-create user if tests modify them
	// For now, assume TestUser created in SetupSuite is sufficient for most tests
	// If a test deletes or modifies the suite.TestUser, it should handle its own user setup/teardown
}

// createTestUser is a helper to insert a user directly into the DB for testing
func (suite *ClipboardTestSuite) createTestUser(username, email, password string) *models.User {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	suite.Require().NoError(err)

	user := &models.User{
		ID:        primitive.NewObjectID(),
		Username:  username,
		Email:     email,
		Password:  string(hashedPassword),
		CreatedAt: time.Now(),
	}

	collection := database.GetCollection(config.DB_Collection.Users)
	_, err = collection.InsertOne(context.Background(), user)
	suite.Require().NoError(err)
	return user
}

// makeRequest is a helper to create and execute HTTP requests for testing
func (suite *ClipboardTestSuite) makeRequest(method, url, token string, body io.Reader, headers map[string]string) *httptest.ResponseRecorder {
	req, err := http.NewRequest(method, url, body)
	suite.Require().NoError(err)

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	rr := httptest.NewRecorder()
	suite.Router.ServeHTTP(rr, req)
	return rr
}

// TestClipboardTestSuite runs the test suite
func TestClipboardTestSuite(t *testing.T) {
	// Ensure this is run only if not in short mode or if integration tests are explicitly enabled
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode.")
	}
	suite.Run(t, new(ClipboardTestSuite))
}

// Actual test cases will follow, e.g.:
// func (suite *ClipboardTestSuite) TestCreateTextClip_Success() { ... }

// --- Example: Test POST /api/clipboard - Create Text Clip ---
func (suite *ClipboardTestSuite) TestCreateTextClip_Success() {
	payload := gin.H{
		"content": "This is a test text clip",
		"type": "text", // Ensure type is specified if your model/handler expects it
	}
	jsonPayload, _ := json.Marshal(payload)

	headers := map[string]string{"Content-Type": "application/json"}
	rr := suite.makeRequest(http.MethodPost, "/api/clipboard", suite.AuthToken, bytes.NewBuffer(jsonPayload), headers)

	suite.Equal(http.StatusCreated, rr.Code, "Status code should be 201 Created")

	var responseBody map[string]string
	err := json.Unmarshal(rr.Body.Bytes(), &responseBody)
	suite.NoError(err, "Failed to unmarshal response body")
	suite.Contains(responseBody, "id", "Response should contain an ID for the created clip")

	// Optionally, verify in DB
	clipID, err := primitive.ObjectIDFromHex(responseBody["id"])
	suite.NoError(err)
	var createdEntry models.ClipboardEntry
	entryCollection := database.GetCollection(config.DB_Collection.Entries)
	err = entryCollection.FindOne(context.Background(), bson.M{"_id": clipID, "user_id": suite.TestUser.ID}).Decode(&createdEntry)
	suite.NoError(err, "Created entry not found in DB or does not belong to test user")
	suite.Equal("This is a test text clip", createdEntry.Content)
	suite.Equal("text", createdEntry.Type)
}

func (suite *ClipboardTestSuite) TestCreateTextClip_Unauthorized() {
	payload := gin.H{"content": "This is a test text clip", "type": "text"}
	jsonPayload, _ := json.Marshal(payload)
	headers := map[string]string{"Content-Type": "application/json"}

	// No token provided
	rr := suite.makeRequest(http.MethodPost, "/api/clipboard", "", bytes.NewBuffer(jsonPayload), headers)
	suite.Equal(http.StatusUnauthorized, rr.Code, "Status code should be 401 Unauthorized")
}


// --- Example: Test POST /api/clipboard - Create File Clip ---
func (suite *ClipboardTestSuite) TestCreateFileClip_Success() {
	// Create a temporary file for upload
	tempDir := suite.T().TempDir() // Creates a temporary directory that is cleaned up after the test
	tempFilePath := filepath.Join(tempDir, "testfile.txt")
	err := os.WriteFile(tempFilePath, []byte("This is a test file content."), 0644)
	suite.Require().NoError(err)

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	// Create a form file field
	part, err := writer.CreateFormFile("file", filepath.Base(tempFilePath))
	suite.Require().NoError(err)

	file, err := os.Open(tempFilePath)
	suite.Require().NoError(err)
	defer file.Close()

	_, err = io.Copy(part, file)
	suite.Require().NoError(err)

	// Add other form fields if necessary, e.g. type
	// _ = writer.WriteField("type", "file") // Your handler might infer this or require it

	err = writer.Close() // This finalizes the body and writes the boundary
	suite.Require().NoError(err)

	headers := map[string]string{"Content-Type": writer.FormDataContentType()}
	rr := suite.makeRequest(http.MethodPost, "/api/clipboard", suite.AuthToken, body, headers)

	suite.Equal(http.StatusCreated, rr.Code, "Status code should be 201 Created for file upload")

	var responseBody map[string]interface{} // Using interface{} for ID as it's ObjectID
	err = json.Unmarshal(rr.Body.Bytes(), &responseBody)
	suite.NoError(err, "Failed to unmarshal response body for file upload")
	suite.Contains(responseBody, "id", "Response should contain an ID for the created file clip")

	// Verify in DB
	clipIDHex, ok := responseBody["id"].(string)
	suite.True(ok, "Clip ID in response is not a string")
	clipID, err := primitive.ObjectIDFromHex(clipIDHex)
	suite.NoError(err)

	var createdEntry models.ClipboardEntry
	entryCollection := database.GetCollection(config.DB_Collection.Entries)
	err = entryCollection.FindOne(context.Background(), bson.M{"_id": clipID, "user_id": suite.TestUser.ID}).Decode(&createdEntry)
	suite.NoError(err, "Created file entry not found in DB or does not belong to test user")
	suite.Equal("file", createdEntry.Type)
	suite.Equal("testfile.txt", createdEntry.Filename)
	// suite.NotEmpty(createdEntry.Filepath, "Filepath should not be empty for file clips") // Assuming ./uploads/... structure

	// Cleanup: Remove the uploaded file if your handler saves it and you want to clean it
	// This depends on how your CopyClipboard handles file storage.
	// If it saves to a predictable path related to `dst` in `CopyClipboard`, you can remove it.
	// For example, if dst is `fmt.Sprintf("./uploads/%s", fileHeader.Filename)`
	// os.Remove(fmt.Sprintf("./uploads/%s", "testfile.txt"))
	// Ensure the "uploads" directory exists for the test or is created.
	// For simplicity in unit/integration tests, actual file system interaction is sometimes mocked
	// or handled carefully with temporary directories.
	// The test above assumes the 'uploads' dir exists relative to where tests are run.
	// It's better to make this path configurable or use os.MkdirAll if the handler doesn't create it.
	// For now, we are not cleaning up the file system here, assuming it's handled or a non-issue for test env.
	// If the `uploads` directory is not created by the application before saving, this test might fail
	// if the directory doesn't exist. Let's create it if it doesn't exist for the test.
	uploadsDir := "./uploads"
	if _, err := os.Stat(uploadsDir); os.IsNotExist(err) {
		err = os.MkdirAll(uploadsDir, 0755)
		suite.Require().NoError(err, "Failed to create uploads directory for testing")
	}
	// And attempt to remove the test file after test
	defer os.Remove(filepath.Join(uploadsDir, "testfile.txt"))

}

// --- Tests for GET /api/clipboard (List Clips with Pagination) ---

func (suite *ClipboardTestSuite) TestGetClips_Empty() {
	rr := suite.makeRequest(http.MethodGet, "/api/clipboard", suite.AuthToken, nil, nil)
	suite.Equal(http.StatusOK, rr.Code)

	var responseBody map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &responseBody)
	suite.NoError(err)

	suite.Equal(float64(0), responseBody["pagination"].(map[string]interface{})["total_entries"])
	suite.Len(responseBody["data"], 0, "Data should be an empty array")
}

func (suite *ClipboardTestSuite) TestGetClips_WithDataAndPagination() {
	// Create some entries for the test user
	entryCollection := database.GetCollection(config.DB_Collection.Entries)
	entries := []models.ClipboardEntry{
		{ID: primitive.NewObjectID(), UserId: suite.TestUser.ID, Type: "text", Content: "Clip 1", Timestamp: time.Now().Add(-3 * time.Hour)},
		{ID: primitive.NewObjectID(), UserId: suite.TestUser.ID, Type: "text", Content: "Clip 2", Timestamp: time.Now().Add(-2 * time.Hour)},
		{ID: primitive.NewObjectID(), UserId: suite.TestUser.ID, Type: "text", Content: "Clip 3", Timestamp: time.Now().Add(-1 * time.Hour)},
	}
	for _, entry := range entries {
		_, err := entryCollection.InsertOne(context.Background(), entry)
		suite.Require().NoError(err)
	}
	// Create an entry for another user to ensure it's not fetched
	otherUser := suite.createTestUser("otheruser", "other@example.com", "password")
	_, err := entryCollection.InsertOne(context.Background(), models.ClipboardEntry{
		ID:      primitive.NewObjectID(),
		UserId:  otherUser.ID,
		Type:    "text",
		Content: "Other user clip",
	})
	suite.Require().NoError(err)


	// Test default pagination (page=1, limit=10)
	rr := suite.makeRequest(http.MethodGet, "/api/clipboard", suite.AuthToken, nil, nil)
	suite.Equal(http.StatusOK, rr.Code)
	var responseBody map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &responseBody)

	suite.Equal(float64(3), responseBody["pagination"].(map[string]interface{})["total_entries"])
	data, ok := responseBody["data"].([]interface{})
	suite.True(ok, "Data field is not an array")
	suite.Len(data, 3, "Should fetch 3 entries for the authenticated user")
	// Check order (newest first)
	suite.Equal("Clip 3", data[0].(map[string]interface{})["content"])


	// Test custom pagination (page=2, limit=1)
	rr = suite.makeRequest(http.MethodGet, "/api/clipboard?page=2&limit=1", suite.AuthToken, nil, nil)
	suite.Equal(http.StatusOK, rr.Code)
	json.Unmarshal(rr.Body.Bytes(), &responseBody)

	suite.Equal(float64(3), responseBody["pagination"].(map[string]interface{})["total_entries"])
	suite.Equal(float64(2), responseBody["pagination"].(map[string]interface{})["current_page"])
	suite.Equal(float64(1), responseBody["pagination"].(map[string]interface{})["limit"])
	data, _ = responseBody["data"].([]interface{})
	suite.Len(data, 1)
	suite.Equal("Clip 2", data[0].(map[string]interface{})["content"])
}

// --- Tests for GET /api/clipboard/:id (Get Specific Clip) ---
func (suite *ClipboardTestSuite) TestGetClipByID_Success() {
	entryTime := time.Now().Truncate(time.Millisecond) // Truncate for comparison
	entry := models.ClipboardEntry{
		ID:        primitive.NewObjectID(),
		UserId:    suite.TestUser.ID,
		Type:      "text",
		Content:   "Specific Clip Content",
		Timestamp: entryTime,
	}
	entryCollection := database.GetCollection(config.DB_Collection.Entries)
	_, err := entryCollection.InsertOne(context.Background(), entry)
	suite.Require().NoError(err)

	url := fmt.Sprintf("/api/clipboard/%s", entry.ID.Hex())
	rr := suite.makeRequest(http.MethodGet, url, suite.AuthToken, nil, nil)
	suite.Equal(http.StatusOK, rr.Code)

	var fetchedEntry models.ClipboardEntry
	err = json.Unmarshal(rr.Body.Bytes(), &fetchedEntry)
	suite.NoError(err)
	suite.Equal(entry.ID, fetchedEntry.ID)
	suite.Equal(entry.Content, fetchedEntry.Content)
	suite.True(entry.Timestamp.Equal(fetchedEntry.Timestamp.In(entry.Timestamp.Location())), "Timestamps do not match")
}

func (suite *ClipboardTestSuite) TestGetClipByID_NotFound() {
	nonExistentID := primitive.NewObjectID()
	url := fmt.Sprintf("/api/clipboard/%s", nonExistentID.Hex())
	rr := suite.makeRequest(http.MethodGet, url, suite.AuthToken, nil, nil)
	suite.Equal(http.StatusNotFound, rr.Code)
}

func (suite *ClipboardTestSuite) TestGetClipByID_Forbidden() {
	otherUser := suite.createTestUser("otheruser2", "other2@example.com", "password")
	entry := models.ClipboardEntry{
		ID:      primitive.NewObjectID(),
		UserId:  otherUser.ID, // Belongs to another user
		Type:    "text",
		Content: "Another user's specific clip",
	}
	entryCollection := database.GetCollection(config.DB_Collection.Entries)
	_, err := entryCollection.InsertOne(context.Background(), entry)
	suite.Require().NoError(err)

	url := fmt.Sprintf("/api/clipboard/%s", entry.ID.Hex())
	// Authenticated as suite.TestUser, trying to access otherUser's clip
	rr := suite.makeRequest(http.MethodGet, url, suite.AuthToken, nil, nil)
	suite.Equal(http.StatusNotFound, rr.Code) // Should be 404 as if it doesn't exist for this user
}

// --- Tests for PATCH /api/clipboard/:id (Update Clip) ---
func (suite *ClipboardTestSuite) TestUpdateClip_Success_TextContent() {
	entry := models.ClipboardEntry{
		ID:      primitive.NewObjectID(),
		UserId:  suite.TestUser.ID,
		Type:    "text",
		Content: "Original Content",
		Pinned:  false,
	}
	entryCollection := database.GetCollection(config.DB_Collection.Entries)
	_, err := entryCollection.InsertOne(context.Background(), entry)
	suite.Require().NoError(err)

	updatePayload := gin.H{"content": "Updated Content", "pinned": true}
	jsonPayload, _ := json.Marshal(updatePayload)
	headers := map[string]string{"Content-Type": "application/json"}
	url := fmt.Sprintf("/api/clipboard/%s", entry.ID.Hex())

	rr := suite.makeRequest(http.MethodPatch, url, suite.AuthToken, bytes.NewBuffer(jsonPayload), headers)
	suite.Equal(http.StatusOK, rr.Code)

	var updatedEntry models.ClipboardEntry
	err = json.Unmarshal(rr.Body.Bytes(), &updatedEntry)
	suite.NoError(err)
	suite.Equal("Updated Content", updatedEntry.Content)
	suite.True(updatedEntry.Pinned)
	suite.NotEqual(entry.Timestamp, updatedEntry.Timestamp, "Timestamp should update when content changes")

	// Verify in DB
	var dbEntry models.ClipboardEntry
	err = entryCollection.FindOne(context.Background(), bson.M{"_id": entry.ID}).Decode(&dbEntry)
	suite.NoError(err)
	suite.Equal("Updated Content", dbEntry.Content)
	suite.True(dbEntry.Pinned)
}

func (suite *ClipboardTestSuite) TestUpdateClip_Success_PinFile() {
	entry := models.ClipboardEntry{
		ID:       primitive.NewObjectID(),
		UserId:   suite.TestUser.ID,
		Type:     "file",
		Filename: "test.txt",
		Filepath: "/uploads/test.txt",
		Pinned:   false,
	}
	entryCollection := database.GetCollection(config.DB_Collection.Entries)
	_, err := entryCollection.InsertOne(context.Background(), entry)
	suite.Require().NoError(err)

	updatePayload := gin.H{"pinned": true} // Only updating pinned status
	jsonPayload, _ := json.Marshal(updatePayload)
	headers := map[string]string{"Content-Type": "application/json"}
	url := fmt.Sprintf("/api/clipboard/%s", entry.ID.Hex())

	rr := suite.makeRequest(http.MethodPatch, url, suite.AuthToken, bytes.NewBuffer(jsonPayload), headers)
	suite.Equal(http.StatusOK, rr.Code)

	var updatedEntry models.ClipboardEntry
	err = json.Unmarshal(rr.Body.Bytes(), &updatedEntry)
	suite.NoError(err)
	suite.True(updatedEntry.Pinned)
	suite.Equal(entry.Filename, updatedEntry.Filename) // Other fields should remain
}

func (suite *ClipboardTestSuite) TestUpdateClip_Fail_UpdateFileContent() {
	entry := models.ClipboardEntry{
		ID:       primitive.NewObjectID(),
		UserId:   suite.TestUser.ID,
		Type:     "file",
		Filename: "original.txt",
		Pinned:   false,
	}
	entryCollection := database.GetCollection(config.DB_Collection.Entries)
	_, err := entryCollection.InsertOne(context.Background(), entry)
	suite.Require().NoError(err)

	updatePayload := gin.H{"content": "Attempt to update file content"}
	jsonPayload, _ := json.Marshal(updatePayload)
	headers := map[string]string{"Content-Type": "application/json"}
	url := fmt.Sprintf("/api/clipboard/%s", entry.ID.Hex())

	rr := suite.makeRequest(http.MethodPatch, url, suite.AuthToken, bytes.NewBuffer(jsonPayload), headers)
	// Expecting a 400 Bad Request as per controller logic
	suite.Equal(http.StatusBadRequest, rr.Code)
}


func (suite *ClipboardTestSuite) TestUpdateClip_NotFound() {
	nonExistentID := primitive.NewObjectID()
	updatePayload := gin.H{"content": "Doesn't matter"}
	jsonPayload, _ := json.Marshal(updatePayload)
	headers := map[string]string{"Content-Type": "application/json"}
	url := fmt.Sprintf("/api/clipboard/%s", nonExistentID.Hex())

	rr := suite.makeRequest(http.MethodPatch, url, suite.AuthToken, bytes.NewBuffer(jsonPayload), headers)
	suite.Equal(http.StatusNotFound, rr.Code)
}

// --- Tests for DELETE /api/clipboard/:id (Delete Clip) ---
func (suite *ClipboardTestSuite) TestDeleteClip_Success() {
	entry := models.ClipboardEntry{
		ID:      primitive.NewObjectID(),
		UserId:  suite.TestUser.ID,
		Type:    "text",
		Content: "To be deleted",
	}
	entryCollection := database.GetCollection(config.DB_Collection.Entries)
	_, err := entryCollection.InsertOne(context.Background(), entry)
	suite.Require().NoError(err)

	url := fmt.Sprintf("/api/clipboard/%s", entry.ID.Hex())
	rr := suite.makeRequest(http.MethodDelete, url, suite.AuthToken, nil, nil)
	suite.Equal(http.StatusOK, rr.Code)

	var responseBody map[string]string
	json.Unmarshal(rr.Body.Bytes(), &responseBody)
	suite.Equal("Clipboard entry deleted successfully", responseBody["message"])

	// Verify in DB
	count, err := entryCollection.CountDocuments(context.Background(), bson.M{"_id": entry.ID})
	suite.NoError(err)
	suite.Equal(int64(0), count, "Entry should be deleted from DB")
}

func (suite *ClipboardTestSuite) TestDeleteClip_NotFound() {
	nonExistentID := primitive.NewObjectID()
	url := fmt.Sprintf("/api/clipboard/%s", nonExistentID.Hex())
	rr := suite.makeRequest(http.MethodDelete, url, suite.AuthToken, nil, nil)
	suite.Equal(http.StatusNotFound, rr.Code)
}

func (suite *ClipboardTestSuite) TestDeleteClip_Forbidden() {
	otherUser := suite.createTestUser("otheruser3", "other3@example.com", "password")
	entry := models.ClipboardEntry{
		ID:      primitive.NewObjectID(),
		UserId:  otherUser.ID, // Belongs to another user
		Type:    "text",
		Content: "Another user's clip to delete",
	}
	entryCollection := database.GetCollection(config.DB_Collection.Entries)
	_, err := entryCollection.InsertOne(context.Background(), entry)
	suite.Require().NoError(err)

	url := fmt.Sprintf("/api/clipboard/%s", entry.ID.Hex())
	// Authenticated as suite.TestUser
	rr := suite.makeRequest(http.MethodDelete, url, suite.AuthToken, nil, nil)
	suite.Equal(http.StatusNotFound, rr.Code) // Should be 404 as if it doesn't exist for this user

	// Verify it wasn't deleted from DB
	count, err := entryCollection.CountDocuments(context.Background(), bson.M{"_id": entry.ID})
	suite.NoError(err)
	suite.Equal(int64(1), count, "Entry should still exist in DB as it belonged to another user")
}
