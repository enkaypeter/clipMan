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
	"clipMan/routes"
	"clipMan/utils"

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
	OriginalDBName string
}

// SetupSuite runs once before all tests in the suite
func (suite *ClipboardTestSuite) SetupSuite() {
	config.LoadConfig()
	suite.OriginalDBName = config.AppConfig.MongoDB
	config.AppConfig.MongoDB = "clipboardDB_test"
	log.Printf("Using test database: %s", config.AppConfig.MongoDB)

	// Point to the Dockerized MongoDB instance
	config.AppConfig.MongoURI = "mongodb://localhost:27017"

	// Ensure JWT Secret is set for tests
	config.AppConfig.JWTSecret = "test_secret_key_for_jwt_1234567890"
	log.Println("Using JWT_SECRET for testing:", config.AppConfig.JWTSecret)

	_, err := database.Connect()
	suite.Require().NoError(err, "Failed to connect to MongoDB")

	gin.SetMode(gin.TestMode)
	suite.Router = gin.New()
	routes.SetupClipboardRoutes(suite.Router)
}

func (suite *ClipboardTestSuite) TearDownSuite() {
	// No need to stop a server, but we can clear the test database
	if database.MongoClient != nil {
		err := database.MongoClient.Database("clipboardDB_test").Drop(context.Background())
		suite.Require().NoError(err)
	}
	config.AppConfig.MongoDB = suite.OriginalDBName
}

func (suite *ClipboardTestSuite) SetupTest() {
	client, err := database.Connect()
	suite.Require().NoError(err)
	err = client.Database("clipboardDB_test").Drop(context.Background())
	suite.Require().NoError(err)

	suite.TestUser = suite.createTestUser("testuser", "test@example.com", "password123")
	suite.AuthToken, err = utils.GenerateJWT(suite.TestUser)
	suite.Require().NoError(err, "Failed to generate test user token")
	log.Println("Generated AuthToken:", suite.AuthToken)
}

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
	log.Printf("Attempting to insert user with ID: %s", user.ID.Hex())
	_, err = collection.InsertOne(context.Background(), user)
	suite.Require().NoError(err)
	log.Printf("Successfully inserted user with ID: %s", user.ID.Hex())
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


// --- Example: Test POST /api/clipboard - Create Text Clip ---
func (suite *ClipboardTestSuite) TestCreateTextClip_Success() {
	payload := gin.H{
		"content": "This is a test text clip",
		"type": "text",
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
	tempDir := suite.T().TempDir()
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


	err = writer.Close()
	suite.Require().NoError(err)

	headers := map[string]string{"Content-Type": writer.FormDataContentType()}
	rr := suite.makeRequest(http.MethodPost, "/api/clipboard", suite.AuthToken, body, headers)

	suite.Equal(http.StatusCreated, rr.Code, "Status code should be 201 Created for file upload")

	var responseBody map[string]interface{}
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

	uploadsDir := "./uploads"
	if _, err := os.Stat(uploadsDir); os.IsNotExist(err) {
		err = os.MkdirAll(uploadsDir, 0755)
		suite.Require().NoError(err, "Failed to create uploads directory for testing")
	}
	// And attempt to remove the test file after test
	defer os.Remove(filepath.Join(uploadsDir, "testfile.txt"))

}

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
