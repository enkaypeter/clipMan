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

	"clipMan/authprovider"
	"clipMan/config"
	usercontrollers "clipMan/controllers"
	"clipMan/database"
	"clipMan/models"
	"clipMan/routes"
	"clipMan/services"
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
	Router         *gin.Engine
	TestUser       *models.User
	AuthToken      string
	OriginalDBName string
	AuthProvider   *fakeAuthProvider
}

type fakeAuthProvider struct {
	startedEmail string
}

func (provider *fakeAuthProvider) Name() string { return authprovider.WorkOS }

func (provider *fakeAuthProvider) StartMagicAuth(_ context.Context, email string, _ authprovider.RequestContext) error {
	provider.startedEmail = email
	return nil
}

func (provider *fakeAuthProvider) VerifyMagicAuth(_ context.Context, email, code string, _ authprovider.RequestContext) (*authprovider.User, error) {
	if code != "123456" {
		return nil, fmt.Errorf("invalid code")
	}
	return &authprovider.User{
		Subject:       "workos-" + email,
		Email:         email,
		EmailVerified: true,
	}, nil
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
	routes.SetupUserRoutes(suite.Router)
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
	suite.Require().NoError(database.EnsureIndexes(context.Background()))
	suite.AuthProvider = &fakeAuthProvider{}
	usercontrollers.ConfigureAuthService(services.NewAuthService(suite.AuthProvider))

	suite.TestUser = suite.createTestUser("testuser", "test@example.com", "password123")
	suite.AuthToken, err = utils.GenerateJWT(suite.TestUser)
	suite.Require().NoError(err, "Failed to generate test user token")
	log.Println("Generated AuthToken:", suite.AuthToken)
}

func (suite *ClipboardTestSuite) TestMagicAuthCreatesAccountAndSession() {
	start := suite.makeJSONRequest(http.MethodPost, "/auth/magic/start", "", map[string]string{
		"email": "  NEW.User@Example.com ",
	})
	suite.Equal(http.StatusAccepted, start.Code)
	suite.Equal("new.user@example.com", suite.AuthProvider.startedEmail)

	verify := suite.makeJSONRequest(http.MethodPost, "/auth/magic/verify", "", map[string]string{
		"email": "new.user@example.com",
		"code":  "123456",
	})
	suite.Equal(http.StatusOK, verify.Code, verify.Body.String())
	cookies := verify.Result().Cookies()
	suite.Require().NotEmpty(cookies)

	me := suite.makeRequest(http.MethodGet, "/api/account/me", "", nil, map[string]string{
		"Cookie": cookies[0].Name + "=" + cookies[0].Value,
	})
	suite.Equal(http.StatusOK, me.Code, me.Body.String())
	suite.Contains(me.Body.String(), `"email":"new.user@example.com"`)
	suite.Contains(me.Body.String(), `"emailVerified":true`)
}

func (suite *ClipboardTestSuite) TestMagicAuthReusesExistingIdentity() {
	first := suite.makeJSONRequest(http.MethodPost, "/auth/magic/verify", "", map[string]string{
		"email": "repeat@example.com", "code": "123456",
	})
	second := suite.makeJSONRequest(http.MethodPost, "/auth/magic/verify", "", map[string]string{
		"email": "repeat@example.com", "code": "123456",
	})
	suite.Equal(http.StatusOK, first.Code)
	suite.Equal(http.StatusOK, second.Code)

	var firstPayload, secondPayload struct {
		User models.User `json:"user"`
	}
	suite.Require().NoError(json.Unmarshal(first.Body.Bytes(), &firstPayload))
	suite.Require().NoError(json.Unmarshal(second.Body.Bytes(), &secondPayload))
	suite.Equal(firstPayload.User.ID, secondPayload.User.ID)

	count, err := database.GetCollection(config.DB_Collection.Users).CountDocuments(context.Background(), bson.M{"email_normalized": "repeat@example.com"})
	suite.Require().NoError(err)
	suite.EqualValues(1, count)
}

func (suite *ClipboardTestSuite) TestLegacyUserCanLinkEmailAndThenUseOTP() {
	start := suite.makeJSONRequest(http.MethodPost, "/api/account/email-link/start", suite.AuthToken, map[string]string{
		"email": "linked@example.com",
	})
	suite.Equal(http.StatusAccepted, start.Code, start.Body.String())

	confirm := suite.makeJSONRequest(http.MethodPost, "/api/account/email-link/confirm", suite.AuthToken, map[string]string{
		"code": "123456",
	})
	suite.Equal(http.StatusOK, confirm.Code, confirm.Body.String())
	suite.Contains(confirm.Body.String(), `"emailVerified":true`)

	magicLogin := suite.makeJSONRequest(http.MethodPost, "/auth/magic/verify", "", map[string]string{
		"email": "linked@example.com", "code": "123456",
	})
	suite.Equal(http.StatusOK, magicLogin.Code, magicLogin.Body.String())
	suite.Contains(magicLogin.Body.String(), suite.TestUser.ID.Hex())

	legacyLogin := suite.makeJSONRequest(http.MethodPost, "/login", "", map[string]string{
		"username": "testuser", "password": "password123",
	})
	suite.Equal(http.StatusUnauthorized, legacyLogin.Code)
}

func (suite *ClipboardTestSuite) TestEmailCannotBeLinkedToTwoAccounts() {
	start := suite.makeJSONRequest(http.MethodPost, "/api/account/email-link/start", suite.AuthToken, map[string]string{"email": "owned@example.com"})
	suite.Equal(http.StatusAccepted, start.Code)
	confirm := suite.makeJSONRequest(http.MethodPost, "/api/account/email-link/confirm", suite.AuthToken, map[string]string{"code": "123456"})
	suite.Equal(http.StatusOK, confirm.Code)

	otherUser := suite.createTestUser("otheruser", "", "password123")
	otherToken, err := utils.GenerateJWT(otherUser)
	suite.Require().NoError(err)
	conflict := suite.makeJSONRequest(http.MethodPost, "/api/account/email-link/start", otherToken, map[string]string{"email": "owned@example.com"})
	suite.Equal(http.StatusConflict, conflict.Code, conflict.Body.String())
}

func (suite *ClipboardTestSuite) TestInvalidMagicCodeDoesNotCreateAccount() {
	response := suite.makeJSONRequest(http.MethodPost, "/auth/magic/verify", "", map[string]string{
		"email": "invalid@example.com", "code": "000000",
	})
	suite.Equal(http.StatusUnauthorized, response.Code)
	count, err := database.GetCollection(config.DB_Collection.Users).CountDocuments(context.Background(), bson.M{"email_normalized": "invalid@example.com"})
	suite.Require().NoError(err)
	suite.Zero(count)
}

func (suite *ClipboardTestSuite) TestLegacyRegistrationIsDisabled() {
	response := suite.makeJSONRequest(http.MethodPost, "/register", "", map[string]string{
		"username": "new-legacy-user", "password": "password123",
	})
	suite.Equal(http.StatusNotFound, response.Code)
}

func (suite *ClipboardTestSuite) makeJSONRequest(method, url, token string, payload interface{}) *httptest.ResponseRecorder {
	body, err := json.Marshal(payload)
	suite.Require().NoError(err)
	return suite.makeRequest(method, url, token, bytes.NewReader(body), map[string]string{"Content-Type": "application/json"})
}

func (suite *ClipboardTestSuite) createTestUser(username, email, password string) *models.User {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	suite.Require().NoError(err)

	user := &models.User{
		ID:           primitive.NewObjectID(),
		Username:     username,
		Email:        email,
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
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
		"content": "This is a test note",
		"title":   "Test Note",
		"type":    "note",
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
	suite.Equal("This is a test note", createdEntry.Content)
	suite.Equal("Test Note", createdEntry.Title)
	suite.Equal("note", createdEntry.Type)
}

func (suite *ClipboardTestSuite) TestCreateTextClip_Unauthorized() {
	payload := gin.H{"content": "This is a test text clip", "type": "text"}
	jsonPayload, _ := json.Marshal(payload)
	headers := map[string]string{"Content-Type": "application/json"}

	// No token provided
	rr := suite.makeRequest(http.MethodPost, "/api/clipboard", "", bytes.NewBuffer(jsonPayload), headers)
	suite.Equal(http.StatusUnauthorized, rr.Code, "Status code should be 401 Unauthorized")
}

// Test POST /api/clipboard - Create File Clip
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

func (suite *ClipboardTestSuite) TestUpdateClip_Success_AllEditableFields() {
	entry := models.ClipboardEntry{
		ID:        primitive.NewObjectID(),
		UserId:    suite.TestUser.ID,
		Type:      "note",
		Title:     "Original title",
		Content:   "Original content",
		Timestamp: time.Now().Add(-time.Hour),
	}
	entryCollection := database.GetCollection(config.DB_Collection.Entries)
	_, err := entryCollection.InsertOne(context.Background(), entry)
	suite.Require().NoError(err)

	payload := gin.H{
		"type":    "code",
		"title":   "Updated title",
		"content": "  const answer = 42;\n",
	}
	jsonPayload, _ := json.Marshal(payload)
	url := fmt.Sprintf("/api/clipboard/%s", entry.ID.Hex())
	rr := suite.makeRequest(http.MethodPatch, url, suite.AuthToken, bytes.NewBuffer(jsonPayload), map[string]string{"Content-Type": "application/json"})

	suite.Equal(http.StatusOK, rr.Code)

	var updatedEntry models.ClipboardEntry
	suite.Require().NoError(json.Unmarshal(rr.Body.Bytes(), &updatedEntry))
	suite.Equal("code", updatedEntry.Type)
	suite.Equal("Updated title", updatedEntry.Title)
	suite.Equal("  const answer = 42;\n", updatedEntry.Content)
	suite.True(updatedEntry.Timestamp.After(entry.Timestamp))

	var dbEntry models.ClipboardEntry
	suite.Require().NoError(entryCollection.FindOne(context.Background(), bson.M{"_id": entry.ID}).Decode(&dbEntry))
	suite.Equal(updatedEntry.Type, dbEntry.Type)
	suite.Equal(updatedEntry.Title, dbEntry.Title)
	suite.Equal(updatedEntry.Content, dbEntry.Content)
}

func (suite *ClipboardTestSuite) TestUpdateClip_Success_TitleOnlyPreservesOtherFields() {
	entry := models.ClipboardEntry{
		ID:        primitive.NewObjectID(),
		UserId:    suite.TestUser.ID,
		Type:      "url",
		Title:     "Old title",
		Content:   "https://example.com",
		Timestamp: time.Now().Add(-time.Hour),
	}
	entryCollection := database.GetCollection(config.DB_Collection.Entries)
	_, err := entryCollection.InsertOne(context.Background(), entry)
	suite.Require().NoError(err)

	jsonPayload, _ := json.Marshal(gin.H{"title": "New title"})
	url := fmt.Sprintf("/api/clipboard/%s", entry.ID.Hex())
	rr := suite.makeRequest(http.MethodPatch, url, suite.AuthToken, bytes.NewBuffer(jsonPayload), map[string]string{"Content-Type": "application/json"})

	suite.Equal(http.StatusOK, rr.Code)

	var updatedEntry models.ClipboardEntry
	suite.Require().NoError(json.Unmarshal(rr.Body.Bytes(), &updatedEntry))
	suite.Equal("New title", updatedEntry.Title)
	suite.Equal(entry.Type, updatedEntry.Type)
	suite.Equal(entry.Content, updatedEntry.Content)
}

func (suite *ClipboardTestSuite) TestUpdateClip_Success_TypeOnlyPreservesOtherFields() {
	entry := models.ClipboardEntry{
		ID:        primitive.NewObjectID(),
		UserId:    suite.TestUser.ID,
		Type:      "note",
		Title:     "Keep this title",
		Content:   "#ff00aa",
		Timestamp: time.Now().Add(-time.Hour),
	}
	entryCollection := database.GetCollection(config.DB_Collection.Entries)
	_, err := entryCollection.InsertOne(context.Background(), entry)
	suite.Require().NoError(err)

	jsonPayload, _ := json.Marshal(gin.H{"type": "color"})
	url := fmt.Sprintf("/api/clipboard/%s", entry.ID.Hex())
	rr := suite.makeRequest(http.MethodPatch, url, suite.AuthToken, bytes.NewBuffer(jsonPayload), map[string]string{"Content-Type": "application/json"})

	suite.Equal(http.StatusOK, rr.Code)

	var updatedEntry models.ClipboardEntry
	suite.Require().NoError(json.Unmarshal(rr.Body.Bytes(), &updatedEntry))
	suite.Equal("color", updatedEntry.Type)
	suite.Equal(entry.Title, updatedEntry.Title)
	suite.Equal(entry.Content, updatedEntry.Content)
}

func (suite *ClipboardTestSuite) TestUpdateClip_RejectsInvalidTypeWithoutMutation() {
	entry := models.ClipboardEntry{
		ID:      primitive.NewObjectID(),
		UserId:  suite.TestUser.ID,
		Type:    "note",
		Title:   "Original title",
		Content: "Original content",
	}
	entryCollection := database.GetCollection(config.DB_Collection.Entries)
	_, err := entryCollection.InsertOne(context.Background(), entry)
	suite.Require().NoError(err)

	jsonPayload, _ := json.Marshal(gin.H{"type": "video"})
	url := fmt.Sprintf("/api/clipboard/%s", entry.ID.Hex())
	rr := suite.makeRequest(http.MethodPatch, url, suite.AuthToken, bytes.NewBuffer(jsonPayload), map[string]string{"Content-Type": "application/json"})

	suite.Equal(http.StatusBadRequest, rr.Code)

	var dbEntry models.ClipboardEntry
	suite.Require().NoError(entryCollection.FindOne(context.Background(), bson.M{"_id": entry.ID}).Decode(&dbEntry))
	suite.Equal(entry.Type, dbEntry.Type)
	suite.Equal(entry.Title, dbEntry.Title)
	suite.Equal(entry.Content, dbEntry.Content)
}

func (suite *ClipboardTestSuite) TestUpdateClip_RejectsBlankContentWithoutMutation() {
	entry := models.ClipboardEntry{
		ID:      primitive.NewObjectID(),
		UserId:  suite.TestUser.ID,
		Type:    "note",
		Title:   "Original title",
		Content: "Original content",
	}
	entryCollection := database.GetCollection(config.DB_Collection.Entries)
	_, err := entryCollection.InsertOne(context.Background(), entry)
	suite.Require().NoError(err)

	jsonPayload, _ := json.Marshal(gin.H{"content": "   \n\t"})
	url := fmt.Sprintf("/api/clipboard/%s", entry.ID.Hex())
	rr := suite.makeRequest(http.MethodPatch, url, suite.AuthToken, bytes.NewBuffer(jsonPayload), map[string]string{"Content-Type": "application/json"})

	suite.Equal(http.StatusBadRequest, rr.Code)

	var dbEntry models.ClipboardEntry
	suite.Require().NoError(entryCollection.FindOne(context.Background(), bson.M{"_id": entry.ID}).Decode(&dbEntry))
	suite.Equal(entry.Content, dbEntry.Content)
}

func (suite *ClipboardTestSuite) TestUpdateClip_RejectsNoEditableFields() {
	entry := models.ClipboardEntry{
		ID:      primitive.NewObjectID(),
		UserId:  suite.TestUser.ID,
		Type:    "note",
		Content: "Original content",
	}
	entryCollection := database.GetCollection(config.DB_Collection.Entries)
	_, err := entryCollection.InsertOne(context.Background(), entry)
	suite.Require().NoError(err)

	jsonPayload, _ := json.Marshal(gin.H{"device": "desktop"})
	url := fmt.Sprintf("/api/clipboard/%s", entry.ID.Hex())
	rr := suite.makeRequest(http.MethodPatch, url, suite.AuthToken, bytes.NewBuffer(jsonPayload), map[string]string{"Content-Type": "application/json"})

	suite.Equal(http.StatusBadRequest, rr.Code)
}

func (suite *ClipboardTestSuite) TestUpdateClip_OtherUsersEntryIsNotFoundAndUnchanged() {
	otherUser := suite.createTestUser("update-other-user", "update-other@example.com", "password")
	entry := models.ClipboardEntry{
		ID:      primitive.NewObjectID(),
		UserId:  otherUser.ID,
		Type:    "note",
		Title:   "Private title",
		Content: "Private content",
	}
	entryCollection := database.GetCollection(config.DB_Collection.Entries)
	_, err := entryCollection.InsertOne(context.Background(), entry)
	suite.Require().NoError(err)

	jsonPayload, _ := json.Marshal(gin.H{"title": "Unauthorized change"})
	url := fmt.Sprintf("/api/clipboard/%s", entry.ID.Hex())
	rr := suite.makeRequest(http.MethodPatch, url, suite.AuthToken, bytes.NewBuffer(jsonPayload), map[string]string{"Content-Type": "application/json"})

	suite.Equal(http.StatusNotFound, rr.Code)

	var dbEntry models.ClipboardEntry
	suite.Require().NoError(entryCollection.FindOne(context.Background(), bson.M{"_id": entry.ID}).Decode(&dbEntry))
	suite.Equal(entry.Title, dbEntry.Title)
}

func (suite *ClipboardTestSuite) TestUpdateClip_RejectsFileTypeChange() {
	entry := models.ClipboardEntry{
		ID:       primitive.NewObjectID(),
		UserId:   suite.TestUser.ID,
		Type:     "file",
		Title:    "Document",
		Filename: "document.pdf",
		Filepath: "/uploads/document.pdf",
	}
	entryCollection := database.GetCollection(config.DB_Collection.Entries)
	_, err := entryCollection.InsertOne(context.Background(), entry)
	suite.Require().NoError(err)

	jsonPayload, _ := json.Marshal(gin.H{"type": "note"})
	url := fmt.Sprintf("/api/clipboard/%s", entry.ID.Hex())
	rr := suite.makeRequest(http.MethodPatch, url, suite.AuthToken, bytes.NewBuffer(jsonPayload), map[string]string{"Content-Type": "application/json"})

	suite.Equal(http.StatusBadRequest, rr.Code)

	var dbEntry models.ClipboardEntry
	suite.Require().NoError(entryCollection.FindOne(context.Background(), bson.M{"_id": entry.ID}).Decode(&dbEntry))
	suite.Equal("file", dbEntry.Type)
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
