package controllers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"clipMan/api"
	"clipMan/config"
	"clipMan/database"
	"clipMan/models"

	"math"
	"strconv"

	"github.com/gin-gonic/gin"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// TODO: extract to dto layer
type ClipboardListResponse struct {
	Data       []models.ClipboardEntry `json:"data"`
	Pagination Pagination              `json:"pagination"`
}

type Pagination struct {
	TotalEntries int64 `json:"total_entries"`
	CurrentPage  int64 `json:"current_page"`
	TotalPages   int64 `json:"total_pages"`
	Limit        int64 `json:"limit"`
}

// TODO: extract db operations to service->repository layer
func CopyClipboard(c *gin.Context) {

	var entry models.ClipboardEntry

	user, exists := c.Get("user")
	if !exists {
		log.Println("User not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		c.Abort()
		return
	}

	authUser, ok := user.(*models.User)
	if !ok {
		log.Println("Error casting user from context")
		api.ErrResponse[error](c, http.StatusInternalServerError, "Internal server error")
		c.Abort()
		return
	}
	_, fileHeader, err := c.Request.FormFile("file")
	if err == nil && fileHeader != nil {
		entry.Type = "file"
		entry.Filename = fileHeader.Filename

		dst := fmt.Sprintf("./uploads/%s", fileHeader.Filename)
		err := c.SaveUploadedFile(fileHeader, dst)
		if err != nil {
			api.ErrResponse[error](c, http.StatusInternalServerError, "Failed to save file")
			return
		}
		entry.Filepath = dst

	} else {
		if err := c.ShouldBindJSON(&entry); err != nil {
			log.Println("Error binding JSON:", err)
			api.ErrResponse[error](c, http.StatusBadRequest, err.Error())
			return
		}
		entry.Type = "text"
	}

	entry.Timestamp = time.Now()
	entry.UserId = authUser.ID

	collection := database.GetCollection(config.DB_Collection.Entries)

	res, err := collection.InsertOne(context.TODO(), entry)
	entry.ID = res.InsertedID.(primitive.ObjectID)

	if err != nil {
		api.ErrResponse[error](c, http.StatusInternalServerError, err.Error())
		return
	}

	api.SuccessResponse(c, &entry, api.StringPtr("Clipboard entry created successfully"))
}

func PasteClipboard(c *gin.Context) {
	userCtx, exists := c.Get("user")
	if !exists {
		api.ErrResponse[error](c, http.StatusUnauthorized, "user not authenticated")
		return
	}

	authenticatedUser, ok := userCtx.(*models.User)
	if !ok {
		api.ErrResponse[error](c, http.StatusInternalServerError, "invalid user data")
		return
	}

	collection := database.GetCollection(config.DB_Collection.Entries)

	// Pagination parameters
	pageQuery := c.DefaultQuery("page", "1")
	limitQuery := c.DefaultQuery("limit", "10")

	page, err := strconv.ParseInt(pageQuery, 10, 64)
	if err != nil || page < 1 {
		page = 1
	}
	limit, err := strconv.ParseInt(limitQuery, 10, 64)
	if err != nil || limit < 1 {
		limit = 10
	}

	skip := (page - 1) * limit

	filter := bson.D{{"user_id", authenticatedUser.ID}}

	// Get total count for pagination
	totalEntries, err := collection.CountDocuments(context.TODO(), filter)
	if err != nil {
		api.ErrResponse[error](c, http.StatusInternalServerError, "failed to count entries")
		return
	}

	// Retrieve entries with pagination
	findOptions := options.Find()
	findOptions.SetSort(bson.D{{"timestamp", -1}}) // Sort by timestamp descending
	findOptions.SetSkip(skip)
	findOptions.SetLimit(limit)

	cursor, err := collection.Find(context.TODO(), filter, findOptions)
	if err != nil {
		api.ErrResponse[error](c, http.StatusInternalServerError, "failed to retrieve entries")
		return
	}
	defer cursor.Close(context.TODO())

	var entries []models.ClipboardEntry
	if err = cursor.All(context.TODO(), &entries); err != nil {
		api.ErrResponse[error](c, http.StatusInternalServerError, "failed to decode entries")
		return
	}

	if entries == nil {
		entries = []models.ClipboardEntry{}
	}

	responseObject := ClipboardListResponse{
		Data: entries,
		Pagination: Pagination{
			TotalEntries: totalEntries,
			CurrentPage:  page,
			TotalPages:   int64(math.Ceil(float64(totalEntries) / float64(limit))),
			Limit:        limit,
		},
	}

	api.SuccessResponse(c, &responseObject, api.StringPtr("Entries retrieved successfully"))
}

func GetClipboardEntryByID(c *gin.Context) {
	userCtx, exists := c.Get("user")
	if !exists {
		api.ErrResponse[error](c, http.StatusUnauthorized, "user not authenticated")
		return
	}

	authenticatedUser, ok := userCtx.(*models.User)
	if !ok {
		api.ErrResponse[error](c, http.StatusInternalServerError, "invalid user data")
		return
	}

	entryIDParam := c.Param("id")
	entryID, err := primitive.ObjectIDFromHex(entryIDParam)
	if err != nil {
		api.ErrResponse[error](c, http.StatusBadRequest, "invalid entry ID format")
		return
	}

	collection := database.GetCollection(config.DB_Collection.Entries)
	var entry models.ClipboardEntry

	filter := bson.M{"_id": entryID, "user_id": authenticatedUser.ID}

	err = collection.FindOne(context.TODO(), filter).Decode(&entry)
	if err != nil {
		if err.Error() == "mongo: no documents in result" { // TODO: check for specific error type
			api.ErrResponse[error](c, http.StatusNotFound, "clipboard entry not found")
			return
		}
		api.ErrResponse[error](c, http.StatusInternalServerError, "failed to retrieve entry")
		return
	}

	api.SuccessResponse(c, &entry, api.StringPtr("Entry retrieved successfully"))
}

type UpdateClipboardEntryPayload struct {
	Content *string `json:"content"`
	Pinned  *bool   `json:"pinned"`
}

func UpdateClipboardEntry(c *gin.Context) {
	userCtx, exists := c.Get("user")
	if !exists {
		api.ErrResponse[error](c, http.StatusUnauthorized, "user not authenticated")
		return
	}

	authenticatedUser, ok := userCtx.(*models.User)
	if !ok {
		api.ErrResponse[error](c, http.StatusInternalServerError, "invalid user data")
		return
	}

	entryIDParam := c.Param("id")
	entryID, err := primitive.ObjectIDFromHex(entryIDParam)
	if err != nil {
		api.ErrResponse[error](c, http.StatusBadRequest, "invalid entry ID format")
		return
	}

	var payload UpdateClipboardEntryPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		api.ErrResponse[error](c, http.StatusBadRequest, "invalid entry ID format: "+err.Error())
		return
	}

	// Ensure at least one field is being updated
	if payload.Content == nil && payload.Pinned == nil {
		api.ErrResponse[error](c, http.StatusBadRequest, "no update fields provided")
		return
	}

	collection := database.GetCollection(config.DB_Collection.Entries)
	var currentEntry models.ClipboardEntry

	// First, verify the entry exists and belongs to the user
	filter := bson.M{"_id": entryID, "user_id": authenticatedUser.ID}
	err = collection.FindOne(context.TODO(), filter).Decode(&currentEntry)
	if err != nil {
		if err.Error() == "mongo: no documents in result" {
			api.ErrResponse[error](c, http.StatusNotFound, "clipboard entry not found or access denied")
			return
		}
		api.ErrResponse[error](c, http.StatusInternalServerError, "Failed to retrieve entry for update")
		return
	}

	// Prevent updating fields of a "file" type entry, except for 'pinned'
	if currentEntry.Type == "file" && payload.Content != nil {
		api.ErrResponse[error](c, http.StatusBadRequest, "cannot update content of a file entry. You can only pin/unpin it.")
		return
	}

	updateFields := bson.M{}
	if payload.Content != nil {
		updateFields["content"] = *payload.Content
		updateFields["timestamp"] = time.Now()
	}
	if payload.Pinned != nil {
		updateFields["pinned"] = *payload.Pinned
	}

	update := bson.M{"$set": updateFields}

	_, err = collection.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		api.ErrResponse[error](c, http.StatusInternalServerError, "Failed to update clipboard entry: "+err.Error())
		return
	}

	var updatedEntry models.ClipboardEntry
	err = collection.FindOne(context.TODO(), filter).Decode(&updatedEntry)
	if err != nil {
		api.ErrResponse[error](c, http.StatusInternalServerError, "Failed to retrieve updated entry")
		return
	}

	api.SuccessResponse(c, &updatedEntry, api.StringPtr("Clipboard entry updated successfully"))
}

func DeleteClipboardEntry(c *gin.Context) {
	userCtx, exists := c.Get("user")
	if !exists {
		api.ErrResponse[error](c, http.StatusUnauthorized, "user not authenticated")
		return
	}

	authenticatedUser, ok := userCtx.(*models.User)
	if !ok {
		api.ErrResponse[error](c, http.StatusInternalServerError, "invalid user data")
		return
	}

	entryIDParam := c.Param("id")
	entryID, err := primitive.ObjectIDFromHex(entryIDParam)
	if err != nil {
		api.ErrResponse[error](c, http.StatusBadRequest, "invalid entry ID format")
		return
	}

	collection := database.GetCollection(config.DB_Collection.Entries)

	filter := bson.M{"_id": entryID, "user_id": authenticatedUser.ID}

	result, err := collection.DeleteOne(context.TODO(), filter)
	if err != nil {
		api.ErrResponse[error](c, http.StatusInternalServerError, "Failed to delete clipboard entry")
		return
	}

	if result.DeletedCount == 0 {
		api.ErrResponse[error](c, http.StatusNotFound, "Clipboard entry not found or access denied")
		return
	}

	api.SuccessResponse(c, &entryID, api.StringPtr("Clipboard entry deleted successfully"))
}
