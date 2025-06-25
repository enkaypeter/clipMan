package controllers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"clipMan/config"
	"clipMan/database"
	"clipMan/models"

	"github.com/gin-gonic/gin"
	"math"
	"strconv"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)


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
    c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user data"})
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
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
			return
		}
		entry.Filepath = dst

	} else {
		if err := c.ShouldBindJSON(&entry); err != nil {
			log.Println("Error binding JSON:", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		entry.Type = "text"
	}

	entry.Timestamp = time.Now()
	entry.UserId = authUser.ID


	collection := database.GetCollection(config.DB_Collection.Entries)
	
	res, err := collection.InsertOne(context.TODO(), entry)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}


	c.JSON(http.StatusCreated, gin.H{"id": res.InsertedID})
}


func PasteClipboard(c *gin.Context) {
	userCtx, exists := c.Get("user")
	requestCtx := c.Request.Context()
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	authenticatedUser, ok := userCtx.(*models.User)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user data"})
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

	totalEntries, err := collection.CountDocuments(requestCtx, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count entries"})
		return
	}

	// Retrieve entries with pagination
	findOptions := options.Find()
	findOptions.SetSort(bson.D{{"timestamp", -1}}) // Sort by timestamp descending
	findOptions.SetSkip(skip)
	findOptions.SetLimit(limit)

	cursor, err := collection.Find(requestCtx, filter, findOptions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve entries"})
		return
	}
	defer cursor.Close(requestCtx)

	var entries []models.ClipboardEntry
	if err = cursor.All(requestCtx, &entries); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode entries"})
		return
	}

	if entries == nil {
		entries = []models.ClipboardEntry{} // Return empty array instead of null
	}

	c.JSON(http.StatusOK, gin.H{
		"data": entries,
		"pagination": gin.H{
			"total_entries": totalEntries,
			"current_page":  page,
			"total_pages":   int64(math.Ceil(float64(totalEntries) / float64(limit))),
			"limit":         limit,
		},
	})
}

func GetClipboardEntryByID(c *gin.Context) {
	userCtx, exists := c.Get("user")
	requestCtx := c.Request.Context()

	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	authenticatedUser, ok := userCtx.(*models.User)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user data"})
		return
	}

	entryIDParam := c.Param("id")
	entryID, err := primitive.ObjectIDFromHex(entryIDParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid entry ID format"})
		return
	}

	collection := database.GetCollection(config.DB_Collection.Entries)
	var entry models.ClipboardEntry

	filter := bson.M{"_id": entryID, "user_id": authenticatedUser.ID}

	err = collection.FindOne(requestCtx, filter).Decode(&entry)
	if err != nil {
		if err.Error() == "mongo: no documents in result" { // TODO: check for specific error type
			c.JSON(http.StatusNotFound, gin.H{"error": "Clipboard entry not found or access denied"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve entry"})
		return
	}

	c.JSON(http.StatusOK, entry)
}

// UpdateClipboardEntryPayload defines the structure for the PATCH request body
type UpdateClipboardEntryPayload struct {
	Content *string `json:"content"`
	Pinned  *bool   `json:"pinned"`
	// Add other updatable fields here, e.g., metadata
}

func UpdateClipboardEntry(c *gin.Context) {
	userCtx, exists := c.Get("user")
	requestCtx := c.Request.Context()
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	authenticatedUser, ok := userCtx.(*models.User)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user data"})
		return
	}

	entryIDParam := c.Param("id")
	entryID, err := primitive.ObjectIDFromHex(entryIDParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid entry ID format"})
		return
	}

	var payload UpdateClipboardEntryPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload: " + err.Error()})
		return
	}

	// Ensure at least one field is being updated
	if payload.Content == nil && payload.Pinned == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No update fields provided"})
		return
	}

	collection := database.GetCollection(config.DB_Collection.Entries)
	var currentEntry models.ClipboardEntry

	// First, verify the entry exists and belongs to the user
	filter := bson.M{"_id": entryID, "user_id": authenticatedUser.ID}
	err = collection.FindOne(requestCtx, filter).Decode(&currentEntry)
	if err != nil {
		if err.Error() == "mongo: no documents in result" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Clipboard entry not found or access denied"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve entry for update"})
		return
	}

	// Prevent updating fields of a "file" type entry, except for 'pinned'
	if currentEntry.Type == "file" && payload.Content != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot update content of a file entry. You can only pin/unpin it."})
		return
	}


	updateFields := bson.M{}
	if payload.Content != nil {
		updateFields["content"] = *payload.Content
		// If content is updated, also update the timestamp
		updateFields["timestamp"] = time.Now()
	}
	if payload.Pinned != nil {
		updateFields["pinned"] = *payload.Pinned
	}

	update := bson.M{"$set": updateFields}

	_, err = collection.UpdateOne(requestCtx, filter, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update clipboard entry"})
		return
	}

	// Fetch the updated entry to return it
	var updatedEntry models.ClipboardEntry
	err = collection.FindOne(requestCtx, filter).Decode(&updatedEntry)
	if err != nil {
		// This should ideally not happen if the update was successful
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve updated entry"})
		return
	}

	c.JSON(http.StatusOK, updatedEntry)
}

func DeleteClipboardEntry(c *gin.Context) {
	userCtx, exists := c.Get("user")
	requestCtx := c.Request.Context()
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	authenticatedUser, ok := userCtx.(*models.User)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user data"})
		return
	}

	entryIDParam := c.Param("id")
	entryID, err := primitive.ObjectIDFromHex(entryIDParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid entry ID format"})
		return
	}

	collection := database.GetCollection(config.DB_Collection.Entries)

	// Construct filter to ensure the entry belongs to the authenticated user
	filter := bson.M{"_id": entryID, "user_id": authenticatedUser.ID}

	result, err := collection.DeleteOne(requestCtx, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete clipboard entry"})
		return
	}

	if result.DeletedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Clipboard entry not found or access denied"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Clipboard entry deleted successfully"})
}

