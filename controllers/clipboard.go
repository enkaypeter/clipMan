package controllers

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"clipMan/config"
	"clipMan/database"
	"clipMan/models"

	"github.com/gin-gonic/gin"
	"math"
	"strconv"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var editableEntryTypes = map[string]struct{}{
	"note":  {},
	"url":   {},
	"code":  {},
	"color": {},
}

func isEditableEntryType(entryType string) bool {
	_, ok := editableEntryTypes[entryType]
	return ok
}

func isCreateEntryType(entryType string) bool {
	// "text" remains valid for older clients. New clients persist a specific
	// editable type such as note, URL, code, or color.
	return entryType == "text" || isEditableEntryType(entryType)
}

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

		entry.Type = strings.ToLower(strings.TrimSpace(entry.Type))
		if entry.Type == "" {
			entry.Type = "text"
		}
		if !isCreateEntryType(entry.Type) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid entry type"})
			return
		}

		entry.Title = strings.TrimSpace(entry.Title)
		if strings.TrimSpace(entry.Content) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Content is required"})
			return
		}
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

	// Get total count for pagination
	totalEntries, err := collection.CountDocuments(context.TODO(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count entries"})
		return
	}

	// Retrieve entries with pagination
	findOptions := options.Find()
	findOptions.SetSort(bson.D{{"timestamp", -1}}) // Sort by timestamp descending
	findOptions.SetSkip(skip)
	findOptions.SetLimit(limit)

	cursor, err := collection.Find(context.TODO(), filter, findOptions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve entries"})
		return
	}
	defer cursor.Close(context.TODO())

	var entries []models.ClipboardEntry
	if err = cursor.All(context.TODO(), &entries); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode entries"})
		return
	}

	if entries == nil {
		entries = []models.ClipboardEntry{}
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

	err = collection.FindOne(context.TODO(), filter).Decode(&entry)
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

type UpdateClipboardEntryPayload struct {
	Type    *string `json:"type"`
	Title   *string `json:"title"`
	Content *string `json:"content"`
	Pinned  *bool   `json:"pinned"`
}

type normalizedClipboardUpdate struct {
	entryType string
	content   string
}

func validateUpdatePayload(payload UpdateClipboardEntryPayload) (normalizedClipboardUpdate, error) {
	if payload.Type == nil && payload.Title == nil && payload.Content == nil && payload.Pinned == nil {
		return normalizedClipboardUpdate{}, errors.New("No update fields provided")
	}

	normalized := normalizedClipboardUpdate{}
	if payload.Type != nil {
		normalized.entryType = strings.ToLower(strings.TrimSpace(*payload.Type))
		if !isEditableEntryType(normalized.entryType) {
			return normalizedClipboardUpdate{}, errors.New("Invalid entry type")
		}
	}

	if payload.Content != nil {
		normalized.content = *payload.Content
		if strings.TrimSpace(normalized.content) == "" {
			return normalizedClipboardUpdate{}, errors.New("Content is required")
		}
	}

	return normalized, nil
}

func validateEntryUpdate(currentEntry models.ClipboardEntry, payload UpdateClipboardEntryPayload) error {
	if currentEntry.Type != "file" {
		return nil
	}
	if payload.Content != nil {
		return errors.New("Cannot update content of a file entry")
	}
	if payload.Type != nil {
		return errors.New("Cannot change the type of a file entry")
	}

	return nil
}

func buildUpdateFields(payload UpdateClipboardEntryPayload, normalized normalizedClipboardUpdate, now time.Time) bson.M {
	updateFields := bson.M{}

	if payload.Type != nil {
		updateFields["type"] = normalized.entryType
	}
	if payload.Title != nil {
		updateFields["title"] = strings.TrimSpace(*payload.Title)
	}
	if payload.Content != nil {
		updateFields["content"] = normalized.content
	}
	if payload.Pinned != nil {
		updateFields["pinned"] = *payload.Pinned
	}
	if payload.Type != nil || payload.Title != nil || payload.Content != nil {
		updateFields["timestamp"] = now
	}

	return updateFields
}

func UpdateClipboardEntry(c *gin.Context) {
	userCtx, exists := c.Get("user")
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

	normalized, err := validateUpdatePayload(payload)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	collection := database.GetCollection(config.DB_Collection.Entries)
	var currentEntry models.ClipboardEntry

	// First, verify the entry exists and belongs to the user
	filter := bson.M{"_id": entryID, "user_id": authenticatedUser.ID}
	err = collection.FindOne(context.TODO(), filter).Decode(&currentEntry)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Clipboard entry not found or access denied"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve entry for update"})
		return
	}

	if err := validateEntryUpdate(currentEntry, payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updateFields := buildUpdateFields(payload, normalized, time.Now())
	update := bson.M{"$set": updateFields}

	_, err = collection.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update clipboard entry"})
		return
	}

	var updatedEntry models.ClipboardEntry
	err = collection.FindOne(context.TODO(), filter).Decode(&updatedEntry)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve updated entry"})
		return
	}

	c.JSON(http.StatusOK, updatedEntry)
}

func DeleteClipboardEntry(c *gin.Context) {
	userCtx, exists := c.Get("user")
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

	filter := bson.M{"_id": entryID, "user_id": authenticatedUser.ID}

	result, err := collection.DeleteOne(context.TODO(), filter)
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
