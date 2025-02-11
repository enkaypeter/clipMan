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
	"go.mongodb.org/mongo-driver/bson"
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
	var entry models.ClipboardEntry

	userCtx, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Assuming user is a *models.User, extract the user ID
	authenticatedUser, ok := userCtx.(*models.User)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user data"})
		return
	}

	collection := database.GetCollection(config.DB_Collection.Entries)

	// Retrieve the most recent clipboard entry
	opts := options.FindOne().SetSort(bson.D{{"timestamp", -1}})

	filter := bson.D{{"user_id", authenticatedUser.ID}}
	collection.FindOne(context.TODO(), filter, opts).Decode(&entry)

	if entry.Type == "file" {
		c.JSON(http.StatusOK, gin.H{
			"type":     "file",
			"filename": entry.Filename,
			"filepath": entry.Filepath,
			"message":  "Use this path to download the file.",
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"type":    entry.Type,
			"content": entry.Content,
		})
	}
}

