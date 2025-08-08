package controllers

import (
	"net/http"

	"clipMan/models"
	"clipMan/utils"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// LoginGoogle handles OAuth login with Google. This is a simplified placeholder that accepts a fixed token value.
func LoginGoogle(c *gin.Context) {
	var payload struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		utils.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}
	if payload.Token != "valid_google_token" {
		utils.RespondError(c, http.StatusUnauthorized, "Invalid Google token")
		return
	}
	user := &models.User{ID: primitive.NewObjectID(), Username: "google_user"}
	jwt, err := utils.GenerateJWT(user)
	if err != nil {
		utils.RespondError(c, http.StatusInternalServerError, err.Error())
		return
	}
	utils.RespondSuccess(c, http.StatusOK, gin.H{"token": jwt}, "")
}

// LoginApple handles OAuth login with Apple. This is a simplified placeholder that accepts a fixed token value.
func LoginApple(c *gin.Context) {
	var payload struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		utils.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}
	if payload.Token != "valid_apple_token" {
		utils.RespondError(c, http.StatusUnauthorized, "Invalid Apple token")
		return
	}
	user := &models.User{ID: primitive.NewObjectID(), Username: "apple_user"}
	jwt, err := utils.GenerateJWT(user)
	if err != nil {
		utils.RespondError(c, http.StatusInternalServerError, err.Error())
		return
	}
	utils.RespondSuccess(c, http.StatusOK, gin.H{"token": jwt}, "")
}
