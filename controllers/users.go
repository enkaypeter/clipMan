package controllers

import (
	"clipMan/dto/user"
	"clipMan/models"
	"log"

	"clipMan/services"
	"clipMan/utils"
	"net/http"

	"github.com/gin-gonic/gin"
)

func LoginUser(c *gin.Context) {
	var loginData user.UserLoginDTO

	if err := c.ShouldBindJSON(&loginData); err != nil {
		utils.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}

	userService := services.UserService{}

	token, err := userService.LoginUser(loginData.Username, loginData.Password)
	if err != nil {
		log.Println("Login error:", err)
		utils.RespondError(c, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	utils.RespondSuccess(c, http.StatusOK, gin.H{"token": token}, "")
}

func RegisterUser(c *gin.Context) {
	var user models.User

	if err := c.ShouldBindJSON(&user); err != nil {
		utils.RespondError(c, http.StatusBadRequest, err.Error())
		return
	}

	userService := services.UserService{}

	if err := userService.RegisterUser(user); err != nil {
		utils.RespondError(c, http.StatusInternalServerError, err.Error())
		return
	}

	utils.RespondSuccess(c, http.StatusCreated, gin.H{"message": "User registered successfully"}, "")
}
