package controllers

import (
	"clipMan/dto/user"
	"clipMan/models"
	"clipMan/api"

	"clipMan/services"
	"net/http"

	"github.com/gin-gonic/gin"
)

type LoginResponse struct {
	User struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	} `json:"user"`
	Token string `json:"token"`
}

func LoginUser(c *gin.Context) {
	var loginData user.UserLoginDTO

	if err := c.ShouldBindJSON(&loginData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userService := services.UserService{}

    loggedUser, err := userService.LoginUser(loginData.Username, loginData.Password)
    if err != nil {
        if err.Error() == "invalid credentials" {
            api.ErrResponse[error](c, http.StatusUnauthorized, err.Error())
            return
        }

        api.ErrResponse[error](c, http.StatusBadRequest, err.Error())
    }

	responseObject := &LoginResponse{
		User: struct {
			Username string `json:"username"`
			Email    string `json:"email"`
		}{
			Username: loggedUser.User.Username,
			Email:    loggedUser.User.Email,
		},
		Token: loggedUser.Token,
	}

	api.SuccessResponse(c, responseObject, api.StringPtr("Login successful"))
}

func RegisterUser(c *gin.Context) {
	var user models.User

	if err := c.ShouldBindJSON(&user); err != nil {
        api.ErrResponse[error](c, http.StatusBadRequest, err.Error())
        return
	}

	userService := services.UserService{}
	if err := userService.RegisterUser(user); err != nil {
        api.ErrResponse[error](c, http.StatusInternalServerError, err.Error())
        return
	}

    loggedUser, err := userService.LoginUser(user.Username, user.Password)
    if err != nil {
        api.ErrResponse[error](c, http.StatusBadRequest, err.Error())
    }

    responseObject := &LoginResponse{
		User: struct {
			Username string `json:"username"`
			Email    string `json:"email"`
		}{
			Username: loggedUser.User.Username,
			Email:    loggedUser.User.Email,
		},
		Token: loggedUser.Token,
	}

    api.SuccessResponse(c, responseObject, api.StringPtr("User registered successfully"))
}
