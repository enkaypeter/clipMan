package controllers

import (
	"clipMan/authprovider"
	"clipMan/config"
	"clipMan/models"
	"clipMan/repositories"
	"clipMan/services"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

var authService = services.NewAuthService(nil)

func ConfigureAuthService(service *services.AuthService) {
	authService = service
}

type legacyLoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type emailRequest struct {
	Email string `json:"email" binding:"required"`
}

type magicVerifyRequest struct {
	Email string `json:"email" binding:"required"`
	Code  string `json:"code" binding:"required"`
}

type codeRequest struct {
	Code string `json:"code" binding:"required"`
}

func LoginUser(c *gin.Context) {
	var request legacyLoginRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Username and password are required"})
		return
	}

	token, user, err := (&services.UserService{}).LoginUser(request.Username, request.Password)
	if err != nil {
		log.Println("Login error:", err)
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid credentials"})
		return
	}
	sessionToken, err := repositories.CreateSession(c.Request.Context(), user.ID, config.AppConfig.SessionDuration)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Could not create session"})
		return
	}
	setSessionCookie(c, sessionToken)
	c.JSON(http.StatusOK, gin.H{"token": token, "user": user})
}

func StartMagicAuth(c *gin.Context) {
	var request emailRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Email is required"})
		return
	}
	if err := authService.StartMagicAuth(c.Request.Context(), request.Email, providerRequest(c)); err != nil {
		writeAuthError(c, err, http.StatusBadGateway)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"message": "If the address can receive email, a sign-in code is on its way"})
}

func VerifyMagicAuth(c *gin.Context) {
	var request magicVerifyRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Email and code are required"})
		return
	}
	result, err := authService.VerifyMagicAuth(c.Request.Context(), request.Email, request.Code, providerRequest(c))
	if err != nil {
		writeAuthError(c, err, http.StatusUnauthorized)
		return
	}
	setSessionCookie(c, result.SessionToken)
	c.JSON(http.StatusOK, gin.H{"user": result.User})
}

func StartEmailLink(c *gin.Context) {
	user, ok := authenticatedUser(c)
	if !ok {
		return
	}
	var request emailRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Email is required"})
		return
	}
	if err := authService.StartEmailLink(c.Request.Context(), user, request.Email, providerRequest(c)); err != nil {
		writeAuthError(c, err, http.StatusBadGateway)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"message": "We sent a verification code to that email address"})
}

func ConfirmEmailLink(c *gin.Context) {
	user, ok := authenticatedUser(c)
	if !ok {
		return
	}
	var request codeRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Verification code is required"})
		return
	}
	updatedUser, err := authService.ConfirmEmailLink(c.Request.Context(), user, request.Code, providerRequest(c))
	if err != nil {
		writeAuthError(c, err, http.StatusUnauthorized)
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": updatedUser})
}

func CurrentUser(c *gin.Context) {
	user, ok := authenticatedUser(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": user})
}

func LogoutUser(c *gin.Context) {
	token, _ := c.Cookie(config.AppConfig.SessionCookieName)
	if err := repositories.DeleteSession(c.Request.Context(), token); err != nil {
		log.Printf("Could not delete session: %v", err)
	}
	clearSessionCookie(c)
	c.Status(http.StatusNoContent)
}

func authenticatedUser(c *gin.Context) (*models.User, bool) {
	value, exists := c.Get("user")
	user, ok := value.(*models.User)
	if !exists || !ok || user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Authentication required"})
		return nil, false
	}
	return user, true
}

func providerRequest(c *gin.Context) authprovider.RequestContext {
	return authprovider.RequestContext{IPAddress: c.ClientIP(), UserAgent: c.Request.UserAgent()}
}

func setSessionCookie(c *gin.Context, token string) {
	c.SetSameSite(config.AppConfig.SessionCookieSameSite)
	c.SetCookie(
		config.AppConfig.SessionCookieName,
		token,
		int(config.AppConfig.SessionDuration/time.Second),
		"/",
		"",
		config.AppConfig.SessionCookieSecure,
		true,
	)
}

func clearSessionCookie(c *gin.Context) {
	c.SetSameSite(config.AppConfig.SessionCookieSameSite)
	c.SetCookie(config.AppConfig.SessionCookieName, "", -1, "/", "", config.AppConfig.SessionCookieSecure, true)
}

func writeAuthError(c *gin.Context, err error, fallbackStatus int) {
	status := fallbackStatus
	if errors.Is(err, services.ErrAuthUnavailable) {
		status = http.StatusServiceUnavailable
	} else if errors.Is(err, services.ErrInvalidEmail) || errors.Is(err, services.ErrInvalidCode) {
		status = http.StatusBadRequest
	} else if errors.Is(err, services.ErrIdentityConflict) || errors.Is(err, services.ErrEmailConflict) || errors.Is(err, services.ErrAccountAlreadyLinked) {
		status = http.StatusConflict
	}
	if status >= http.StatusInternalServerError {
		log.Printf("Authentication provider error: %v", err)
	}
	c.JSON(status, gin.H{"message": services.ProviderErrorMessage(err)})
}
