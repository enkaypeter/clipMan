package middleware

import (
	"clipMan/config"
	"clipMan/models"
	"clipMan/repositories"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, err := authenticateRequest(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid or expired session"})
			c.Abort()
			return
		}
		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Authentication required"})
			c.Abort()
			return
		}

		c.Set("user", user)
		c.Next()
	}
}

func authenticateRequest(c *gin.Context) (*models.User, error) {
	if token, err := c.Cookie(config.AppConfig.SessionCookieName); err == nil && token != "" {
		user, sessionErr := repositories.GetUserBySessionToken(c.Request.Context(), token)
		if sessionErr != nil || user != nil {
			return user, sessionErr
		}
	}

	header := c.GetHeader("Authorization")
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, nil
	}
	return authenticateLegacyJWT(parts[1])
}

func authenticateLegacyJWT(tokenString string) (*models.User, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
		}
		return []byte(config.AppConfig.JWTSecret), nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}
	userID, ok := claims["id"].(string)
	if !ok || userID == "" {
		return nil, errors.New("missing user ID")
	}
	return repositories.GetUser(map[string]interface{}{"_id": userID})
}
