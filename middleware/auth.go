package middleware

import (
	"clipMan/config"
	"clipMan/models"
	"clipMan/repositories"
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"

	"net/http"
	"strings"
)


func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from Authorization header
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token required"})
			c.Abort()
			return
		}

		// Token format is "Bearer token", so we split the string
		parts := strings.Split(tokenString, " ")
		// log.Println(parts)
		// os.Exit(0)
		
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
			c.Abort()
			return
		}
		tokenString = parts[1]

		// Parse and validate the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
			}

			return []byte(config.AppConfig.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		// Extract the claims and attach the user information to the request context
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}


		userId := claims["id"].(string)
		user, err := getUserById(userId)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching user"})
			c.Abort()
			return
		}

		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			c.Abort()
			return
	}

		// Store user info in the context for downstream handlers
		c.Set("user", user)

		// Proceed to the next middleware or handler
		c.Next()
	}
}

// Helper function to get user by ID (you can replace this with your own implementation)
func getUserById(userId string) (*models.User, error) {	
	dbFilter := map[string]interface{}{"_id": userId}
	user, err := repositories.GetUser(dbFilter) 

	return user, err
}
