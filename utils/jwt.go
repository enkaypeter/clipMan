package utils

import (
	"clipMan/config"
	"clipMan/models"

	"time"

	"github.com/dgrijalva/jwt-go"
)

func GenerateJWT(user *models.User) (string, error) {
	claims := jwt.MapClaims{
		"username": user.Username,
		"id":       user.ID.Hex(),
		"exp":      time.Now().Add(time.Hour * 72).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(config.AppConfig.JWTSecret))
	
	if err != nil {
		return "", err
	}

  return tokenString, nil
}
