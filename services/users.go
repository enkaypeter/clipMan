package services

import (
	"clipMan/models"
	"clipMan/repositories"
	"clipMan/utils"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

type UserService struct{}

func (us *UserService) LoginUser(username, password string) (string, *models.User, error) {
	user, err := repositories.GetUserByUsername(username)
	if err != nil {
		return "", nil, err
	}
	if user == nil {
		return "", nil, errors.New("invalid username")
	}
	if user.EmailVerified {
		return "", nil, errors.New("use email authentication for this account")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", nil, errors.New("invalid username or password")
	}

	token, err := utils.GenerateJWT(user)
	if err != nil {
		return "", nil, err
	}
	return token, user, nil
}
