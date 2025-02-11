package services

import (
	"clipMan/models"
	"clipMan/repositories"
	"clipMan/utils"

	"errors"

	"golang.org/x/crypto/bcrypt"
)

type UserService struct{}

func (us *UserService) RegisterUser(user models.User) error {
    existingUser, err := repositories.GetUserByUsername(user.Username)
    if err != nil {
        return err
    }
    
    if existingUser != nil {
        return errors.New("username already taken")
    }

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(hashedPassword)

    err = repositories.CreateUser(user)
    return err
}

func (us *UserService) LoginUser(username, password string) (string, error) {
    user, err := repositories.GetUserByUsername(username)
    if err != nil {
        return "", err
    }

    if user == nil {
        return "", errors.New("invalid username")
    }

    err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
    if err != nil {
        return "", errors.New("invalid username or password")
    }

    token, err := utils.GenerateJWT(user)

    if err != nil {
        return "", err
    }

    return token, nil
}