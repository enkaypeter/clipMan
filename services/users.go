package services

import (
	"clipMan/models"
	"clipMan/repositories"
	"clipMan/utils"
	"log"

	"errors"

	"golang.org/x/crypto/bcrypt"
)

type UserService struct{}

type LoginUserResponse struct {
	User *models.User 
	Token string
}

func (us *UserService) RegisterUser(user models.User) error {
	filters := map[string]interface{}{
		"username": user.Username,
		"email":    user.Email,
	}
	existingUser, err := repositories.GetExistingUser(filters)
	log.Println(existingUser)

	if existingUser != nil {
		var (
			UsernameTakenErr = errors.New("username already taken")
			EmailTakenErr    = errors.New("email already taken")
		)

		if existingUser.Username == user.Username {
			return UsernameTakenErr
		}
		if existingUser.Email == user.Email {
			return EmailTakenErr
		}
	}

	if err != nil {
		return err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(hashedPassword)

	err = repositories.CreateUser(user)
	return err
}

func (us *UserService) GetUserToken(username, password string) (string, error) {
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

func (us *UserService) LoginUser(username, password string) (*LoginUserResponse, error) {
	token, err := us.GetUserToken(username, password)

	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	userData, err := us.GetUserProfile(username)
	if err != nil {
		return nil, err
	}

	responseDataObject := &LoginUserResponse{
		User: userData,
		Token: token,
	}

    return responseDataObject, nil
}

func (us *UserService) GetUserProfile(username string) (*models.User, error) {
	user, err := repositories.GetUserByUsername(username)
	if err != nil {
		return nil, err
	}
	return user, nil
}
