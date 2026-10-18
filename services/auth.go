package services

import (
	"clipMan/authprovider"
	"clipMan/config"
	"clipMan/models"
	"clipMan/repositories"
	"context"
	"errors"
	"regexp"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var (
	ErrAuthUnavailable      = errors.New("email authentication is not configured")
	ErrInvalidEmail         = errors.New("enter a valid email address")
	ErrInvalidCode          = errors.New("enter the six-digit code")
	ErrUnverifiedEmail      = errors.New("the identity provider did not verify the email")
	ErrPendingLinkNotFound  = errors.New("email link request expired; request a new code")
	ErrIdentityConflict     = errors.New("this email identity belongs to another account")
	ErrEmailConflict        = errors.New("this email is already linked to another account")
	ErrAccountAlreadyLinked = errors.New("this account already has a linked email")
)

var magicCodePattern = regexp.MustCompile(`^\d{6}$`)
var emailPattern = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

type AuthResult struct {
	User         *models.User
	SessionToken string
}

type AuthService struct {
	provider authprovider.Provider
}

func NewAuthService(provider authprovider.Provider) *AuthService {
	return &AuthService{provider: provider}
}

func (service *AuthService) Available() bool {
	return service != nil && service.provider != nil
}

func (service *AuthService) StartMagicAuth(ctx context.Context, email string, request authprovider.RequestContext) error {
	normalized, err := validateEmail(email)
	if err != nil {
		return err
	}
	if !service.Available() {
		return ErrAuthUnavailable
	}
	return service.provider.StartMagicAuth(ctx, normalized, request)
}

func (service *AuthService) VerifyMagicAuth(ctx context.Context, email, code string, request authprovider.RequestContext) (*AuthResult, error) {
	normalized, err := validateEmail(email)
	if err != nil {
		return nil, err
	}
	if !magicCodePattern.MatchString(code) {
		return nil, ErrInvalidCode
	}
	if !service.Available() {
		return nil, ErrAuthUnavailable
	}

	providerUser, err := service.provider.VerifyMagicAuth(ctx, normalized, code, request)
	if err != nil {
		return nil, err
	}
	if !providerUser.EmailVerified || repositories.NormalizeEmail(providerUser.Email) != normalized {
		return nil, ErrUnverifiedEmail
	}

	user, err := service.findOrCreateUser(ctx, providerUser)
	if err != nil {
		return nil, err
	}
	sessionToken, err := repositories.CreateSession(ctx, user.ID, config.AppConfig.SessionDuration)
	if err != nil {
		return nil, err
	}
	return &AuthResult{User: user, SessionToken: sessionToken}, nil
}

func (service *AuthService) StartEmailLink(ctx context.Context, user *models.User, email string, request authprovider.RequestContext) error {
	normalized, err := validateEmail(email)
	if err != nil {
		return err
	}
	if !service.Available() {
		return ErrAuthUnavailable
	}

	existingIdentity, err := repositories.GetIdentityForUser(ctx, user.ID, service.provider.Name())
	if err != nil {
		return err
	}
	if existingIdentity != nil {
		return ErrAccountAlreadyLinked
	}
	existingUser, err := repositories.GetVerifiedUserByEmail(ctx, normalized)
	if err != nil {
		return err
	}
	if existingUser != nil && existingUser.ID != user.ID {
		return ErrEmailConflict
	}

	if err := service.provider.StartMagicAuth(ctx, normalized, request); err != nil {
		return err
	}
	now := time.Now().UTC()
	return repositories.UpsertPendingEmailLink(ctx, models.PendingEmailLink{
		UserID:    user.ID,
		Email:     normalized,
		CreatedAt: now,
		ExpiresAt: now.Add(10 * time.Minute),
	})
}

func (service *AuthService) ConfirmEmailLink(ctx context.Context, user *models.User, code string, request authprovider.RequestContext) (*models.User, error) {
	if !magicCodePattern.MatchString(code) {
		return nil, ErrInvalidCode
	}
	if !service.Available() {
		return nil, ErrAuthUnavailable
	}

	pending, err := repositories.GetPendingEmailLink(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	if pending == nil {
		return nil, ErrPendingLinkNotFound
	}
	providerUser, err := service.provider.VerifyMagicAuth(ctx, pending.Email, code, request)
	if err != nil {
		return nil, err
	}
	if !providerUser.EmailVerified || repositories.NormalizeEmail(providerUser.Email) != pending.Email {
		return nil, ErrUnverifiedEmail
	}

	linkedUser, err := service.linkIdentity(ctx, user, providerUser)
	if err != nil {
		return nil, err
	}
	_ = repositories.DeletePendingEmailLink(ctx, user.ID)
	return linkedUser, nil
}

func (service *AuthService) findOrCreateUser(ctx context.Context, providerUser *authprovider.User) (*models.User, error) {
	identity, err := repositories.GetIdentity(ctx, service.provider.Name(), providerUser.Subject)
	if err != nil {
		return nil, err
	}
	if identity != nil {
		return repositories.GetUserByID(ctx, identity.UserID)
	}

	existingUser, err := repositories.GetVerifiedUserByEmail(ctx, providerUser.Email)
	if err != nil {
		return nil, err
	}
	if existingUser != nil {
		return nil, ErrEmailConflict
	}

	user, err := repositories.CreateProviderUser(ctx, providerUser.Email)
	if err != nil {
		return nil, err
	}
	if err := service.createIdentity(ctx, user.ID, providerUser); err != nil {
		_ = repositories.DeleteUserByID(ctx, user.ID)
		if mongo.IsDuplicateKeyError(err) {
			identity, lookupErr := repositories.GetIdentity(ctx, service.provider.Name(), providerUser.Subject)
			if lookupErr == nil && identity != nil {
				return repositories.GetUserByID(ctx, identity.UserID)
			}
		}
		return nil, err
	}
	return user, nil
}

func (service *AuthService) linkIdentity(ctx context.Context, user *models.User, providerUser *authprovider.User) (*models.User, error) {
	identity, err := repositories.GetIdentity(ctx, service.provider.Name(), providerUser.Subject)
	if err != nil {
		return nil, err
	}
	if identity != nil && identity.UserID != user.ID {
		return nil, ErrIdentityConflict
	}

	userIdentity, err := repositories.GetIdentityForUser(ctx, user.ID, service.provider.Name())
	if err != nil {
		return nil, err
	}
	if userIdentity != nil && userIdentity.ProviderSubject != providerUser.Subject {
		return nil, ErrAccountAlreadyLinked
	}

	emailOwner, err := repositories.GetVerifiedUserByEmail(ctx, providerUser.Email)
	if err != nil {
		return nil, err
	}
	if emailOwner != nil && emailOwner.ID != user.ID {
		return nil, ErrEmailConflict
	}

	createdIdentity := false
	if identity == nil && userIdentity == nil {
		if err := service.createIdentity(ctx, user.ID, providerUser); err != nil {
			if mongo.IsDuplicateKeyError(err) {
				return nil, ErrIdentityConflict
			}
			return nil, err
		}
		createdIdentity = true
	}

	updatedUser, err := repositories.UpdateUserVerifiedEmail(ctx, user.ID, providerUser.Email)
	if err != nil {
		if createdIdentity {
			_ = repositories.DeleteIdentity(ctx, user.ID, service.provider.Name())
		}
		if mongo.IsDuplicateKeyError(err) {
			return nil, ErrEmailConflict
		}
		return nil, err
	}
	return updatedUser, nil
}

func (service *AuthService) createIdentity(ctx context.Context, userID primitive.ObjectID, providerUser *authprovider.User) error {
	now := time.Now().UTC()
	return repositories.CreateIdentity(ctx, models.AuthIdentity{
		UserID:          userID,
		Provider:        service.provider.Name(),
		ProviderSubject: providerUser.Subject,
		Email:           repositories.NormalizeEmail(providerUser.Email),
		VerifiedAt:      &now,
		CreatedAt:       now,
		UpdatedAt:       now,
	})
}

func validateEmail(value string) (string, error) {
	normalized := repositories.NormalizeEmail(value)
	if len(normalized) > 254 || !emailPattern.MatchString(normalized) {
		return "", ErrInvalidEmail
	}
	return normalized, nil
}

func ProviderErrorMessage(err error) string {
	switch {
	case errors.Is(err, ErrAuthUnavailable),
		errors.Is(err, ErrInvalidEmail),
		errors.Is(err, ErrInvalidCode),
		errors.Is(err, ErrPendingLinkNotFound),
		errors.Is(err, ErrIdentityConflict),
		errors.Is(err, ErrEmailConflict),
		errors.Is(err, ErrAccountAlreadyLinked):
		return err.Error()
	default:
		return "authentication could not be completed"
	}
}
