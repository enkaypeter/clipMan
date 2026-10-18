package authprovider

import (
	"context"
	"errors"

	workos "github.com/workos/workos-go/v10"
)

var ErrInvalidProviderResponse = errors.New("identity provider returned an invalid user")

type WorkOSProvider struct {
	client *workos.Client
}

func NewWorkOS(apiKey, clientID string) *WorkOSProvider {
	return &WorkOSProvider{client: workos.NewClient(apiKey, workos.WithClientID(clientID))}
}

func (provider *WorkOSProvider) Name() string {
	return WorkOS
}

func (provider *WorkOSProvider) StartMagicAuth(ctx context.Context, email string, request RequestContext) error {
	params := &workos.UserManagementCreateMagicAuthParams{
		Email:     email,
		IPAddress: optionalString(request.IPAddress),
		UserAgent: optionalString(request.UserAgent),
	}
	_, err := provider.client.UserManagement().CreateMagicAuth(ctx, params)
	return err
}

func (provider *WorkOSProvider) VerifyMagicAuth(ctx context.Context, email, code string, request RequestContext) (*User, error) {
	response, err := provider.client.UserManagement().AuthenticateWithMagicAuth(ctx, &workos.UserManagementAuthenticateWithMagicAuthParams{
		Email:     email,
		Code:      code,
		IPAddress: optionalString(request.IPAddress),
		UserAgent: optionalString(request.UserAgent),
	})
	if err != nil {
		return nil, err
	}
	if response.User == nil || response.User.ID == "" || response.User.Email == "" {
		return nil, ErrInvalidProviderResponse
	}
	return &User{
		Subject:       response.User.ID,
		Email:         response.User.Email,
		EmailVerified: response.User.EmailVerified,
	}, nil
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
