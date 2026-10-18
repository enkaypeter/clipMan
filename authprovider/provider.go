package authprovider

import "context"

const WorkOS = "workos"

type RequestContext struct {
	IPAddress string
	UserAgent string
}

type User struct {
	Subject       string
	Email         string
	EmailVerified bool
}

type Provider interface {
	Name() string
	StartMagicAuth(ctx context.Context, email string, request RequestContext) error
	VerifyMagicAuth(ctx context.Context, email, code string, request RequestContext) (*User, error)
}
