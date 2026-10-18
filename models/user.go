package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User represents a user in the system
type User struct {
	ID              primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Email           string             `json:"email,omitempty" bson:"email,omitempty"`
	EmailNormalized string             `json:"-" bson:"email_normalized,omitempty"`
	EmailVerified   bool               `json:"emailVerified" bson:"email_verified"`
	Username        string             `json:"username,omitempty" bson:"username,omitempty"`
	PasswordHash    string             `json:"-" bson:"password,omitempty"`
	CreatedAt       time.Time          `json:"createdAt" bson:"createdAt"`
	UpdatedAt       time.Time          `json:"updatedAt" bson:"updated_at,omitempty"`
}

// AuthIdentity maps an application user to an external identity provider.
// Clipboard ownership always uses UserID, never an email or provider subject.
type AuthIdentity struct {
	ID              primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	UserID          primitive.ObjectID `json:"userId" bson:"user_id"`
	Provider        string             `json:"provider" bson:"provider"`
	ProviderSubject string             `json:"-" bson:"provider_subject"`
	Email           string             `json:"email" bson:"email"`
	VerifiedAt      *time.Time         `json:"verifiedAt,omitempty" bson:"verified_at,omitempty"`
	CreatedAt       time.Time          `json:"createdAt" bson:"created_at"`
	UpdatedAt       time.Time          `json:"updatedAt" bson:"updated_at"`
}

// PendingEmailLink is short-lived state for attaching a verified identity to
// an already authenticated legacy account.
type PendingEmailLink struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	UserID    primitive.ObjectID `bson:"user_id"`
	Email     string             `bson:"email"`
	ExpiresAt time.Time          `bson:"expires_at"`
	CreatedAt time.Time          `bson:"created_at"`
}

// Session stores only a hash of the opaque browser session token.
type Session struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	UserID    primitive.ObjectID `bson:"user_id"`
	TokenHash string             `bson:"token_hash"`
	ExpiresAt time.Time          `bson:"expires_at"`
	CreatedAt time.Time          `bson:"created_at"`
}
