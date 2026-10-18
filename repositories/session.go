package repositories

import (
	"clipMan/config"
	"clipMan/database"
	"clipMan/models"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func CreateSession(ctx context.Context, userID primitive.ObjectID, duration time.Duration) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	now := time.Now().UTC()
	_, err := database.GetCollection(config.DB_Collection.Sessions).InsertOne(ctx, models.Session{
		UserID:    userID,
		TokenHash: hashSessionToken(token),
		ExpiresAt: now.Add(duration),
		CreatedAt: now,
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

func GetUserBySessionToken(ctx context.Context, token string) (*models.User, error) {
	if token == "" {
		return nil, nil
	}

	var session models.Session
	err := database.GetCollection(config.DB_Collection.Sessions).FindOne(ctx, bson.M{
		"token_hash": hashSessionToken(token),
		"expires_at": bson.M{"$gt": time.Now().UTC()},
	}).Decode(&session)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return GetUserByID(ctx, session.UserID)
}

func DeleteSession(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	_, err := database.GetCollection(config.DB_Collection.Sessions).DeleteOne(ctx, bson.M{"token_hash": hashSessionToken(token)})
	return err
}

func DeleteUserSessions(ctx context.Context, userID primitive.ObjectID) error {
	_, err := database.GetCollection(config.DB_Collection.Sessions).DeleteMany(ctx, bson.M{"user_id": userID})
	return err
}

func hashSessionToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
