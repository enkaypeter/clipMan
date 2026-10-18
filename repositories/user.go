package repositories

import (
	"clipMan/config"
	"clipMan/database"
	"clipMan/models"
	"context"
	"errors"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var ErrIdentityAlreadyLinked = errors.New("identity is already linked to another account")
var ErrEmailAlreadyLinked = errors.New("email is already linked to another account")

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func GetUser(filters map[string]interface{}) (*models.User, error) {
	filter := bson.M{}
	for key, value := range filters {
		if key != "_id" {
			filter[key] = value
			continue
		}

		id, ok := value.(string)
		if !ok {
			return nil, errors.New("user ID must be a string")
		}
		objectID, err := primitive.ObjectIDFromHex(id)
		if err != nil {
			return nil, err
		}
		filter[key] = objectID
	}

	return findUser(filter)
}

func GetUserByID(ctx context.Context, id primitive.ObjectID) (*models.User, error) {
	return findUserWithContext(ctx, bson.M{"_id": id})
}

func GetUserByUsername(username string) (*models.User, error) {
	return findUser(bson.M{"username": strings.TrimSpace(username)})
}

func GetVerifiedUserByEmail(ctx context.Context, email string) (*models.User, error) {
	return findUserWithContext(ctx, bson.M{
		"email_normalized": NormalizeEmail(email),
		"email_verified":   true,
	})
}

func findUser(filter bson.M) (*models.User, error) {
	return findUserWithContext(context.Background(), filter)
}

func findUserWithContext(ctx context.Context, filter bson.M) (*models.User, error) {
	var user models.User
	err := database.GetCollection(config.DB_Collection.Users).FindOne(ctx, filter).Decode(&user)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func CreateUser(user models.User) error {
	_, err := database.GetCollection(config.DB_Collection.Users).InsertOne(context.Background(), user)
	return err
}

func CreateProviderUser(ctx context.Context, email string) (*models.User, error) {
	now := time.Now().UTC()
	user := &models.User{
		ID:              primitive.NewObjectID(),
		Email:           NormalizeEmail(email),
		EmailNormalized: NormalizeEmail(email),
		EmailVerified:   true,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	_, err := database.GetCollection(config.DB_Collection.Users).InsertOne(ctx, user)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func DeleteUserByID(ctx context.Context, userID primitive.ObjectID) error {
	_, err := database.GetCollection(config.DB_Collection.Users).DeleteOne(ctx, bson.M{"_id": userID})
	return err
}

func UpdateUserVerifiedEmail(ctx context.Context, userID primitive.ObjectID, email string) (*models.User, error) {
	normalized := NormalizeEmail(email)
	return findOneAndUpdateUser(ctx, bson.M{"_id": userID}, bson.M{"$set": bson.M{
		"email":            normalized,
		"email_normalized": normalized,
		"email_verified":   true,
		"updated_at":       time.Now().UTC(),
	}})
}

func findOneAndUpdateUser(ctx context.Context, filter, update bson.M) (*models.User, error) {
	var user models.User
	err := database.GetCollection(config.DB_Collection.Users).FindOneAndUpdate(
		ctx,
		filter,
		update,
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	).Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func GetIdentity(ctx context.Context, provider, subject string) (*models.AuthIdentity, error) {
	var identity models.AuthIdentity
	err := database.GetCollection(config.DB_Collection.AuthIdentities).FindOne(ctx, bson.M{
		"provider":         provider,
		"provider_subject": subject,
	}).Decode(&identity)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &identity, nil
}

func GetIdentityForUser(ctx context.Context, userID primitive.ObjectID, provider string) (*models.AuthIdentity, error) {
	var identity models.AuthIdentity
	err := database.GetCollection(config.DB_Collection.AuthIdentities).FindOne(ctx, bson.M{
		"user_id":  userID,
		"provider": provider,
	}).Decode(&identity)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &identity, nil
}

func CreateIdentity(ctx context.Context, identity models.AuthIdentity) error {
	_, err := database.GetCollection(config.DB_Collection.AuthIdentities).InsertOne(ctx, identity)
	return err
}

func DeleteIdentity(ctx context.Context, userID primitive.ObjectID, provider string) error {
	_, err := database.GetCollection(config.DB_Collection.AuthIdentities).DeleteOne(ctx, bson.M{
		"user_id":  userID,
		"provider": provider,
	})
	return err
}

func UpsertPendingEmailLink(ctx context.Context, link models.PendingEmailLink) error {
	_, err := database.GetCollection(config.DB_Collection.PendingEmailLinks).UpdateOne(
		ctx,
		bson.M{"user_id": link.UserID},
		bson.M{"$set": bson.M{
			"email":      link.Email,
			"expires_at": link.ExpiresAt,
			"created_at": link.CreatedAt,
		}},
		options.Update().SetUpsert(true),
	)
	return err
}

func GetPendingEmailLink(ctx context.Context, userID primitive.ObjectID) (*models.PendingEmailLink, error) {
	var link models.PendingEmailLink
	err := database.GetCollection(config.DB_Collection.PendingEmailLinks).FindOne(ctx, bson.M{
		"user_id":    userID,
		"expires_at": bson.M{"$gt": time.Now().UTC()},
	}).Decode(&link)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &link, nil
}

func DeletePendingEmailLink(ctx context.Context, userID primitive.ObjectID) error {
	_, err := database.GetCollection(config.DB_Collection.PendingEmailLinks).DeleteOne(ctx, bson.M{"user_id": userID})
	return err
}
