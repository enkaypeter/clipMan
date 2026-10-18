package database

import (
	"clipMan/config"
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var MongoClient *mongo.Client
var MongoCtx = context.Background()

func Connect() (*mongo.Client, error) {
	ctx, cancel := context.WithTimeout(MongoCtx, 30*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI(config.AppConfig.MongoURI)

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("MongoDB connection failed: %v", err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("MongoDB ping failed: %v", err)
	}

	log.Println("✅ Connected to MongoDB")

	MongoClient = client
	if err := EnsureIndexes(ctx); err != nil {
		return nil, fmt.Errorf("MongoDB index creation failed: %v", err)
	}
	return client, nil
}

func EnsureIndexes(ctx context.Context) error {
	database := MongoClient.Database(config.AppConfig.MongoDB)
	indexSets := []struct {
		collection string
		models     []mongo.IndexModel
	}{
		{
			collection: string(config.DB_Collection.Users),
			models: []mongo.IndexModel{
				{Keys: bson.D{{Key: "username", Value: 1}}, Options: options.Index().SetUnique(true).SetSparse(true)},
				{Keys: bson.D{{Key: "email_normalized", Value: 1}}, Options: options.Index().SetUnique(true).SetPartialFilterExpression(bson.M{"email_verified": true})},
			},
		},
		{
			collection: string(config.DB_Collection.AuthIdentities),
			models: []mongo.IndexModel{
				{Keys: bson.D{{Key: "provider", Value: 1}, {Key: "provider_subject", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "user_id", Value: 1}, {Key: "provider", Value: 1}}, Options: options.Index().SetUnique(true)},
			},
		},
		{
			collection: string(config.DB_Collection.PendingEmailLinks),
			models: []mongo.IndexModel{
				{Keys: bson.D{{Key: "user_id", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
			},
		},
		{
			collection: string(config.DB_Collection.Sessions),
			models: []mongo.IndexModel{
				{Keys: bson.D{{Key: "token_hash", Value: 1}}, Options: options.Index().SetUnique(true)},
				{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
			},
		},
	}

	for _, indexSet := range indexSets {
		if _, err := database.Collection(indexSet.collection).Indexes().CreateMany(ctx, indexSet.models); err != nil {
			return err
		}
	}
	return nil
}

func GetCollection(collectionName config.CollectionName) *mongo.Collection {
	return MongoClient.Database(config.AppConfig.MongoDB).Collection(string(collectionName))
}

func Disconnect() {
	if MongoClient != nil {
		if err := MongoClient.Disconnect(MongoCtx); err != nil {
			log.Fatalf("❌ MongoDB Disconnection Error: %v", err)
		}
		log.Println("✅ MongoDB Disconnected")
	}
}
