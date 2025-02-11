package database

import (
	"clipMan/config"
	"context"
	"fmt"
	"log"
	"time"

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
	return client, nil
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
