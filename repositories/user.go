package repositories

import (
	"clipMan/config"
	"clipMan/database"
	"clipMan/models"
	"context"
	"log"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)


func GetUser(filters map[string]interface{}) (*models.User, error) {
    var user models.User

    filter := bson.M{}
    for key, value := range filters {
        if key == "_id" {
            objID, err := primitive.ObjectIDFromHex(value.(string))
            if err != nil {
                return nil, err
            }
            filter[key] = objID
        } else {
            filter[key] = value
        }


    }
 

    userCollection := database.GetCollection(config.DB_Collection.Users)

    err := userCollection.FindOne(context.Background(), filter).Decode(&user)
    if err == mongo.ErrNoDocuments {
        return nil, nil
    }

    if err != nil {
        log.Println("Error fetching user:", err)
        return nil, err
    }


    return &user, nil
}

func CreateUser(user models.User) error {
    userCollection := database.GetCollection(config.DB_Collection.Users)
    _, err := userCollection.InsertOne(context.Background(), user)
    return err
}

func GetUserByUsername(username string) (*models.User, error) {
    var user models.User
    userCollection := database.GetCollection(config.DB_Collection.Users)
    err := userCollection.FindOne(context.Background(), bson.M{"username": username}).Decode(&user)
    
    if err != nil {
        log.Println("Err:", err)
        if err == mongo.ErrNoDocuments {
            return nil, nil
        }
        panic(err)
    }

    return &user, err
}
