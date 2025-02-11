package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User represents a user in the system
type User struct {
    ID        primitive.ObjectID    `json:"id,omitempty" bson:"_id,omitempty"`
    Username  string    `json:"username" bson:"username"`
    Password  string    `json:"password" bson:"password"`
    Email     string    `json:"email" bson:"email"`
    CreatedAt time.Time `json:"createdAt" bson:"createdAt"`
}
