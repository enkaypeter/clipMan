package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ClipboardEntry struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Type     string    `json:"type"`         
	Filename string    `json:"filename,omitempty"`
	Content  string    `json:"content"`       
	Timestamp time.Time `json:"timestamp"`
	Filepath  string    `json:"filepath,omitempty"`
	UserId		primitive.ObjectID    `json:"user_id" bson:"user_id"`
}
