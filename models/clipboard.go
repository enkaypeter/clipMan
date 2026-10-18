package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ClipboardEntry struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Type      string             `bson:"type" json:"type"`
	Title     string             `bson:"title,omitempty" json:"title,omitempty"`
	Filename  string             `bson:"filename,omitempty" json:"filename,omitempty"`
	Content   string             `bson:"content" json:"content"`
	Timestamp time.Time          `bson:"timestamp" json:"timestamp"`
	Filepath  string             `bson:"filepath,omitempty" json:"filepath,omitempty"`
	UserId    primitive.ObjectID `bson:"user_id" json:"user_id"`
	Pinned    bool               `bson:"pinned,omitempty" json:"pinned"`
}
