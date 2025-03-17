package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	MongoURI string
	MongoDB  string
	JWTSecret string
	PORT string
}

type CollectionName string

var DB_Collection = struct {
	Entries CollectionName
	Users   CollectionName
}{
	Entries: "entries",
	Users:   "users",
}



var AppConfig *Config

func LoadConfig() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	AppConfig = &Config{
		MongoURI: getEnv("MONGO_URI", "mongodb://localhost:27017"),
		MongoDB:  getEnv("MONGO_DB", "clipboardDB"),
		JWTSecret: getEnv("JWT_SECRET", ""),
		PORT: getEnv("APP_PORT", "8080"),
	}

	log.Println("Environment variables loaded successfully")
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
