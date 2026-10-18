package config

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	MongoURI            string
	MongoDB             string
	JWTSecret           string
	PORT                string
	WorkOSAPIKey        string
	WorkOSClientID      string
	SessionCookieName   string
	SessionCookieSecure bool
	SessionDuration     time.Duration
	CORSAllowOrigins    []string
}

type CollectionName string

var DB_Collection = struct {
	Entries           CollectionName
	Users             CollectionName
	AuthIdentities    CollectionName
	PendingEmailLinks CollectionName
	Sessions          CollectionName
}{
	Entries:           "entries",
	Users:             "users",
	AuthIdentities:    "auth_identities",
	PendingEmailLinks: "pending_email_links",
	Sessions:          "sessions",
}

var AppConfig *Config

func LoadConfig() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	ginMode := getEnv("GIN_MODE", "debug")
	AppConfig = &Config{
		MongoURI:            getEnv("MONGO_URI", "mongodb://localhost:27017"),
		MongoDB:             getEnv("MONGO_DB", getEnv("MONGO_DB_NAME", "clipboardDB")),
		JWTSecret:           getEnv("JWT_SECRET", ""),
		PORT:                getEnv("APP_PORT", "8080"),
		WorkOSAPIKey:        getEnv("WORKOS_API_KEY", ""),
		WorkOSClientID:      getEnv("WORKOS_CLIENT_ID", ""),
		SessionCookieName:   getEnv("SESSION_COOKIE_NAME", "clipman_session"),
		SessionCookieSecure: getEnvBool("SESSION_COOKIE_SECURE", ginMode == "release"),
		SessionDuration:     getEnvDuration("SESSION_DURATION", 30*24*time.Hour),
		CORSAllowOrigins:    getEnvList("CORS_ALLOW_ORIGINS", "http://localhost:5173"),
	}

	log.Println("Environment variables loaded successfully")
}

func getEnvBool(key string, defaultValue bool) bool {
	value, exists := os.LookupEnv(key)
	if !exists {
		return defaultValue
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		log.Printf("Invalid boolean value for %s; using default", key)
		return defaultValue
	}
	return parsed
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	value, exists := os.LookupEnv(key)
	if !exists {
		return defaultValue
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		log.Printf("Invalid duration value for %s; using default", key)
		return defaultValue
	}
	return parsed
}

func getEnvList(key, defaultValue string) []string {
	values := strings.Split(getEnv(key, defaultValue), ",")
	result := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
