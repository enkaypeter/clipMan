package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"clipMan/config"
	"clipMan/database"
	"clipMan/routes"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	config.LoadConfig()

	_, err := database.Connect()
	if err != nil {
		log.Fatalf("❌ MongoDB Connection Error: %v", err)
	}


	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"}, // Allow all domains
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// Setup API routes
	routes.SetupClipboardRoutes(r)
	routes.SetupUserRoutes(r)

	// Handle graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		if err := r.Run(":8080"); err != nil {
			log.Fatalf("❌ Server Startup Error: %v", err)
		}
	}()

	// Wait for termination signal
	<-quit
	log.Println("🛑 Shutting down server...")

	// Gracefully disconnect MongoDB
	database.Disconnect()
}
