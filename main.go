package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"clipMan/config"
	"clipMan/database"
	"clipMan/routes"
	"clipMan/utils"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

func main() {
	config.LoadConfig()
	appConfig := config.AppConfig

	_, err := database.Connect()
	if err != nil {
		log.Fatalf("❌ MongoDB Connection Error: %v", err)
	}

	r := gin.Default()
	if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
		v.RegisterValidation("encryptionKey", utils.ValidateEncryptionKey)
	}

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"}, // Allow all domains
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// API routes
	routes.SetupClipboardRoutes(r)
	routes.SetupUserRoutes(r)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := r.Run(fmt.Sprintf(":%v", appConfig.PORT)); err != nil {
			log.Fatalf("❌ Server Startup Error: %v", err)
		}
	}()

	<-quit
	log.Println("🛑 Shutting down server...")

	database.Disconnect()
}
