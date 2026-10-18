package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"clipMan/authprovider"
	"clipMan/config"
	"clipMan/controllers"
	"clipMan/database"
	"clipMan/routes"
	"clipMan/services"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	config.LoadConfig()
	appConfig := config.AppConfig

	_, err := database.Connect()
	if err != nil {
		log.Fatalf("❌ MongoDB Connection Error: %v", err)
	}

	if appConfig.WorkOSAPIKey != "" && appConfig.WorkOSClientID != "" {
		controllers.ConfigureAuthService(services.NewAuthService(
			authprovider.NewWorkOS(appConfig.WorkOSAPIKey, appConfig.WorkOSClientID),
		))
	} else {
		log.Println("⚠️ WorkOS email authentication is disabled; set WORKOS_API_KEY and WORKOS_CLIENT_ID to enable it")
	}

	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     appConfig.CORSAllowOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
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
