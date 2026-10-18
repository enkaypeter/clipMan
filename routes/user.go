package routes

import (
	"clipMan/controllers"
	"clipMan/middleware"

	"github.com/gin-gonic/gin"
)

// SetupUserRoutes defines the routes for user-related operations.
func SetupUserRoutes(r *gin.Engine) {
	r.POST("/login", controllers.LoginUser)
	r.POST("/auth/magic/start", controllers.StartMagicAuth)
	r.POST("/auth/magic/verify", controllers.VerifyMagicAuth)
	r.POST("/auth/logout", controllers.LogoutUser)

	account := r.Group("/api/account")
	account.Use(middleware.AuthMiddleware())
	account.GET("/me", controllers.CurrentUser)
	account.POST("/email-link/start", controllers.StartEmailLink)
	account.POST("/email-link/confirm", controllers.ConfirmEmailLink)
}
