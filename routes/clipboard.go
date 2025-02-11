package routes

import (
	"github.com/gin-gonic/gin"
	"clipMan/controllers"
	
	"clipMan/middleware"

)

// SetupRoutes registers the API routes.
func SetupClipboardRoutes(r *gin.Engine) {

	private := r.Group("/api")
	private.Use(middleware.AuthMiddleware())
			
	private.POST("/clipboard", controllers.CopyClipboard)
	private.GET("/clipboard", controllers.PasteClipboard)
	
}
