package routes

import (
	"github.com/gin-gonic/gin"
	"clipMan/controllers"
	
	"clipMan/middleware"

)

// SetupClipboardRoutes registers the API routes.
func SetupClipboardRoutes(r *gin.Engine) {

	private := r.Group("/api")
	private.Use(middleware.AuthMiddleware())
			
	private.POST("/clipboard", controllers.CopyClipboard)
	private.GET("/clipboard", controllers.PasteClipboard)
	private.GET("/clipboard/:id", controllers.GetClipboardEntryByID)
	private.PATCH("/clipboard/:id", controllers.UpdateClipboardEntry)
	private.DELETE("/clipboard/:id", controllers.DeleteClipboardEntry)
	
}
