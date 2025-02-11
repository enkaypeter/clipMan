package routes

import (
    "clipMan/controllers"
    "github.com/gin-gonic/gin"
)

// SetupUserRoutes defines the routes for user-related operations.
func SetupUserRoutes(r *gin.Engine) {
    r.POST("/register", controllers.RegisterUser)
    r.POST("/login", controllers.LoginUser)
}
