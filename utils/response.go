package utils

import "github.com/gin-gonic/gin"

// APIResponse defines a standard response structure for all endpoints
// Success indicates whether the request was successful.
// Data holds the successful payload, while Error contains an error message when Success is false.
// Message can optionally provide additional context.
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Message string      `json:"message,omitempty"`
}

// RespondSuccess sends a success response with the given status, data, and message.
func RespondSuccess(c *gin.Context, status int, data interface{}, message string) {
	c.JSON(status, APIResponse{Success: true, Data: data, Message: message})
}

// RespondError sends an error response with the given status and error message.
func RespondError(c *gin.Context, status int, err string) {
	c.JSON(status, APIResponse{Success: false, Error: err})
}
