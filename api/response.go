package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Defines a standard response structure for all endpoints
type APIResponse[T any] struct {
	Status int		 `json:"status"`
	Message *string `json:"message,omitempty"`
	Data    *T      `json:"data,omitempty"`
	Error   *string `json:"error,omitempty"`
}

func StringPtr(s string) *string { return &s }

func SuccessResponse[T any](c *gin.Context, data *T, message *string) {
	status := http.StatusOK
	c.JSON(status, APIResponse[T]{
		Status:  status,
		Message: message,
		Data:    data,
		Error:   nil,
	})
}

func ErrResponse[T any](c *gin.Context, status int, errMsg string) {
	c.JSON(status, APIResponse[T]{
		Status:  status,
		Message: nil,
		Data:    nil,
		Error:   StringPtr(errMsg),
	})
}