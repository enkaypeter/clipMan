package controllers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"clipMan/config"
	"clipMan/routes"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func setupRouter() *gin.Engine {
	if config.AppConfig == nil {
		config.AppConfig = &config.Config{}
	}
	config.AppConfig.JWTSecret = "test_secret"
	gin.SetMode(gin.TestMode)
	r := gin.New()
	routes.SetupUserRoutes(r)
	return r
}

func TestLoginGoogle(t *testing.T) {
	r := setupRouter()
	payload := []byte(`{"token":"valid_google_token"}`)
	req, _ := http.NewRequest(http.MethodPost, "/login/google", bytes.NewBuffer(payload))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	require.True(t, resp["success"].(bool))
	data := resp["data"].(map[string]interface{})
	require.NotEmpty(t, data["token"])
}

func TestLoginApple(t *testing.T) {
	r := setupRouter()
	payload := []byte(`{"token":"valid_apple_token"}`)
	req, _ := http.NewRequest(http.MethodPost, "/login/apple", bytes.NewBuffer(payload))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	require.True(t, resp["success"].(bool))
	data := resp["data"].(map[string]interface{})
	require.NotEmpty(t, data["token"])
}
