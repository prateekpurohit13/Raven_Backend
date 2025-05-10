package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/RavenSec10/Raven_Backend/internal/handlers"
)

// SetupRoutes initializes all API routes
func SetupRoutes(router *gin.Engine, harHandler *handlers.HARHandler, harAPIHandler *handlers.HarAPIHandler) {
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Welcome to RAVEN API"})
	})
	router.POST("/upload-har", harHandler.UploadHAR) // call the function from upload.go
	harAPIHandler.SetupHarRoutes(router)
}
