package routes

import (
	"github.com/gin-gonic/gin"
)

// SetupRoutes initializes all API routes
func SetupRoutes(router *gin.Engine) {
	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Welcome to RAVEN API"})
	})
	router.POST("/upload-har", UploadHAR) // This will call the function from upload.go
}
