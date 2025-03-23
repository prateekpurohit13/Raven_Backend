package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// SetupRoutes initializes API routes
func SetupRoutes(router *gin.Engine) {
	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "RAVEN API is running!"})
	})

	router.POST("/upload-har", UploadHAR)
}

// UploadHAR - Temporary placeholder
func UploadHAR(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "HAR file upload endpoint"})
}
