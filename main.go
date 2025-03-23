package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/RavenSec10/Raven_Backend/internal/routes"
)

func main() {
	router := gin.Default()

	// Add a root route for testing
	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Welcome to RAVEN API"})
	})

	// Register the upload route
	router.POST("/upload", routes.UploadHAR)

	log.Println("Server running on :8080")
	router.Run(":8080")
}
