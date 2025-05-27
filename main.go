package main

import (
	"log"
	//"net/http"

	"github.com/gin-gonic/gin"
	"github.com/RavenSec10/Raven_Backend/db"
	"github.com/RavenSec10/Raven_Backend/internal/routes"
	"github.com/RavenSec10/Raven_Backend/internal/services"
	"github.com/RavenSec10/Raven_Backend/internal/handlers"


)

func main() {

	err := db.ConnectDB()
	if err != nil{
		log.Fatalf("Failed to connect to database: %v", err)
	}

	harService, err := services.NewHARService()
	if err != nil {
		log.Fatalf("Failed to initialize HAR service: %v", err)
	}
	harHandler := handlers.NewHARHandler(harService)
	harAPIHandler := handlers.NewHarAPIHandler()
	router := gin.Default()

	routes.SetupRoutes(router, harHandler, harAPIHandler)

	// Add a root route for testing
	//router.GET("/", func(c *gin.Context) {
	//	c.JSON(http.StatusOK, gin.H{"message": "Welcome to RAVEN API"})
	//})

	// Register the upload route
	//router.POST("/upload", harHandler.UploadHAR)
	
	log.Println("Server running on :8080")
	router.Run(":8080")
}