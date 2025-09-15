package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/gin-contrib/cors"
	"github.com/RavenSec10/Raven_Backend/db"
	"github.com/RavenSec10/Raven_Backend/internal/handlers"
)

func SetupRoutes(router *gin.Engine, mongoInstance db.MongoInstance) {
	router.Use(cors.Default())

	router.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Welcome to the RAVEN API"})
	})
	apiHandler := handlers.NewAPIHandler(mongoInstance)
	apiHandler.SetupAPIRoutes(router)
}