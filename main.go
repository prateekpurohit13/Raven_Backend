package main

import (
	"fmt"
	"log"
	"github.com/gin-gonic/gin"
	"github.com/harshitnarang28/Raven_Backend/internal/routes"
)

func main() {
	port := "8080"
	router := gin.Default()

	// Routes
	routes.SetupRoutes(router)

	fmt.Println("RAVEN Backend running on port", port)
	log.Fatal(router.Run(":" + port))
}
