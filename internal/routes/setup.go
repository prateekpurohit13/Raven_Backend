package routes

import (
	"github.com/gin-gonic/gin"
)

// InitializeServer sets up the Gin engine
func InitializeServer() *gin.Engine {
	router := gin.Default()
	return router
}
