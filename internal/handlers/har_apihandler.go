package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/RavenSec10/Raven_Backend/db"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type UserAPIData struct {
	ID              primitive.ObjectID `bson:"_id,omitempty" json:"id,omitempty"`
	APIEndpoint     string             `bson:"api_endpoint" json:"api_endpoint"`
	Method          string             `bson:"method" json:"method"`
	Headers         map[string]string  `bson:"headers" json:"headers"`
	RequestBody     string             `bson:"request_body,omitempty" json:"request_body,omitempty"`
	ResponseBody    string             `bson:"response_body,omitempty" json:"response_body,omitempty"`
	SensitiveFields []string           `bson:"sensitive_fields,omitempty" json:"sensitive_fields,omitempty"`
	Timestamp       time.Time          `bson:"timestamp" json:"timestamp"`
	Source          string             `bson:"source" json:"source"`
}

// getHarEntries retrieves all UserAPIData entries from MongoDB
func getHarEntries(c *gin.Context) {
	apiData, err := db.FindAllAPIData()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to retrieve API data: %s", err)})
		return
	}

	c.JSON(http.StatusOK, apiData)
}

// getHarEntry retrieves a single UserAPIData entry by ID from MongoDB
func getHarEntry(c *gin.Context) {
	idStr := c.Param("id") // Get the ID from the URL path
	if idStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID parameter is required"})
		return
	}

	// Convert the ID string to a MongoDB ObjectID
	objectID, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
		return
	}

	// Prepare the filter to find the document by ID
	filter := bson.M{"_id": objectID}

	// Get the collection from the database
	collection := db.GetCollection("user_api_data")

	// Context for the database operation
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Find the document
	var apiData UserAPIData
	err = collection.FindOne(ctx, filter).Decode(&apiData)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "API data not found"})
		return
	}

	// Return the API data in the response
	c.JSON(http.StatusOK, apiData)
}

//HARHandler struct to inject har api calls
type HarAPIHandler struct {}

//SetupHarRoutes to inject har api calls
func (h *HarAPIHandler) SetupHarRoutes(router *gin.Engine){
		router.GET("/api/har-entries", getHarEntries)
		router.GET("/api/har-entries/:id", getHarEntry)
}

func NewHarAPIHandler() *HarAPIHandler {
	return &HarAPIHandler{}
}