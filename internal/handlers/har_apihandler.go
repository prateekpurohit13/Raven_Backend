package handlers

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/RavenSec10/Raven_Backend/db"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Define the UserAPIData struct (copied from db/user.go)
type UserAPIData struct {
	ID              primitive.ObjectID `bson:"_id,omitempty" json:"id"` //Add json tag for id
	APIEndpoint     string             `bson:"api_endpoint" json:"api_endpoint"`
	Method          string             `bson:"method" json:"method"`
	Headers         map[string]string  `bson:"headers" json:"headers"`
	RequestBody     string             `bson:"request_body,omitempty" json:"request_body"`
	ResponseBody    string             `bson:"response_body,omitempty" json:"response_body"`
	SensitiveFields []string           `bson:"sensitive_fields,omitempty" json:"sensitive_fields"`
	Timestamp       time.Time          `bson:"timestamp" json:"timestamp"`
	Source          string             `bson:"source" json:"source"`
}

type PaginatedResponse struct {
	Items []UserAPIData `json:"items"`
	Total int64         `json:"total"`
}

// getHarEntries retrieves all UserAPIData entries from MongoDB
func getHarEntries(c *gin.Context) {
	// Pagination parameters
	pageStr := c.DefaultQuery("page", "1")
	limitStr := c.DefaultQuery("limit", "10")
	searchQuery := c.Query("query")

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid page number"})
		return
	}

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 || limit > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid limit"})
		return
	}

	skip := (page - 1) * limit

	// Build the filter based on the search query
	filter := bson.M{}
	if searchQuery != "" {
		filter["api_endpoint"] = bson.M{"$regex": primitive.Regex{Pattern: searchQuery, Options: "i"}}
	}

	// Count total items
	collection := db.GetCollection("user_api_data")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	total, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		log.Printf("Failed to count documents: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve total count"})
		return
	}

	// Pagination options
	findOptions := options.Find().SetSkip(int64(skip)).SetLimit(int64(limit))

	// Retrieve paginated items
	cursor, err := collection.Find(ctx, filter, findOptions)
	if err != nil {
		log.Printf("Failed to find API data: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve API data"})
		return
	}
	defer cursor.Close(ctx)

	var apiData []UserAPIData
	if err := cursor.All(ctx, &apiData); err != nil {
		log.Printf("Failed to decode API data: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode API data"})
		return
	}

	// Construct paginated response
	response := PaginatedResponse{
		Items: apiData,
		Total: total,
	}

	c.JSON(http.StatusOK, response)
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
	c.JSON(http.StatusOK, gin.H{"items": []UserAPIData{apiData}, "total": 1})
}

//HARHandler struct to inject har api calls
type HarAPIHandler struct{}

//SetupHarRoutes to inject har api calls
func (h *HarAPIHandler) SetupHarRoutes(router *gin.Engine) {
	router.GET("/api/har-entries", getHarEntries)
	router.GET("/api/har-entries/:id", getHarEntry)
}

func NewHarAPIHandler() *HarAPIHandler {
	return &HarAPIHandler{}
}