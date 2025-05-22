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

// Define the UserAPIData struct
type UserAPIData struct {
	ID              primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	APIEndpoint     string             `bson:"api_endpoint" json:"api_endpoint"`
	Method          string             `bson:"method" json:"method"`
	Headers         map[string]string  `bson:"headers" json:"headers"`
	RequestBody     string             `bson:"request_body,omitempty" json:"request_body"`
	ResponseBody    string             `bson:"response_body,omitempty" json:"response_body"`
	SensitiveFields []string           `bson:"sensitive_fields,omitempty" json:"sensitive_fields"`
	Timestamp       time.Time          `bson:"timestamp" json:"timestamp"`
	Source          string             `bson:"source" json:"source"`
	Url             string             `bson:"url" json:"url"`
}

type PaginatedResponse struct {
	Items []UserAPIData `json:"items"`
	Total int64         `json:"total"`
}

func getHarEntries(c *gin.Context) {
	
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

	collection := db.GetCollection("user_api_data")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	total, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		log.Printf("Failed to count documents: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve total count"})
		return
	}

	findOptions := options.Find().SetSkip(int64(skip)).SetLimit(int64(limit))

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

	response := PaginatedResponse{
		Items: apiData,
		Total: total,
	}

	c.JSON(http.StatusOK, response)
}

func getHarEntry(c *gin.Context) {
	idStr := c.Param("id")
	if idStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID parameter is required"})
		return
	}

	objectID, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
		return
	}

	filter := bson.M{"_id": objectID}
	collection := db.GetCollection("user_api_data")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var apiData UserAPIData
	err = collection.FindOne(ctx, filter).Decode(&apiData)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "API data not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"items": []UserAPIData{apiData}, "total": 1})
}

type HarAPIHandler struct{}

func (h *HarAPIHandler) SetupHarRoutes(router *gin.Engine) {
	router.GET("/api/har-entries", getHarEntries)
	router.GET("/api/har-entries/:id", getHarEntry)
}

func NewHarAPIHandler() *HarAPIHandler {
	return &HarAPIHandler{}
}