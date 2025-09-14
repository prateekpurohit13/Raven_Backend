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

type HarAPIHandler struct {
	DB db.MongoInstance
}

func NewHarAPIHandler(mongoInstance db.MongoInstance) *HarAPIHandler {
	return &HarAPIHandler{
		DB: mongoInstance,
	}
}

type PaginatedResponse struct {
	Items []db.UserAPIData `json:"items"`
	Total int64            `json:"total"`
}

func (h *HarAPIHandler) getHarEntries(c *gin.Context) {
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

	filter := bson.M{}
	if searchQuery != "" {
		filter["api_endpoint"] = bson.M{"$regex": primitive.Regex{Pattern: searchQuery, Options: "i"}}
	}

	collection := h.DB.GetCollection("user_api_data")
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

	var apiData []db.UserAPIData
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

func (h *HarAPIHandler) getHarEntry(c *gin.Context) {
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
	collection := h.DB.GetCollection("user_api_data")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var apiData db.UserAPIData
	err = collection.FindOne(ctx, filter).Decode(&apiData)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "API data not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"items": []db.UserAPIData{apiData}, "total": 1})
}

func (h *HarAPIHandler) SetupHarRoutes(router *gin.Engine) {
	apiGroup := router.Group("/api")
	{
		apiGroup.GET("/har-entries", h.getHarEntries)
		apiGroup.GET("/har-entries/:id", h.getHarEntry)
	}
}