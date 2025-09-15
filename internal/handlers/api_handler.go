package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"time"
	"github.com/gin-gonic/gin"
	"github.com/RavenSec10/Raven_Backend/db"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type PIIFinding struct {
	PIIType       string    `bson:"pii_type" json:"pii_type"`
	DetectedValue string    `bson:"detected_value" json:"detected_value"`
	FieldName     string    `bson:"field_name,omitempty" json:"field_name,omitempty"`
	Location      string    `bson:"location" json:"location"`
	DetectionMode string    `bson:"detection_mode" json:"detection_mode"`
	RiskLevel     string    `bson:"risk_level" json:"risk_level"`
	Category      string    `bson:"category" json:"category"`
	Tags          []string  `bson:"tags" json:"tags"`
	Timestamp     time.Time `bson:"timestamp" json:"timestamp"`
}

type UserAPIData struct {
	ID              primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	APIEndpoint     string             `bson:"api_endpoint" json:"api_endpoint"`
	Method          string             `bson:"method" json:"method"`
	RequestHeaders  map[string]string  `bson:"request_headers,omitempty" json:"request_headers,omitempty"`
	ResponseHeaders map[string]string  `bson:"response_headers,omitempty" json:"response_headers,omitempty"`
	RequestBody     interface{}        `bson:"request_body,omitempty" json:"request_body,omitempty"`
	ResponseBody    interface{}        `bson:"response_body,omitempty" json:"response_body,omitempty"`
	SensitiveFields []string           `bson:"sensitive_fields,omitempty" json:"sensitive_fields,omitempty"`
	HasPII          bool               `bson:"has_pii" json:"has_pii"`
	PIICount        int                `bson:"pii_count" json:"pii_count"`
	RiskScore       int                `bson:"risk_score" json:"risk_score"`
	HighestRisk     string             `bson:"highest_risk,omitempty" json:"highest_risk,omitempty"`
	PIIFindings     []PIIFinding       `bson:"pii_findings,omitempty" json:"pii_findings,omitempty"`
	Timestamp       time.Time          `bson:"timestamp" json:"timestamp"`
	Source          string             `bson:"source" json:"source"`
	URL             string             `bson:"url" json:"url"`
	LastPIIAnalysis time.Time          `bson:"last_pii_analysis,omitempty" json:"last_pii_analysis,omitempty"`
}

type PaginatedResponse struct {
	Items []UserAPIData `json:"items"`
	Total int64         `json:"total"`
}

type APIHandler struct {
	mongo db.MongoInstance
}

func NewAPIHandler(mongoInstance db.MongoInstance) *APIHandler {
	return &APIHandler{
		mongo: mongoInstance,
	}
}

func (h *APIHandler) getAPILogs(c *gin.Context) {
	pageStr := c.DefaultQuery("page", "1")
	limitStr := c.DefaultQuery("limit", "10")
	searchQuery := c.Query("query")
	searchHostname := c.Query("hostname")
	hasPiiStr := c.Query("has_pii")
	riskLevel := c.Query("risk_level")

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
	orConditions := []bson.M{}

	if searchQuery != "" {
		orConditions = append(orConditions,
			bson.M{"api_endpoint": bson.M{"$regex": primitive.Regex{Pattern: searchQuery, Options: "i"}}},
			bson.M{"url": bson.M{"$regex": primitive.Regex{Pattern: searchQuery, Options: "i"}}},
			bson.M{"method": bson.M{"$regex": primitive.Regex{Pattern: searchQuery, Options: "i"}}},
		)
	}

	if searchHostname != "" {
		hostnameRegexPattern := fmt.Sprintf("://[^/]*%s[^/]*($|/)", regexp.QuoteMeta(searchHostname))
		orConditions = append(orConditions, bson.M{"url": bson.M{"$regex": primitive.Regex{Pattern: hostnameRegexPattern, Options: "i"}}})
	}

	if len(orConditions) > 0 {
		filter["$or"] = orConditions
	}

	if hasPiiStr != "" {
		hasPiiBool, parseErr := strconv.ParseBool(hasPiiStr)
		if parseErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid value for has_pii. Must be 'true' or 'false'."})
			return
		}
		filter["has_pii"] = hasPiiBool
	}

	if riskLevel != "" {
		filter["highest_risk"] = riskLevel
	}

	collection := h.mongo.GetCollection("user_api_data")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	total, err := collection.CountDocuments(ctx, filter)
	if err != nil {
		log.Printf("Failed to count documents: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve total count"})
		return
	}
	findOptions := options.Find().SetSkip(int64(skip)).SetLimit(int64(limit)).SetSort(bson.D{{Key: "timestamp", Value: -1}})
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

func (h *APIHandler) getAPILog(c *gin.Context) {
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
	collection := h.mongo.GetCollection("user_api_data")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var apiData UserAPIData
	err = collection.FindOne(ctx, filter).Decode(&apiData)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "API data not found"})
		return
	}

	c.JSON(http.StatusOK, apiData)
}

func (h *APIHandler) SetupAPIRoutes(router *gin.Engine) {
	router.GET("/api/logs", h.getAPILogs)
	router.GET("/api/logs/:id", h.getAPILog)
}