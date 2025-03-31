package db

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
 
)

// UserAPIData represents the extracted API metadata and SPII
type UserAPIData struct {
	ID              primitive.ObjectID `bson:"_id,omitempty"`   // Unique MongoDB ObjectID
	APIEndpoint     string             `bson:"api_endpoint"`   // API URL path
	Method         string             `bson:"method"`        // HTTP method (GET, POST, etc.)
	Headers        map[string]string  `bson:"headers"`       // Request headers
	RequestBody    map[string]any     `bson:"request_body"`  // Data sent in request
	ResponseBody   map[string]any     `bson:"response_body"` // Data received in response
	SensitiveFields []string           `bson:"sensitive_fields"` // Detected SPII fields
	Timestamp      time.Time          `bson:"timestamp"`     // Time of data extraction
	Source         string             `bson:"source"`        // HAR file reference
}

// SaveUserAPIData inserts API metadata into MongoDB
func SaveUserAPIData(data UserAPIData) error {
	collection := GetCollection("user_api_data") // Collection name

	data.Timestamp = time.Now() // Assign current timestamp
	_, err := collection.InsertOne(context.Background(), data)

	if err != nil {
		log.Println("Failed to insert API data:", err)
		return err
	}
	log.Println("API Data Inserted Successfully!")
	return nil
}
