// db/user.go
package db

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// UserAPIData represents the extracted API metadata
type UserAPIData struct {
	ID              primitive.ObjectID         `bson:"_id,omitempty"`   // Unique MongoDB ObjectID
	APIEndpoint     string                   `bson:"api_endpoint"`   // API URL path
	Method          string                   `bson:"method"`        // HTTP method (GET, POST, etc.)
	Headers         map[string]string          `bson:"headers"`       // Request headers
	RequestBody     map[string]interface{}     `bson:"request_body"`  // Data sent in request
	ResponseBody    map[string]interface{}    `bson:"response_body"` // Data received in response
	SensitiveFields []string                 `bson:"sensitive_fields"` // Detected SPII fields
	Timestamp       time.Time                `bson:"timestamp"`     // Time of data extraction
	Source          string                   `bson:"source"`        // HAR file reference
}

// SaveUserAPIData inserts API metadata into MongoDB
func SaveUserAPIData(data UserAPIData) error {
	collection := GetCollection("user_api_data") // Collection name

	data.Timestamp = time.Now() // Assign current timestamp
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // Timeout context
	defer cancel()

	_, err := collection.InsertOne(ctx, data)
	if err != nil {
		return fmt.Errorf("failed to insert API data: %w", err)
	}
	log.Println("API Data Inserted Successfully!")
	return nil
}

// FindAllAPIData retrieves all API data from MongoDB (example)
func FindAllAPIData() ([]UserAPIData, error) {
	collection := GetCollection("user_api_data")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := collection.Find(ctx, primitive.D{}) // Empty filter to get all documents
	if err != nil {
		return nil, fmt.Errorf("failed to find API data: %w", err)
	}
	defer cursor.Close(ctx)

	var apiData []UserAPIData
	if err := cursor.All(ctx, &apiData); err != nil {
		return nil, fmt.Errorf("failed to decode API data: %w", err)
	}

	return apiData, nil
}