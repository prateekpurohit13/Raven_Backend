package db

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type UserAPIData struct {
	ID              primitive.ObjectID `bson:"_id,omitempty"`
	APIEndpoint     string             `bson:"api_endpoint"`
	Method          string             `bson:"method"`
	Headers         map[string]string  `bson:"headers"`
	RequestBody     string             `bson:"request_body,omitempty"`
	ResponseBody    string             `bson:"response_body,omitempty"`
	SensitiveFields []string           `bson:"sensitive_fields,omitempty"`
	Timestamp       time.Time          `bson:"timestamp"`
	Source          string             `bson:"source"`               
}


func SaveUserAPIData(data UserAPIData) error {
	collection := GetCollection("user_api_data")
	if data.Timestamp.IsZero() {
		log.Println("Warning: UserAPIData timestamp is zero, setting to current time.")
		data.Timestamp = time.Now()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := collection.InsertOne(ctx, data)
	if err != nil {
		log.Printf("Failed to insert API data for endpoint %s (%s): %v\n", data.APIEndpoint, data.Method, err)
		return fmt.Errorf("failed to insert API data: %w", err)
	}

	log.Printf("API Data Inserted Successfully for %s (%s)", data.APIEndpoint, data.Method)
	return nil
}

func FindAllAPIData() ([]UserAPIData, error) {
	collection := GetCollection("user_api_data")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cursor, err := collection.Find(ctx, primitive.D{})
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