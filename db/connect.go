package db

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/bson"
)

type MongoInstance struct {
	Client *mongo.Client
	DB     *mongo.Database
}

// ConnectDB initializes the MongoDB connection
func ConnectDB() (MongoInstance, error) {
	// Load .env file
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: No .env file found. Using system environment variables.")
	}

	// Get DATABASE_URL from environment
	mongoURI := os.Getenv("DATABASE_URL")
	if mongoURI == "" {
		return MongoInstance{}, fmt.Errorf("DATABASE_URL is not set in the environment")
	}

	// Get DATABASE_NAME from environment
	dbName := os.Getenv("DATABASE_NAME")
	if dbName == "" {
		dbName = "raven_api_db" // Default DB name
		log.Printf("DATABASE_NAME not set, using default: %s", dbName)
	}

	// Set MongoDB client options
	clientOptions := options.Client().ApplyURI(mongoURI)

	// Connect to MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return MongoInstance{}, fmt.Errorf("MongoDB connection error: %w", err)
	}

	// Check the connection
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		if disconnectErr := client.Disconnect(context.Background()); disconnectErr != nil {
			log.Printf("Error during disconnect after failed ping: %v", disconnectErr)
		}
		return MongoInstance{}, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	// Select the database
	db := client.Database(dbName)
	log.Printf("Connected to MongoDB database: %s\n", dbName)

	mi := MongoInstance{
		Client: client,
		DB:     db,
	}
	// Create indexes (optional)
	err = mi.setupIndexes(ctx)
	if err != nil {
		log.Printf("Error setting up indexes: %v", err)
	}

	return mi, nil
}

// GetCollection returns a reference to a MongoDB collection
func (mi *MongoInstance) GetCollection(collectionName string) *mongo.Collection {
	return mi.DB.Collection(collectionName)
}

// setupIndexes creates necessary indexes
func (mi *MongoInstance) setupIndexes(ctx context.Context) error {
	collection := mi.GetCollection("user_api_data")
	indexModel := mongo.IndexModel{
		Keys: bson.D{ // Corrected: Use keyed fields
			{Key: "api_endpoint", Value: 1},
			{Key: "timestamp", Value: -1},
		}, // Index on APIEndpoint and Timestamp
		Options: nil,
	}
	_, err := collection.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		return fmt.Errorf("failed to create index: %w", err)
	}
	log.Println("Created index on api_endpoint and timestamp")
	return nil
}

func (mi *MongoInstance) CloseDB(ctx context.Context) {
	if mi.Client != nil {
		if err := mi.Client.Disconnect(ctx); err != nil {
			log.Printf("Error disconnecting from MongoDB: %v", err)
		} else {
			log.Println("Disconnected from MongoDB.")
		}
	}
}

func (mi *MongoInstance) InsertOne(ctx context.Context, collectionName string, data interface{}) error {
	collection := mi.GetCollection(collectionName)
	_, err := collection.InsertOne(ctx, data)
	if err != nil {
		return fmt.Errorf("failed to insert document into collection '%s': %w", collectionName, err)
	}
	return nil
}