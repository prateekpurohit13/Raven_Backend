package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/RavenSec10/Raven_Backend/db"
	"github.com/segmentio/kafka-go"
)

// KafkaConsumerService holds the dependencies for the consumer.
type KafkaConsumerService struct {
	reader     *kafka.Reader
	piiService *PIIService
	mongo      db.MongoInstance
}

// RawNginxLog represents the structure of the JSON log coming from NGINX.
// Using a struct is safer than map[string]interface{} as it provides type safety.
type RawNginxLog struct {
	Timestamp            string  `json:"timestamp"`
	ClientIP             string  `json:"client_ip"`
	Method               string  `json:"method"`
	URI                  string  `json:"uri"`
	Protocol             string  `json:"protocol"`
	Status               int     `json:"status"`
	ResponseSize         int     `json:"response_size"`
	RequestBody          string  `json:"request_body"`
	ResponseBody         string  `json:"response_body"` // Assuming your NGINX config provides this
	UserAgent            string  `json:"user_agent"`
	Host                 string  `json:"host"`
	ContentType          string  `json:"content_type"`
	ResponseContentType  string  `json:"response_content_type"`
}


// NewKafkaConsumerService creates a new instance of the consumer service.
func NewKafkaConsumerService(brokerAddress string, topic string, groupID string, piiSvc *PIIService, mongoInstance db.MongoInstance) *KafkaConsumerService {
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: []string{brokerAddress},
		Topic:   topic,
		GroupID: groupID,
		// Start consuming from the latest message. Change to kafka.FirstOffset to process old messages.
		StartOffset: kafka.LastOffset, 
		MinBytes:    10e3, // 10KB
		MaxBytes:    10e6, // 10MB
		MaxWait:     2 * time.Second,
	})

	return &KafkaConsumerService{
		reader:     reader,
		piiService: piiSvc,
		mongo:      mongoInstance,
	}
}

// Start consumes messages from Kafka in a loop until the context is canceled.
func (s *KafkaConsumerService) Start(ctx context.Context) {
	log.Println("Kafka consumer service started. Waiting for messages...")
	defer s.reader.Close()

	for {
		// Use FetchMessage for more control over commits and context cancellation
		msg, err := s.reader.FetchMessage(ctx)
		if err != nil {
			// If context is canceled, the loop will break, which is expected for shutdown
			if ctx.Err() != nil {
				break
			}
			log.Printf("Error fetching Kafka message: %v", err)
			continue
		}

		// Process the message in a separate goroutine to allow concurrent processing if needed.
		// For now, we do it synchronously to keep it simple.
		s.processMessage(ctx, msg)
	}

	log.Println("Kafka consumer service stopped.")
}

// processMessage handles a single Kafka message.
func (s *KafkaConsumerService) processMessage(ctx context.Context, msg kafka.Message) {
	log.Printf("Received message from Kafka topic '%s', partition %d, offset %d\n", msg.Topic, msg.Partition, msg.Offset)

	// 1. Unmarshal the raw NGINX log
	var rawLog RawNginxLog
	if err := json.Unmarshal(msg.Value, &rawLog); err != nil {
		log.Printf("Error unmarshaling Kafka message: %v. Skipping message.", err)
		// Commit message even if it's invalid, to avoid reprocessing it forever
		s.commitMessage(ctx, msg)
		return
	}

	// 2. Map the raw log to the db.UserAPIData struct for PII analysis
	apiData := s.mapRawLogToUserAPIData(rawLog)

	// 3. Analyze for PII using the existing PIIService
	piiAnalysis := s.piiService.AnalyzePIIInAPIData(apiData)

	// 4. Enrich the apiData struct with the analysis results
	s.enrichUserAPIData(&apiData, piiAnalysis)
	
	if apiData.HasPII {
		log.Printf("PII DETECTED in %s %s. Risk: %s, Findings: %d", apiData.Method, apiData.APIEndpoint, apiData.HighestRisk, apiData.PIICount)
	}

	// 5. Save the enriched data to MongoDB
	if err := s.mongo.SaveUserAPIData(apiData); err != nil {
		log.Printf("Error saving API data to MongoDB: %v", err)
		// Do NOT commit the message if saving fails, so we can retry later
		return
	}

	// 6. Commit the message to Kafka to mark it as processed
	s.commitMessage(ctx, msg)
}

// mapRawLogToUserAPIData converts the incoming NGINX log format to the database model.
func (s *KafkaConsumerService) mapRawLogToUserAPIData(rawLog RawNginxLog) db.UserAPIData {
	// Parse the timestamp from the NGINX log
	timestamp, err := time.Parse(time.RFC3339, rawLog.Timestamp)
	if err != nil {
		log.Printf("Warning: Could not parse timestamp '%s'. Using current time. Error: %v", rawLog.Timestamp, err)
		timestamp = time.Now()
	}

	// Construct the full URL
	// Note: NGINX log doesn't provide the scheme (http/https) directly, so we assume http for now.
	fullURL := fmt.Sprintf("http://%s%s", rawLog.Host, rawLog.URI)
	
	// API Endpoint is often just the path, which is rawLog.URI
	apiEndpoint := rawLog.URI
	// You might want to remove query params for a cleaner endpoint name
	if idx := strings.Index(apiEndpoint, "?"); idx != -1 {
		apiEndpoint = apiEndpoint[:idx]
	}

	return db.UserAPIData{
		APIEndpoint:  apiEndpoint,
		Method:       rawLog.Method,
		URL:          fullURL,
		Headers:      map[string]string{"User-Agent": rawLog.UserAgent, "Content-Type": rawLog.ContentType}, // NGINX log format has limited headers, adapt as needed
		RequestBody:  rawLog.RequestBody,
		ResponseBody: rawLog.ResponseBody,
		Source:       "Kafka Stream",
		Timestamp:    timestamp,
	}
}

// enrichUserAPIData populates the PII summary fields in the UserAPIData struct.
func (s *KafkaConsumerService) enrichUserAPIData(apiData *db.UserAPIData, piiAnalysis PIIAnalysisResult) {
	apiData.HasPII = piiAnalysis.TotalCount > 0
	apiData.PIICount = piiAnalysis.TotalCount
	apiData.RiskScore = piiAnalysis.RiskScore
	apiData.HighestRisk = piiAnalysis.HighestRisk

	// Convert PII findings from the service model to the DB model
	var dbFindings []db.PIIFinding
	var sensitiveFieldsMap = make(map[string]bool)
	
	for _, finding := range piiAnalysis.Findings {
		dbFindings = append(dbFindings, db.PIIFinding{
			PIIType:       finding.PIIType,
			DetectedValue: finding.DetectedValue,
			FieldName:     finding.FieldName,
			Location:      finding.Location,
			DetectionMode: finding.DetectionMode,
			RiskLevel:     finding.RiskLevel,
			Category:      finding.Category,
			Tags:          finding.Tags,
			Timestamp:     finding.Timestamp,
		})
		// Populate sensitive fields for quick reference
		if !sensitiveFieldsMap[finding.PIIType] {
			apiData.SensitiveFields = append(apiData.SensitiveFields, finding.PIIType)
			sensitiveFieldsMap[finding.PIIType] = true
		}
	}
	apiData.PIIFindings = dbFindings
}

// commitMessage commits the offset for a given message.
func (s *KafkaConsumerService) commitMessage(ctx context.Context, msg kafka.Message) {
	if err := s.reader.CommitMessages(ctx, msg); err != nil {
		log.Printf("Failed to commit Kafka message offset %d: %v", msg.Offset, err)
	}
}