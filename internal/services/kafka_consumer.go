package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/RavenSec10/Raven_Backend/db"
	"github.com/segmentio/kafka-go"
)

type KafkaConsumerService struct {
	reader     *kafka.Reader
	piiService *PIIService
	mongo      db.MongoInstance
}

type KafkaLogMessage struct {
	TimestampMetadata time.Time `json:"@timestamp"`
	Metadata          struct {
		Beat    string `json:"beat"`
		Type    string `json:"type"`
		Version string `json:"version"`
	} `json:"@metadata"`
	Environment         string            `json:"environment"`
	StatusText          string            `json:"status"`
	UserAgent           string            `json:"user_agent"`
	ResponseHeaders     map[string]string `json:"responseHeaders"`
	RequestBodySize     int               `json:"request_body_size"`
	IsGzipCompressed    bool              `json:"is_gzip_compressed"`
	Service             string            `json:"service"`
	HasRequestBody      bool              `json:"has_request_body"`
	ResponsePayload     interface{}       `json:"responsePayload"`
	HasResponseBody     bool              `json:"has_response_body"`
	LogType             string            `json:"log_type"`
	RequestPayload      interface{}       `json:"requestPayload"`
	RequestTime         string            `json:"request_time"`
	Method              string            `json:"method"`
	NjsTime             string            `json:"time"`
	Referer             string            `json:"referer"`
	ResponseSize        string            `json:"response_size"`
	ContainerName       string            `json:"container_name"`
	RequestHeaders      map[string]string `json:"requestHeaders"`
	Source              string            `json:"source"`
	LogSource           string            `json:"log_source"`
	ContentType         string            `json:"content_type"`
	ResponseContentType string            `json:"response_content_type"`
	IP                  string            `json:"ip"`
	RequestSize         string            `json:"request_size"`
	Type                string            `json:"type"`
	StatusCode          string            `json:"statusCode"`
	UpstreamTime        string            `json:"upstream_time"`
	Path                string            `json:"path"`
	ResponseBodySize    int               `json:"response_body_size"`
	Host                string            `json:"host"`
}
// creates a new instance of the consumer service.
func NewKafkaConsumerService(brokerAddress string, topic string, groupID string, piiSvc *PIIService, mongoInstance db.MongoInstance) *KafkaConsumerService {
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: []string{brokerAddress},
		Topic:   topic,
		GroupID: groupID,
		StartOffset: kafka.LastOffset, 
		MinBytes:    10e3,
		MaxBytes:    10e6,
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
		msg, err := s.reader.FetchMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			log.Printf("Error fetching Kafka message: %v", err)
			continue
		}
		s.processMessage(ctx, msg)
	}

	log.Println("Kafka consumer service stopped.")
}

// processMessage handles a single Kafka message.
func (s *KafkaConsumerService) processMessage(ctx context.Context, msg kafka.Message) {
	log.Printf("Received message from Kafka topic '%s', partition %d, offset %d\n", msg.Topic, msg.Partition, msg.Offset)

	var rawKafkaLog KafkaLogMessage
	if err := json.Unmarshal(msg.Value, &rawKafkaLog); err != nil {
		log.Printf("Error unmarshaling Kafka message into KafkaLogMessage: %v. Message: %s. Skipping message.", err, string(msg.Value))
		s.commitMessage(ctx, msg)
		return
	}

	apiData, err := s.mapKafkaLogToUserAPIData(rawKafkaLog)
	if err != nil {
		log.Printf("Error mapping Kafka log to UserAPIData: %v. Skipping message.", err)
		s.commitMessage(ctx, msg)
		return
	}

	piiAnalysis := s.piiService.AnalyzePIIInAPIData(apiData)
	s.enrichUserAPIData(&apiData, piiAnalysis)
	
	if apiData.HasPII {
		log.Printf("PII DETECTED in %s %s. Risk: %s, Findings: %d", apiData.Method, apiData.APIEndpoint, apiData.HighestRisk, apiData.PIICount)
	}
	if err := s.mongo.SaveUserAPIData(apiData); err != nil {
		log.Printf("Error saving API data to MongoDB: %v", err)
		return
	}
	s.commitMessage(ctx, msg)
}

func (s *KafkaConsumerService) mapKafkaLogToUserAPIData(rawLog KafkaLogMessage) (db.UserAPIData, error) {
	njsTimeSeconds, err := parseNjsTime(rawLog.NjsTime)
	parsedTimestamp := rawLog.TimestampMetadata
	if err == nil {
		parsedTimestamp = njsTimeSeconds
	} else {
		log.Printf("Warning: Could not parse NJS timestamp '%s'. Using Filebeat's timestamp. Error: %v", rawLog.NjsTime, err)
	}
	scheme := "http"
	host := rawLog.Host
	if strings.HasPrefix(rawLog.Host, "https://") {
		scheme = "https"
		host = strings.TrimPrefix(rawLog.Host, "https://")
	} else if strings.HasPrefix(rawLog.Host, "http://") {
		scheme = "http"
		host = strings.TrimPrefix(rawLog.Host, "http://")
	}
	
	fullURL := fmt.Sprintf("%s://%s%s", scheme, host, rawLog.Path)
	apiEndpoint := rawLog.Path
	if idx := strings.Index(apiEndpoint, "?"); idx != -1 {
		apiEndpoint = apiEndpoint[:idx]
	}

	return db.UserAPIData{
		APIEndpoint:     apiEndpoint,
		Method:          rawLog.Method,
		URL:             fullURL,
		RequestHeaders:  rawLog.RequestHeaders,
		ResponseHeaders: rawLog.ResponseHeaders,
		RequestBody:     rawLog.RequestPayload,
		ResponseBody:    rawLog.ResponsePayload,
		Source:          rawLog.Source,
		Timestamp:       parsedTimestamp,
	}, nil
}

func parseNjsTime(njsTimeString string) (time.Time, error) {
	seconds, err := strconv.ParseInt(njsTimeString, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse NJS time string '%s' as integer seconds: %w", njsTimeString, err)
	}
	return time.Unix(seconds, 0), nil
}


// enrichUserAPIData populates the PII summary fields in the UserAPIData struct.
func (s *KafkaConsumerService) enrichUserAPIData(apiData *db.UserAPIData, piiAnalysis PIIAnalysisResult) {
	apiData.HasPII = piiAnalysis.TotalCount > 0
	apiData.PIICount = piiAnalysis.TotalCount
	apiData.RiskScore = piiAnalysis.RiskScore
	apiData.HighestRisk = piiAnalysis.HighestRisk

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
		if !sensitiveFieldsMap[finding.PIIType] {
			apiData.SensitiveFields = append(apiData.SensitiveFields, finding.PIIType)
			sensitiveFieldsMap[finding.PIIType] = true
		}
	}
	apiData.PIIFindings = dbFindings
}

func (s *KafkaConsumerService) commitMessage(ctx context.Context, msg kafka.Message) {
	if err := s.reader.CommitMessages(ctx, msg); err != nil {
		log.Printf("Failed to commit Kafka message offset %d: %v", msg.Offset, err)
	}
}