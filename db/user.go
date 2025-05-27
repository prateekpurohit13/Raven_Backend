package db

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type PIIFinding struct {
	PIIType       string    `bson:"pii_type"`
	DetectedValue string    `bson:"detected_value"`
	FieldName     string    `bson:"field_name,omitempty"`
	Location      string    `bson:"location"`
	DetectionMode string    `bson:"detection_mode"`
	RiskLevel     string    `bson:"risk_level"`
	Category      string    `bson:"category"`
	Tags          []string  `bson:"tags"`
	Timestamp     time.Time `bson:"timestamp"`
}

type UserAPIData struct {
	ID              primitive.ObjectID `bson:"_id,omitempty"`
	APIEndpoint     string             `bson:"api_endpoint"`
	Method          string             `bson:"method"`
	Headers         map[string]string  `bson:"headers"`
	RequestBody     string             `bson:"request_body,omitempty"`
	ResponseBody    string             `bson:"response_body,omitempty"`
	SensitiveFields []string           `bson:"sensitive_fields,omitempty"`
	
	PIIFindings     []PIIFinding `bson:"pii_findings,omitempty"`
	PIICount        int          `bson:"pii_count,omitempty"`
	RiskScore       int          `bson:"risk_score,omitempty"`
	HighestRisk     string       `bson:"highest_risk,omitempty"`
	HasPII          bool         `bson:"has_pii,omitempty"`
	LastPIIAnalysis time.Time    `bson:"last_pii_analysis,omitempty"`
	
	Timestamp       time.Time          `bson:"timestamp"`
	Source          string             `bson:"source"`
	Url             string             `bson:"url"`
}

type PIIAnalysisReport struct {
	ID                    primitive.ObjectID `bson:"_id,omitempty"`
	ReportDate           time.Time          `bson:"report_date"`
	TotalAPIsAnalyzed    int                `bson:"total_apis_analyzed"`
	APIsWithPII          int                `bson:"apis_with_pii"`
	TotalPIIFindings     int                `bson:"total_pii_findings"`
	RiskLevelBreakdown   map[string]int     `bson:"risk_level_breakdown"`
	CategoryBreakdown    map[string]int     `bson:"category_breakdown"`
	DetectionModeBreakdown map[string]int   `bson:"detection_mode_breakdown"`
	TopRiskyEndpoints    []RiskyEndpoint    `bson:"top_risky_endpoints"`
	ComplianceStatus     string             `bson:"compliance_status"`
	CreatedAt            time.Time          `bson:"created_at"`
}

type RiskyEndpoint struct {
	APIEndpoint string `bson:"api_endpoint"`
	Method      string `bson:"method"`
	RiskScore   int    `bson:"risk_score"`
	PIICount    int    `bson:"pii_count"`
	HighestRisk string `bson:"highest_risk"`
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

func UpdateUserAPIDataWithPII(apiEndpoint, method string, findings []PIIFinding, riskScore int, highestRisk string) error {
	collection := GetCollection("user_api_data")
	
	filter := bson.M{
		"api_endpoint": apiEndpoint,
		"method":       method,
	}
	
	update := bson.M{
		"$set": bson.M{
			"pii_findings":      findings,
			"pii_count":         len(findings),
			"risk_score":        riskScore,
			"highest_risk":      highestRisk,
			"has_pii":           len(findings) > 0,
			"last_pii_analysis": time.Now(),
		},
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	result, err := collection.UpdateMany(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update API data with PII findings: %w", err)
	}
	
	log.Printf("Updated %d documents with PII analysis for %s %s", result.ModifiedCount, method, apiEndpoint)
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

func FindAPIDataWithPII() ([]UserAPIData, error) {
	collection := GetCollection("user_api_data")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	filter := bson.M{"has_pii": true}
	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to find API data with PII: %w", err)
	}
	defer cursor.Close(ctx)

	var apiData []UserAPIData
	if err := cursor.All(ctx, &apiData); err != nil {
		return nil, fmt.Errorf("failed to decode API data with PII: %w", err)
	}

	return apiData, nil
}

func FindAPIDataByRiskLevel(riskLevel string) ([]UserAPIData, error) {
	collection := GetCollection("user_api_data")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	filter := bson.M{"highest_risk": riskLevel}
	cursor, err := collection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to find API data by risk level: %w", err)
	}
	defer cursor.Close(ctx)

	var apiData []UserAPIData
	if err := cursor.All(ctx, &apiData); err != nil {
		return nil, fmt.Errorf("failed to decode API data by risk level: %w", err)
	}

	return apiData, nil
}

func SavePIIAnalysisReport(report PIIAnalysisReport) error {
	collection := GetCollection("pii_analysis_reports")
	
	if report.CreatedAt.IsZero() {
		report.CreatedAt = time.Now()
	}
	
	if report.ReportDate.IsZero() {
		report.ReportDate = time.Now()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := collection.InsertOne(ctx, report)
	if err != nil {
		return fmt.Errorf("failed to save PII analysis report: %w", err)
	}

	log.Printf("PII Analysis Report saved successfully for date: %s", report.ReportDate.Format("2006-01-02"))
	return nil
}

func FindLatestPIIAnalysisReport() (*PIIAnalysisReport, error) {
	collection := GetCollection("pii_analysis_reports")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	filter := bson.M{}
	opts := options.FindOne().SetSort(bson.D{bson.E{Key: "created_at", Value: -1}})
	
	var report PIIAnalysisReport
	err := collection.FindOne(ctx, filter, opts).Decode(&report)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to find latest PII analysis report: %w", err)
	}

	return &report, nil
}

func GetPIIComplianceStats() (map[string]interface{}, error) {
	collection := GetCollection("user_api_data")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pipeline := []bson.M{
		{
			"$group": bson.M{
				"_id": nil,
				"total_apis": bson.M{"$sum": 1},
				"apis_with_pii": bson.M{
					"$sum": bson.M{
						"$cond": bson.M{
							"if":   "$has_pii",
							"then": 1,
							"else": 0,
						},
					},
				},
				"critical_risk_apis": bson.M{
					"$sum": bson.M{
						"$cond": bson.M{
							"if":   bson.M{"$eq": []interface{}{"$highest_risk", "CRITICAL"}},
							"then": 1,
							"else": 0,
						},
					},
				},
				"high_risk_apis": bson.M{
					"$sum": bson.M{
						"$cond": bson.M{
							"if":   bson.M{"$eq": []interface{}{"$highest_risk", "HIGH"}},
							"then": 1,
							"else": 0,
						},
					},
				},
				"avg_risk_score": bson.M{"$avg": "$risk_score"},
				"total_pii_findings": bson.M{"$sum": "$pii_count"},
			},
		},
	}

	cursor, err := collection.Aggregate(ctx, pipeline)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate PII compliance stats: %w", err)
	}
	defer cursor.Close(ctx)

	var results []bson.M
	if err := cursor.All(ctx, &results); err != nil {
		return nil, fmt.Errorf("failed to decode PII compliance stats: %w", err)
	}

	if len(results) == 0 {
		return map[string]interface{}{
			"total_apis":           0,
			"apis_with_pii":        0,
			"critical_risk_apis":   0,
			"high_risk_apis":       0,
			"avg_risk_score":       0,
			"total_pii_findings":   0,
			"compliance_percentage": 100,
		}, nil
	}

	stats := results[0]
	totalAPIs := stats["total_apis"].(int32)
	apisWithPII := stats["apis_with_pii"].(int32)

	compliancePercentage := float64(100)
	if totalAPIs > 0 {
		compliancePercentage = float64(totalAPIs-apisWithPII) / float64(totalAPIs) * 100
	}

	stats["compliance_percentage"] = compliancePercentage
	return map[string]interface{}(stats), nil
}