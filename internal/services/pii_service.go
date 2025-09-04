package services

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/RavenSec10/Raven_Backend/db"
)

type PIIDetectionResult struct {
	PIIType       string    `json:"pii_type"`
	DetectedValue string    `json:"detected_value"`
	FieldName     string    `json:"field_name,omitempty"`
	Location      string    `json:"location"`
	DetectionMode string    `json:"detection_mode"`
	RiskLevel     string    `json:"risk_level"`
	Category      string    `json:"category"`
	Tags          []string  `json:"tags"`
	Timestamp     time.Time `json:"timestamp"`
}

type PIIAnalysisResult struct {
	APIEndpoint  string               `json:"api_endpoint"`
	Method       string               `json:"method"`
	URL          string               `json:"url"`
	Findings     []PIIDetectionResult `json:"findings"`
	TotalCount   int                  `json:"total_count"`
	RiskScore    int                  `json:"risk_score"`
	HighestRisk  string               `json:"highest_risk"`
	Timestamp    time.Time            `json:"timestamp"`
}

type PIIPattern struct {
	FieldNames    []string `json:"fieldNames,omitempty"`
	ValuePattern  string   `json:"valuePattern,omitempty"`
	RegexPattern  string   `json:"regexPattern,omitempty"`
	Name          string   `json:"name,omitempty"`
	RiskLevel     string   `json:"riskLevel"`
	Category      string   `json:"category"`
	Tags          []string `json:"tags"`
	ApplyTo       string   `json:"applyTo,omitempty"`
}

type PIIConfig struct {
	DetectionModes struct {
		FieldBased struct {
			Description string                `json:"description"`
			Patterns    map[string]PIIPattern `json:"patterns"`
		} `json:"field_based"`
		ValueOnly struct {
			Description string                `json:"description"`
			Patterns    map[string]PIIPattern `json:"patterns"`
		} `json:"value_only"`
		KeywordBased struct {
			Description string                `json:"description"`
			Patterns    map[string]PIIPattern `json:"patterns"`
		} `json:"keyword_based"`
	} `json:"detection_modes"`
	RiskLevels map[string]int `json:"risk_levels"`
	Categories []string       `json:"categories"`
}

type PIIService struct {
	db             db.MongoInstance
	config         PIIConfig
	compiledRegex  map[string]*regexp.Regexp
	fieldRegex     map[string]*regexp.Regexp
	keywordRegex   map[string]*regexp.Regexp
}

func NewPIIService(mongoInstance db.MongoInstance) (*PIIService, error) {
	service := &PIIService{
		db:            mongoInstance,
		compiledRegex: make(map[string]*regexp.Regexp),
		fieldRegex:    make(map[string]*regexp.Regexp),
		keywordRegex:  make(map[string]*regexp.Regexp),
	}
	if err := service.loadPIIConfig(); err != nil {
		return nil, fmt.Errorf("failed to load PII config: %w", err)
	}
	if err := service.compileRegexPatterns(); err != nil {
		return nil, fmt.Errorf("failed to compile regex patterns: %w", err)
	}
	return service, nil
}

func (s *PIIService) loadPIIConfig() error {
	configPath := filepath.Join("config", "regexpii.json")
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read PII config file: %w", err)
	}
	if err := json.Unmarshal(data, &s.config); err != nil {
		return fmt.Errorf("failed to parse PII config JSON: %w", err)
	}
	log.Printf("Loaded PII config with %d field-based, %d value-only, and %d keyword-based patterns",
		len(s.config.DetectionModes.FieldBased.Patterns),
		len(s.config.DetectionModes.ValueOnly.Patterns),
		len(s.config.DetectionModes.KeywordBased.Patterns))
	return nil
}

func (s *PIIService) compileRegexPatterns() error {
	for name, pattern := range s.config.DetectionModes.FieldBased.Patterns {
		if pattern.ValuePattern != "" {
			regex, err := regexp.Compile(pattern.ValuePattern)
			if err != nil {
				log.Printf("Warning: Failed to compile field-based regex for %s: %v", name, err)
				continue
			}
			s.compiledRegex[fmt.Sprintf("field_%s", name)] = regex
		}
	}
	for name, pattern := range s.config.DetectionModes.ValueOnly.Patterns {
		if pattern.RegexPattern != "" {
			regex, err := regexp.Compile(pattern.RegexPattern)
			if err != nil {
				log.Printf("Warning: Failed to compile value-only regex for %s: %v", name, err)
				continue
			}
			s.compiledRegex[fmt.Sprintf("value_%s", name)] = regex
		}
	}
	for name, pattern := range s.config.DetectionModes.KeywordBased.Patterns {
		if pattern.RegexPattern != "" {
			regex, err := regexp.Compile(pattern.RegexPattern)
			if err != nil {
				log.Printf("Warning: Failed to compile keyword-based regex for %s: %v", name, err)
				continue
			}
			s.keywordRegex[name] = regex
		}
	}
	log.Printf("Compiled %d regex patterns successfully", len(s.compiledRegex)+len(s.keywordRegex))
	return nil
}

func (s *PIIService) AnalyzePIIInAPIData(apiData db.UserAPIData) PIIAnalysisResult {
	result := PIIAnalysisResult{
		APIEndpoint: apiData.APIEndpoint,
		Method:      apiData.Method,
		URL:         apiData.URL,
		Findings:    []PIIDetectionResult{},
		Timestamp:   time.Now(),
	}
	s.analyzeRequestHeaders(apiData.Headers, &result)
	s.analyzeRequestBody(apiData.RequestBody, &result)
	s.analyzeResponseBody(apiData.ResponseBody, &result)
	s.analyzeURL(apiData.URL, &result)
	result.TotalCount = len(result.Findings)
	result.RiskScore, result.HighestRisk = s.calculateRiskMetrics(result.Findings)
	return result
}

func (s *PIIService) analyzeRequestHeaders(headers map[string]string, result *PIIAnalysisResult) {
	for fieldName, fieldValue := range headers {
		findings := s.detectPIIInField(fieldName, fieldValue, "request_headers")
		result.Findings = append(result.Findings, findings...)
	}
}

func (s *PIIService) analyzeRequestBody(body string, result *PIIAnalysisResult) {
	if body == "" || body == "[Invalid UTF-8 or Binary Data]" {
		return
	}
	if s.isJSON(body) {
		s.analyzeJSONForPII(body, "request_body", result)
	} else {
		findings := s.detectPIIInText("", body, "request_body")
		result.Findings = append(result.Findings, findings...)
	}
}

func (s *PIIService) analyzeResponseBody(body string, result *PIIAnalysisResult) {
	if body == "" || body == "[Invalid UTF-8 or Binary Data]" {
		return
	}
	if s.isJSON(body) {
		s.analyzeJSONForPII(body, "response_body", result)
	} else {
		findings := s.detectPIIInText("", body, "response_body")
		result.Findings = append(result.Findings, findings...)
	}
}

func (s *PIIService) analyzeURL(urlString string, result *PIIAnalysisResult) {
	decodedURL, err := url.QueryUnescape(urlString)
	if err != nil {
		log.Printf("Error decoding URL: %v", err)
		decodedURL = urlString
	}
	parsedURL, err := url.Parse(decodedURL)
	if err != nil {
		log.Printf("Error parsing URL: %v", err)
		return
	}
	path := parsedURL.Path
	pathSegments := strings.Split(path, "/")
	for i, segment := range pathSegments {
		if segment != "" {
			fieldName := s.inferFieldNameFromURL(pathSegments, i)
			findings := s.detectPIIInField(fieldName, segment, "url_path")
			result.Findings = append(result.Findings, findings...)
			if fieldName == "url_path_segment" {
				valueFindings := s.detectPIIInText("", segment, "url_path")
				for _, finding := range valueFindings {
					finding.FieldName = fmt.Sprintf("url_segment_%d", i)
					result.Findings = append(result.Findings, finding)
				}
			}
		}
	}
	queryParams := parsedURL.Query()
	for key, values := range queryParams {
		for _, value := range values {
			findings := s.detectPIIInField(key, value, "query_params")
			result.Findings = append(result.Findings, findings...)
		}
	}
}

func (s *PIIService) inferFieldNameFromURL(pathSegments []string, currentIndex int) string {
	if currentIndex <= 0 || currentIndex >= len(pathSegments) {
		return "url_path_segment"
	}
	previousSegment := strings.ToLower(pathSegments[currentIndex-1])
	switch previousSegment {
	case "apikey", "api-key", "api_key":
		return "apikey"
	case "token", "access-token", "access_token":
		return "token"
	case "key":
		return "key"
	case "id", "userid", "user-id", "user_id":
		return "id"
	case "email":
		return "email"
	case "phone":
		return "phone"
	case "ssn":
		return "ssn"
	case "sin":
		return "sin"
	case "auth", "authorization":
		if currentIndex+1 < len(pathSegments) {
			nextSegment := strings.ToLower(pathSegments[currentIndex+1])
			if nextSegment == "apikey" || nextSegment == "key" {
				return "apikey"
			}
		}
		return "auth_token"
	default:
		if strings.Contains(previousSegment, "key") {
			return "apikey"
		}
		if strings.Contains(previousSegment, "token") {
			return "token"
		}
		if strings.Contains(previousSegment, "id") {
			return "id"
		}
		return "url_path_segment"
	}
}

func (s *PIIService) detectPIIInField(fieldName, fieldValue, location string) []PIIDetectionResult {
	var findings []PIIDetectionResult
	fieldNameLower := strings.ToLower(fieldName)
	for patternName, pattern := range s.config.DetectionModes.FieldBased.Patterns {
		for _, targetField := range pattern.FieldNames {
			if strings.Contains(fieldNameLower, strings.ToLower(targetField)) {
				regexKey := fmt.Sprintf("field_%s", patternName)
				if regex, exists := s.compiledRegex[regexKey]; exists {
					if regex.MatchString(fieldValue) {
						findings = append(findings, PIIDetectionResult{
							PIIType:       patternName,
							DetectedValue: s.maskSensitiveValue(fieldValue),
							FieldName:     fieldName,
							Location:      location,
							DetectionMode: "field_based",
							RiskLevel:     pattern.RiskLevel,
							Category:      pattern.Category,
							Tags:          pattern.Tags,
							Timestamp:     time.Now(),
						})
						return findings
					}
				}
			}
		}
	}
	for patternName, pattern := range s.config.DetectionModes.KeywordBased.Patterns {
		if regex, exists := s.keywordRegex[patternName]; exists {
			if regex.MatchString(fieldName) {
				findings = append(findings, PIIDetectionResult{
					PIIType:       patternName,
					DetectedValue: s.maskSensitiveValue(fieldValue),
					FieldName:     fieldName,
					Location:      location,
					DetectionMode: "keyword_based",
					RiskLevel:     pattern.RiskLevel,
					Category:      pattern.Category,
					Tags:          pattern.Tags,
					Timestamp:     time.Now(),
				})
			}
		}
	}
	valueFindings := s.detectPIIInText(fieldNameLower, fieldValue, location)
	for _, finding := range valueFindings {
		finding.FieldName = fieldName
		findings = append(findings, finding)
	}
	return findings
}

func (s *PIIService) detectPIIInText(fieldNameLower, text, location string) []PIIDetectionResult {
	var findings []PIIDetectionResult
	cardFields := []string{"cardnumber", "ccnumber", "creditcard", "card", "cc", "visa", "visacard", "mastercard", "maestro"}
	for patternName, pattern := range s.config.DetectionModes.ValueOnly.Patterns {
		skip := false
		if location != "url_path" {
			for _, cardField := range cardFields {
				if strings.Contains(fieldNameLower, cardField) {
					skip = true
					break
				}
			}
		}
		if skip {
			continue
		}
		regexKey := fmt.Sprintf("value_%s", patternName)
		if regex, exists := s.compiledRegex[regexKey]; exists {
			matches := regex.FindAllString(text, -1)
			for _, match := range matches {
				findings = append(findings, PIIDetectionResult{
					PIIType:       patternName,
					DetectedValue: s.maskSensitiveValue(match),
					Location:      location,
					DetectionMode: "value_only",
					RiskLevel:     pattern.RiskLevel,
					Category:      pattern.Category,
					Tags:          pattern.Tags,
					Timestamp:     time.Now(),
				})
			}
		}
	}
	return findings
}

func (s *PIIService) analyzeJSONForPII(jsonStr, location string, result *PIIAnalysisResult) {
	var jsonData interface{}
	if err := json.Unmarshal([]byte(jsonStr), &jsonData); err != nil {
		findings := s.detectPIIInText("", jsonStr, location)
		result.Findings = append(result.Findings, findings...)
		return
	}
	s.analyzeJSONObject(jsonData, "", location, result)
}

func (s *PIIService) analyzeJSONObject(data interface{}, prefix, location string, result *PIIAnalysisResult) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			fullKey := key
			if prefix != "" {
				fullKey = prefix + "." + key
			}
			switch val := value.(type) {
			case string:
				findings := s.detectPIIInField(key, val, location)
				result.Findings = append(result.Findings, findings...)
			case map[string]interface{}, []interface{}:
				s.analyzeJSONObject(val, fullKey, location, result)
			}
		}
	case []interface{}:
		for i, item := range v {
			s.analyzeJSONObject(item, fmt.Sprintf("%s[%d]", prefix, i), location, result)
		}
	}
}

func (s *PIIService) maskSensitiveValue(value string) string {
	if len(value) <= 4 {
		return strings.Repeat("*", len(value))
	}
	return value[:2] + strings.Repeat("*", len(value)-4) + value[len(value)-2:]
}

func (s *PIIService) calculateRiskMetrics(findings []PIIDetectionResult) (int, string) {
	if len(findings) == 0 {
		return 0, "NONE"
	}
	totalScore := 0
	highestRisk := "LOW"
	maxRiskValue := 0
	for _, finding := range findings {
		if riskValue, exists := s.config.RiskLevels[finding.RiskLevel]; exists {
			totalScore += riskValue
			if riskValue > maxRiskValue {
				maxRiskValue = riskValue
				highestRisk = finding.RiskLevel
			}
		}
	}
	return totalScore, highestRisk
}

func (s *PIIService) isJSON(str string) bool {
	var js interface{}
	return json.Unmarshal([]byte(str), &js) == nil
}

func (s *PIIService) ProcessAllAPIDataForPII() ([]PIIAnalysisResult, error) {
	apiDataList, err := s.db.FindAllAPIData()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch API data: %w", err)
	}
	var results []PIIAnalysisResult
	log.Printf("Starting PII analysis for %d API entries", len(apiDataList))
	for _, apiData := range apiDataList {
		result := s.AnalyzePIIInAPIData(apiData)
		if result.TotalCount > 0 {
			results = append(results, result)
			log.Printf("Found %d PII findings in %s %s (Risk: %s, Score: %d)",
				result.TotalCount, result.Method, result.APIEndpoint,
				result.HighestRisk, result.RiskScore)
		}
	}
	log.Printf("PII analysis complete. Found PII in %d/%d API entries", len(results), len(apiDataList))
	return results, nil
}

func (s *PIIService) GetPIIStats(results []PIIAnalysisResult) map[string]interface{} {
	stats := map[string]interface{}{
		"total_apis_analyzed":    0,
		"apis_with_pii":         len(results),
		"total_pii_findings":    0,
		"risk_level_breakdown":  make(map[string]int),
		"category_breakdown":    make(map[string]int),
		"detection_mode_breakdown": make(map[string]int),
	}
	totalFindings := 0
	riskBreakdown := make(map[string]int)
	categoryBreakdown := make(map[string]int)
	modeBreakdown := make(map[string]int)
	for _, result := range results {
		totalFindings += result.TotalCount
		for _, finding := range result.Findings {
			riskBreakdown[finding.RiskLevel]++
			categoryBreakdown[finding.Category]++
			modeBreakdown[finding.DetectionMode]++
		}
	}
	stats["total_pii_findings"] = totalFindings
	stats["risk_level_breakdown"] = riskBreakdown
	stats["category_breakdown"] = categoryBreakdown
	stats["detection_mode_breakdown"] = modeBreakdown
	return stats
}