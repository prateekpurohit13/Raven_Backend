package services

import (
	"fmt"
	"log"
	"time"
	"unicode/utf8"

	"github.com/RavenSec10/Raven_Backend/db"
	"github.com/RavenSec10/Raven_Backend/har_parser"
)

type HARService struct{
	piiService *PIIService
}

func NewHARService() (*HARService, error) {
	piiService, err := NewPIIService()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PII service: %w", err)
	}

	return &HARService{
		piiService: piiService,
	}, nil
}

func (s *HARService) ProcessAndStore(filePath string) error {
	harData, err := har_parser.ParseHAR(filePath)
	if err != nil {
		return fmt.Errorf("failed to parse HAR file '%s': %w", filePath, err)
	}

	extractedInfoList := har_parser.ExtractAPIInfo(harData)
	log.Printf("Extracted %d entries from HAR file: %s", len(extractedInfoList), filePath)
	var successCount, errorCount, piiFoundCount int

	for _, info := range extractedInfoList {
		requestBody := info.RequestBody
		if !utf8.ValidString(requestBody) {
			log.Printf("Warning: Invalid UTF-8 detected in request body for %s %s. Replacing.", info.Method, info.APIEndpoint)
			requestBody = "[Invalid UTF-8 or Binary Data]"
		}
		responseBody := info.ResponseBody
		if !utf8.ValidString(responseBody) {
			log.Printf("Warning: Invalid UTF-8 detected in response body for %s %s. Replacing.", info.Method, info.APIEndpoint)
			responseBody = "[Invalid UTF-8 or Binary Data]"
		}

		apiData := db.UserAPIData{
			APIEndpoint: info.APIEndpoint,
			Method:      info.Method,
			Headers:     info.RequestHeaders,
			RequestBody: requestBody,
			ResponseBody: responseBody,
			Source:      "HAR File",
			Timestamp:   info.StartedDateTime,
			Url:         info.URL,
		}

		piiAnalysis := s.piiService.AnalyzePIIInAPIData(apiData)
		var piiFindings []db.PIIFinding
		var sensitiveFields []string
		piiTypeMap := make(map[string]bool)

		for _, finding := range piiAnalysis.Findings {
			piiFinding := db.PIIFinding{
				PIIType:       finding.PIIType,
				DetectedValue: finding.DetectedValue,
				FieldName:     finding.FieldName,
				Location:      finding.Location,
				DetectionMode: finding.DetectionMode,
				RiskLevel:     finding.RiskLevel,
				Category:      finding.Category,
				Tags:          finding.Tags,
				Timestamp:     finding.Timestamp,
				PIICount:        piiAnalysis.TotalCount,
				RiskScore:       piiAnalysis.RiskScore,
				HighestRisk:     piiAnalysis.HighestRisk,
				HasPII:          piiAnalysis.TotalCount > 0,
				LastPIIAnalysis: piiAnalysis.Timestamp,
			}
			piiFindings = append(piiFindings, piiFinding)

			if _, ok := piiTypeMap[finding.PIIType]; !ok {
				sensitiveFields = append(sensitiveFields, finding.PIIType)
				piiTypeMap[finding.PIIType] = true
			}
		}
		apiData.PIIFindings = piiFindings
		apiData.SensitiveFields = sensitiveFields
		apiData.RiskLevel = piiAnalysis.HighestRisk
		err = db.SaveUserAPIData(apiData)
		if err != nil {
			log.Printf("Failed to save API data to MongoDB for entry (%s %s): %v\n", info.Method, info.APIEndpoint, err)
			errorCount++
		} else {
			successCount++
			if piiAnalysis.TotalCount > 0 {
				piiFoundCount++
				log.Printf("PII Alert: Found %d PII items in %s %s (Risk: %s, Score: %d)",
					piiAnalysis.TotalCount, info.Method, info.APIEndpoint,
					piiAnalysis.HighestRisk, piiAnalysis.RiskScore)
			}
		}
	}

	log.Printf("HAR processing complete for %s. Successful inserts: %d, Errors: %d, APIs with PII: %d",
		filePath, successCount, errorCount, piiFoundCount)

	if errorCount > 0 {
		return fmt.Errorf("encountered %d errors while saving HAR entries to database", errorCount)
	}

	return nil
}

func (s *HARService) ProcessExistingDataForPII() error {
	log.Println("Starting PII analysis for existing API data...")
	apiDataList, err := db.FindAllAPIData()
	if err != nil {
		return fmt.Errorf("failed to fetch existing API data: %w", err)
	}
	var processedCount, piiFoundCount int

	for _, apiData := range apiDataList {
		needsAnalysis := true

		for _, finding := range apiData.PIIFindings {
			if !finding.LastPIIAnalysis.IsZero() &&
				finding.LastPIIAnalysis.After(finding.LastPIIAnalysis.Add(-24*time.Hour)) {
				needsAnalysis = false
				break
			}
		}

		if !needsAnalysis {
			continue
		}

		piiAnalysis := s.piiService.AnalyzePIIInAPIData(apiData)
		if piiAnalysis.TotalCount > 0 {
			piiFoundCount++
			var piiFindings []db.PIIFinding
			for _, finding := range piiAnalysis.Findings {
				piiFinding := db.PIIFinding{
					PIIType:       finding.PIIType,
					DetectedValue: finding.DetectedValue,
					FieldName:     finding.FieldName,
					Location:      finding.Location,
					DetectionMode: finding.DetectionMode,
					RiskLevel:     finding.RiskLevel,
					Category:      finding.Category,
					Tags:          finding.Tags,
					Timestamp:     finding.Timestamp,
					PIICount:        piiAnalysis.TotalCount,
					RiskScore:       piiAnalysis.RiskScore,
					HighestRisk:     piiAnalysis.HighestRisk,
					HasPII:          piiAnalysis.TotalCount > 0,
					LastPIIAnalysis: piiAnalysis.Timestamp,
				}
				piiFindings = append(piiFindings, piiFinding)
			}
			err := db.UpdateUserAPIDataWithPII(
				apiData.APIEndpoint,
				apiData.Method,
				piiFindings,
				piiAnalysis.RiskScore,
				piiAnalysis.HighestRisk,
			)

			if err != nil {
				log.Printf("Failed to update PII data for %s %s: %v", apiData.Method, apiData.APIEndpoint, err)
			}
		}

		processedCount++
	}

	log.Printf("PII analysis complete. Processed: %d, Found PII in: %d APIs", processedCount, piiFoundCount)
	return nil
}

func (s *HARService) GeneratePIIComplianceReport() (*db.PIIAnalysisReport, error) {
	log.Println("Generating PII compliance report...")
	stats, err := db.GetPIIComplianceStats()
	if err != nil {
		return nil, fmt.Errorf("failed to get compliance stats: %w", err)
	}
	apisWithPII, err := db.FindAPIDataWithPII()
	if err != nil {
		return nil, fmt.Errorf("failed to get APIs with PII: %w", err)
	}

	var topRiskyEndpoints []db.RiskyEndpoint
	for _, apiData := range apisWithPII {
		for _, finding := range apiData.PIIFindings {
			if finding.RiskScore > 5 {
				topRiskyEndpoints = append(topRiskyEndpoints, db.RiskyEndpoint{
					APIEndpoint: apiData.APIEndpoint,
					Method:      apiData.Method,
					RiskScore:   finding.RiskScore,
					PIICount:    finding.PIICount,
					HighestRisk: finding.HighestRisk,
				})
				break
			}
		}
	}
	if len(topRiskyEndpoints) > 10 {
		topRiskyEndpoints = topRiskyEndpoints[:10]
	}

	complianceStatus := "COMPLIANT"
	if compliancePercentage, ok := stats["compliance_percentage"].(float64); ok {
		if compliancePercentage < 80 {
			complianceStatus = "NON_COMPLIANT"
		} else if compliancePercentage < 95 {
			complianceStatus = "PARTIALLY_COMPLIANT"
		}
	}

	report := db.PIIAnalysisReport{
		TotalAPIsAnalyzed:      int(stats["total_apis"].(int32)),
		APIsWithPII:           int(stats["apis_with_pii"].(int32)),
		TotalPIIFindings:      int(stats["total_pii_findings"].(int32)),
		RiskLevelBreakdown:    make(map[string]int),
		CategoryBreakdown:     make(map[string]int),
		DetectionModeBreakdown: make(map[string]int),
		TopRiskyEndpoints:     topRiskyEndpoints,
		ComplianceStatus:      complianceStatus,
	}

	for _, apiData := range apisWithPII {
		for _, finding := range apiData.PIIFindings {
			report.RiskLevelBreakdown[finding.RiskLevel]++
			report.CategoryBreakdown[finding.Category]++
			report.DetectionModeBreakdown[finding.DetectionMode]++
		}
	}

	err = db.SavePIIAnalysisReport(report)
	if err != nil {
		return nil, fmt.Errorf("failed to save PII analysis report: %w", err)
	}
	log.Printf("PII compliance report generated successfully")
	return &report, nil
}

func (s *HARService) GetPIIServiceStats() map[string]interface{} {
	return map[string]interface{}{
		"total_patterns_loaded": len(s.piiService.compiledRegex) + len(s.piiService.keywordRegex),
		"field_based_patterns":  len(s.piiService.config.DetectionModes.FieldBased.Patterns),
		"value_only_patterns":   len(s.piiService.config.DetectionModes.ValueOnly.Patterns),
		"keyword_patterns":      len(s.piiService.config.DetectionModes.KeywordBased.Patterns),
		"supported_categories":  s.piiService.config.Categories,
		"risk_levels":          s.piiService.config.RiskLevels,
	}
}