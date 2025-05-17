package services

import (
	"fmt"
	"log"
	"unicode/utf8"
	"github.com/RavenSec10/Raven_Backend/db"
	"github.com/RavenSec10/Raven_Backend/har_parser"
)

type HARService struct{}

func NewHARService() *HARService {
	return &HARService{}
}

// ProcessAndStore processes a HAR file and stores extracted info in MongoDB
func (s *HARService) ProcessAndStore(filePath string) error {
	harData, err := har_parser.ParseHAR(filePath)
	if err != nil {
		return fmt.Errorf("failed to parse HAR file '%s': %w", filePath, err)
	}

	extractedInfoList := har_parser.ExtractAPIInfo(harData)

	log.Printf("Extracted %d entries from HAR file: %s", len(extractedInfoList), filePath)

	// Process the extracted API info and save to MongoDB
	var successCount, errorCount int
	for _, info := range extractedInfoList {

		// Validate Request Body
		requestBody := info.RequestBody
    	if !utf8.ValidString(requestBody) {
        	log.Printf("Warning: Invalid UTF-8 detected in request body for %s %s. Replacing.", info.Method, info.APIEndpoint)
        	requestBody = "[Invalid UTF-8 or Binary Data]"
    	}

		// Validate Response Body
		responseBody := info.ResponseBody
		if !utf8.ValidString(responseBody) {
			log.Printf("Warning: Invalid UTF-8 detected in response body for %s %s. Replacing.", info.Method, info.APIEndpoint)
			responseBody = "[Invalid UTF-8 or Binary Data]"
		}

		// Create a UserAPIData struct directly from the extracted info
		apiData := db.UserAPIData{
			APIEndpoint: info.APIEndpoint,
			Method:      info.Method,
			Headers:     info.RequestHeaders,
			RequestBody:  requestBody,
			ResponseBody: responseBody,
			Source:       "HAR File", 
			Timestamp:    info.StartedDateTime,
			Url:          info.URL,
		}

		

		// Save the API data to MongoDB
		err = db.SaveUserAPIData(apiData)
		if err != nil {
			log.Printf("Failed to save API data to MongoDB for entry (%s %s): %v\n", info.Method, info.APIEndpoint, err)
			errorCount++
		} else {
			successCount++
		}
	}

	log.Printf("HAR processing complete for %s. Successful inserts: %d, Errors: %d", filePath, successCount, errorCount)
	if errorCount > 0 {
		return fmt.Errorf("encountered %d errors while saving HAR entries to database", errorCount)
	}

	return nil
}