package services

import(
	"fmt"
	"log"
	"github.com/RavenSec10/Raven_Backend/har_parser"
	"github.com/RavenSec10/Raven_Backend/db"

)

// HARService struct
type HARService struct{}

func NewHARService() *HARService {
	return &HARService{}
}

func (s *HARService) ProcessAndStore(filePath string) error {
	harData, err := har_parser.ParseHAR(filePath)
	if err != nil {
		return fmt.Errorf("failed to parse HAR file: %w", err)
	}

	apiInfoList := har_parser.ExtractAPIInfo(harData)

	// Process the extracted API info and save to MongoDB
	for _, apiInfo := range apiInfoList {
		methodValue, ok := apiInfo["request_method"]
		if !ok {
			log.Println("Error: 'request_method' is missing")
			continue
		}

		method, ok := methodValue.(string)
		if !ok {
			log.Println("Error: 'request_method' is not a string")
			continue
		}
		
		apiEndpointValue, ok := apiInfo["request_url"]
		if !ok {
			log.Println("Error: 'request_url' is missing")
			continue
		}

		apiEndpoint, ok := apiEndpointValue.(string)
		if !ok {
			log.Println("Error: 'request_url' is not a string")
			continue
		}

		headersValue, ok := apiInfo["request_headers"]
		if !ok {
			log.Println("Error: 'request_headers' is missing")
			continue
		}

		headers, ok := headersValue.(map[string]string)
		if !ok {
			log.Println("Error: 'request_headers' is not a map[string]string")
			continue
		}

		requestBodyValue, ok := apiInfo["request_body"]
		if !ok {
			log.Println("Error: 'request_body' is missing")
		}
		requestBody := ""
		if ok {
			requestBody = requestBodyValue.(string)
		}


		responseBodyValue, ok := apiInfo["response_body"]
		if !ok {
			log.Println("Error: 'response_body' is missing")
		}

		responseBody := ""
		if ok {
			responseBody = responseBodyValue.(string)
		}

		// Create a UserAPIData struct
		apiData := db.UserAPIData{
			APIEndpoint: apiEndpoint,
			Method:      method,
			Headers:        headers,
			RequestBody:     map[string]interface{}{"body": requestBody}, // Assign request body,
			ResponseBody:     map[string]interface{}{"body": responseBody}, // Assign response body,
			Source:      "HAR File", // Set the source
		}

		// Save the API data to MongoDB
		err = db.SaveUserAPIData(apiData)
		if err != nil {
			log.Printf("Failed to save API data to MongoDB: %v\n", err)
		}
	}

	return nil
}