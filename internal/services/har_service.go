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

    apiInfoList := har_parser.ExtractAPIInfo(harData) // Call ExtractAPIInfo

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
		// Create a UserAPIData struct
		apiData := db.UserAPIData{
			APIEndpoint: apiEndpoint,
			Method:      method,
			Headers:        headers,
			Source:      "HAR File", // Set the source
		}

		// Save the API data to MongoDB
		err = db.SaveUserAPIData(apiData)
		if err != nil {
			log.Printf("Failed to save API data to MongoDB: %v\n", err)
			// Consider whether to continue processing other API entries
		}
	}

	return nil
}