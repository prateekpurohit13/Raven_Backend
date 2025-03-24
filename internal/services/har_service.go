package services

import(
	"fmt"
	"log"
	"github.com/RavenSec10/Raven_Backend/har_parser"
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

    // Now, do something with the extracted API info (e.g., print it, store it):
    for _, apiInfo := range apiInfoList {
		method, ok := apiInfo["method"].(string)
		if !ok {
			log.Println("Error: 'method' is not a string")
			continue
		}

		url, ok := apiInfo["url"].(string)
		if !ok {
			log.Println("Error: 'url' is not a string")
			continue
		}
        fmt.Println("Method:", method)
        fmt.Println("URL:", url)
        
    }

    return nil
}