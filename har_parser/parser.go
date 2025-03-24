package har_parser

import (
	"encoding/json"
	"os"
)

// HAR struct (simplified, extend as needed)
type HAR struct {
	Log struct {
		Entries []struct {
			Request struct {
				Method string `json:"method"`
				URL    string `json:"url"`
			} `json:"request"`
		} `json:"entries"`
	} `json:"log"`
}

// ParseHAR reads and parses a HAR file
func ParseHAR(filePath string) (*HAR, error) {
	data, err := os.ReadFile(filePath) // UPDATED: Replaced ioutil.ReadAll
	if err != nil {
		return nil, err
	}

	var har HAR
	err = json.Unmarshal(data, &har)
	if err != nil {
		return nil, err
	}

	return &har, nil
}

// ExtractAPIInfo extracts specific API information from the parsed HAR data
func ExtractAPIInfo(har *HAR) []map[string]interface{} {
	apiInfoList := make([]map[string]interface{}, 0) // Initialize an empty slice

	for _, entry := range har.Log.Entries {
		apiInfo := map[string]interface{}{
			"method": entry.Request.Method,
			"url":    entry.Request.URL,
		}
		apiInfoList = append(apiInfoList, apiInfo)
	}

	return apiInfoList
}