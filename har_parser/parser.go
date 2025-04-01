package har_parser

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
)

// HAR struct (more complete)
type HAR struct {
	Log struct {
		Entries []HAREntry `json:"entries"`
	} `json:"log"`
}

type HAREntry struct {
	Request struct {
		Method  string      `json:"method"`
		URL     string      `json:"url"`
		Headers []HARHeader `json:"headers"`
		// Body  string      `json:"body"`  // Add if you need request body
	} `json:"request"`
	Response struct {
		Status      int         `json:"status"`
		StatusText  string      `json:"statusText"`
		Headers     []HARHeader `json:"headers"`
		Content struct{
			Size int64 `json:"size"`
		} `json:"content"`// Add if you need response body
		BodySize int64 `json:"bodySize"`
	} `json:"response"`
	Time    float64 `json:"time"`
	StartedDateTime string `json:"startedDateTime"` // add if you need timestamp of the request
}

type HARHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ParseHAR reads and parses a HAR file
func ParseHAR(filePath string) (*HAR, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("error reading HAR file: %w", err)
	}

	var har HAR
	err = json.Unmarshal(data, &har)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling HAR data: %w", err)
	}

	// Post-processing: Extract request path
	for i := range har.Log.Entries {
		har.Log.Entries[i].Request.URL = extractPathFromURL(har.Log.Entries[i].Request.URL)
	}

	return &har, nil
}

// extractPathFromURL extracts the path from a URL string.
func extractPathFromURL(urlString string) string {
	u, err := url.Parse(urlString)
	if err != nil {
		return "" // Return empty string if parsing fails
	}
	return u.Path
}

// simplifyHeaders extracts and simplifies header information.
func simplifyHeaders(headers []HARHeader) map[string]string {
	simplified := make(map[string]string)
	for _, header := range headers {
		simplified[header.Name] = header.Value
	}
	return simplified
}

// ExtractAPIInventory extracts relevant API inventory data from a HAR file.
func ExtractAPIInfo(har *HAR) []map[string]interface{} {
	apiInventory := []map[string]interface{}{}

	for _, entry := range har.Log.Entries {
		apiInfo := map[string]interface{}{
			"request_method":  entry.Request.Method,
			"request_url":     entry.Request.URL,
			"request_headers": simplifyHeaders(entry.Request.Headers),
			"response_status": entry.Response.Status,
			"response_headers": simplifyHeaders(entry.Response.Headers),
			"response_body_size": entry.Response.BodySize,
			"timestamp":       entry.StartedDateTime,
			"time":            entry.Time,  // Request processing time
			// Add more fields as needed
		}
		apiInventory = append(apiInventory, apiInfo)
	}

	return apiInventory
}