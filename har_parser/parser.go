package har_parser

import (
	"encoding/base64" 
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings" 
	"time"    
)

type HAR struct {
	Log Log `json:"log"`
}

type Log struct {
	Version string     `json:"version"`
	Creator Creator    `json:"creator"`
	Pages   []Page     `json:"pages,omitempty"`
	Entries []HAREntry `json:"entries"`
}

type Creator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Comment string `json:"comment,omitempty"` 
}

type Page struct {
	StartedDateTime time.Time   `json:"startedDateTime"` 
	ID              string      `json:"id"`
	Title           string      `json:"title"`
	PageTimings     PageTimings `json:"pageTimings"`
	Comment         string      `json:"comment,omitempty"` 
}

type PageTimings struct {
	OnContentLoad float64 `json:"onContentLoad,omitempty"` // Use float64, handle -1/omitempty
	OnLoad        float64 `json:"onLoad,omitempty"`        // Use float64, handle -1/omitempty
	Comment       string  `json:"comment,omitempty"`       
}

type HAREntry struct {
	Pageref         string    `json:"pageref,omitempty"` 
	StartedDateTime time.Time `json:"startedDateTime"`   // Use time.Time
	Time            float64   `json:"time"`              // Request time in ms
	Request         Request   `json:"request"`
	Response        Response  `json:"response"`
	Cache           Cache     `json:"cache"`             // Cache details
	Timings         Timings   `json:"timings"`           // Detailed timings
	ServerIPAddress string    `json:"serverIPAddress,omitempty"`
	Connection      string    `json:"connection,omitempty"`
	Comment         string    `json:"comment,omitempty"` 
}

type Request struct {
	Method      string        `json:"method"`
	URL         string        `json:"url"` // Keep original URL here
	HTTPVersion string        `json:"httpVersion"`
	Cookies     []Cookie      `json:"cookies"`
	Headers     []HARHeader   `json:"headers"`
	QueryString []QueryString `json:"queryString"`
	PostData    *PostData `json:"postData,omitempty"`
	HeadersSize int64     `json:"headersSize"` // Use int64, handle -1
	BodySize    int64     `json:"bodySize"`    // Use int64, handle -1
	Comment     string    `json:"comment,omitempty"`
}

type Response struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Cookies     []Cookie    `json:"cookies"`
	Headers     []HARHeader `json:"headers"`
	Content     *RespContent `json:"content"`
	RedirectURL string       `json:"redirectURL"`
	HeadersSize int64        `json:"headersSize"` // Use int64, handle -1
	BodySize    int64        `json:"bodySize"`    // Use int64, handle -1 (size before decompression)
	Comment     string       `json:"comment,omitempty"`
}

// Added PostData struct (as used in Request)
type PostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`    // Body content
	Params   []Param `json:"params,omitempty"` 
	Comment  string `json:"comment,omitempty"` 
}

// Added RespContent struct (as used in Response)
type RespContent struct {
	Size     int64  `json:"size"` // Size of the response body (decompressed)
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`    // Body content (may be base64 encoded)
	Encoding string `json:"encoding,omitempty"` 
	Comment  string `json:"comment,omitempty"`  
}

type HARHeader struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Comment string `json:"comment,omitempty"`
}

type Cookie struct {
	Name     string     `json:"name"`
	Value    string     `json:"value"`
	Path     string     `json:"path,omitempty"`
	Domain   string     `json:"domain,omitempty"`
	Expires  *time.Time `json:"expires,omitempty"` 
	HTTPOnly bool       `json:"httpOnly,omitempty"`
	Secure   bool       `json:"secure,omitempty"`
	Comment  string     `json:"comment,omitempty"`
}

type QueryString struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Comment string `json:"comment,omitempty"` 
}

type Param struct {
	Name        string `json:"name"`
	Value       string `json:"value,omitempty"`
	FileName    string `json:"fileName,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	Comment     string `json:"comment,omitempty"` 
}

type Cache struct { 
	BeforeRequest *CacheEntry `json:"beforeRequest,omitempty"`
	AfterRequest  *CacheEntry `json:"afterRequest,omitempty"`
	Comment       string      `json:"comment,omitempty"` 
}
type CacheEntry struct {
	Expires    *time.Time `json:"expires,omitempty"`
	LastAccess time.Time  `json:"lastAccess"`
	ETag       string     `json:"eTag"`
	HitCount   int        `json:"hitCount"`
	Comment    string     `json:"comment,omitempty"` 
}

type Timings struct { 
	Blocked float64 `json:"blocked,omitempty"` // Use float64, handle -1/omitempty
	DNS     float64 `json:"dns,omitempty"`     // Use float64, handle -1/omitempty
	Connect float64 `json:"connect,omitempty"` // Use float64, handle -1/omitempty
	Send    float64 `json:"send"`              // Use float64
	Wait    float64 `json:"wait"`              // Use float64
	Receive float64 `json:"receive"`           // Use float64
	SSL     float64 `json:"ssl,omitempty"`     // Use float64, handle -1/omitempty
	Comment string  `json:"comment,omitempty"` 
}

// Parsing and Extraction Logic

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

	return &har, nil
}

func extractPathFromURL(urlString string) string {
	u, err := url.Parse(urlString)
	if err != nil {
		fmt.Printf("Warning: Failed to parse URL '%s': %v\n", urlString, err)
		return urlString // Return original URL on parse error
	}

	return u.RequestURI() // Returns path + query string
}

func simplifyHeaders(headers []HARHeader) map[string]string {
	simplified := make(map[string]string)
	for _, header := range headers {
		simplified[strings.ToLower(header.Name)] = header.Value // Store keys lowercased for consistency
	}
	return simplified
}

type ExtractedInfo struct {
	Method          string            `json:"request_method"`
	URL             string            `json:"request_url"` // Full original URL
	APIEndpoint     string            `json:"api_endpoint"` // Just the path/query part
	RequestHeaders  map[string]string `json:"request_headers"`
	RequestBody     string            `json:"request_body"` // Body as string
	ResponseStatus  int               `json:"response_status"`
	ResponseHeaders map[string]string `json:"response_headers"`
	ResponseBody    string            `json:"response_body"` // Body as string
	ResponseBodySize int64             `json:"response_body_size"` // Size from response.content.size
	StartedDateTime time.Time         `json:"timestamp"`
	Time            float64           `json:"time"` // Request processing time
}

func ExtractAPIInfo(har *HAR) []ExtractedInfo {
	apiInventory := []ExtractedInfo{}

	for _, entry := range har.Log.Entries {
		apiInfo := ExtractedInfo{
			Method:          entry.Request.Method,
			URL:             entry.Request.URL,                       // Store original URL
			APIEndpoint:     extractPathFromURL(entry.Request.URL), // Extract path/query
			RequestHeaders:  simplifyHeaders(entry.Request.Headers),
			RequestBody:     getRequestBody(&entry), // Safely get request body
			ResponseStatus:  entry.Response.Status,
			ResponseHeaders: simplifyHeaders(entry.Response.Headers),
			ResponseBody:    getResponseBody(&entry), // Safely get response body
			ResponseBodySize: getResponseBodySize(&entry),
			StartedDateTime:  entry.StartedDateTime,
			Time:             entry.Time,
		}
		apiInventory = append(apiInventory, apiInfo)
	}

	return apiInventory
}

func getRequestBody(entry *HAREntry) string {
	if entry.Request.PostData == nil {
		return "" // No PostData present
	}
	return entry.Request.PostData.Text
}

func getResponseBody(entry *HAREntry) string {
	if entry.Response.Content == nil {
		return "" // No Content present
	}

	bodyText := entry.Response.Content.Text

	// Handle base64 encoding if specified
	if entry.Response.Content.Encoding == "base64" {
		decodedBody, err := base64.StdEncoding.DecodeString(bodyText)
		if err == nil {
			return string(decodedBody)
		} else {
			fmt.Printf("Warning: Failed to decode base64 response body for URL %s: %v\n", entry.Request.URL, err)

			return bodyText
		}
	}

	return bodyText 
}

func getResponseBodySize(entry *HAREntry) int64 {
    if entry.Response.Content != nil {
        return entry.Response.Content.Size
    }
	
    return entry.Response.BodySize
}