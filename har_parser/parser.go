package harparser

import (
	"encoding/json"
	"fmt"
	"os"
)

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

func ParseHAR(filename string) (*HAR, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var har HAR
	if err := json.Unmarshal(file, &har); err != nil {
		return nil, err
	}

	return &har, nil
}

func PrintHARData(har *HAR) {
	for _, entry := range har.Log.Entries {
		fmt.Println("Method:", entry.Request.Method, "| URL:", entry.Request.URL)
	}
}
