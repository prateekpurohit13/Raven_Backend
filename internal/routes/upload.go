package routes

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

// UploadHAR handles .har file uploads and reads its contents
func UploadHAR(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file found"})
		return
	}

	// Ensure uploads directory exists
	uploadDir := "./uploads"
	if _, err := os.Stat(uploadDir); os.IsNotExist(err) {
		os.Mkdir(uploadDir, os.ModePerm)
	}

	// Save file to uploads directory
	dst := filepath.Join(uploadDir, file.Filename)
	if err := c.SaveUploadedFile(file, dst); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}

	// Read file contents
	harData, err := os.ReadFile(dst)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read HAR file"})
		return
	}

	// Print HAR file contents
	fmt.Println("HAR File Contents:")
	fmt.Println(string(harData))

	// Return response
	c.JSON(http.StatusOK, gin.H{
		"message":  "HAR file uploaded successfully",
		"filename": file.Filename,
		"content":  string(harData), // Optional: Send HAR contents in response
	})
}
