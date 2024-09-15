package main

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// Mock Redis and Postgres initialization to avoid real DB and Redis setup
func init() {
	// Set up a temporary file to simulate upload in tests
	file, err := os.CreateTemp("", "testfile-*.txt")
	if err != nil {
		panic("Failed to create temporary file for testing")
	}
	file.WriteString("This is a test file.")
	file.Close()

	// You can set up an in-memory database or skip DB setup for testing
}

// Helper function to get JWT token for tests
func getTestToken() string {
	// You would typically mock the login and return a JWT for tests
	return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6Im5pc2hhbnRAZ21haWwuY29tIiwiZXhwIjoxNzI2NDMxNDI1fQ.jnScgo49-fUh0A_4_qRtiCd-37kFKLIpHkevM7L2HJA"
}

func TestUploadFile(t *testing.T) {
	router := initRouter()

	// Create a new file upload request
	file, _ := os.Open("testfile-*.txt") // Replace with your temp file created in init()
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", file.Name())
	io.Copy(part, file)
	writer.Close()

	req, _ := http.NewRequest("POST", "/upload", body)
	req.Header.Set("Authorization", "Bearer "+getTestToken())
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Create a new response recorder to capture the output
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Check the status code is what we expect
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the response body
	expected := "File uploaded successfully"
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("Handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}

func TestDeleteFile(t *testing.T) {
	router := initRouter()

	req, _ := http.NewRequest("DELETE", "/delete/1", nil)
	req.Header.Set("Authorization", "Bearer "+getTestToken())

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Check the status code is what we expect
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check the response body
	expected := "File deleted successfully"
	if !strings.Contains(rr.Body.String(), expected) {
		t.Errorf("Handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}
