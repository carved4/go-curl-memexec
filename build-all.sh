#!/bin/bash

echo "=== go http memexec builder ==="

# Make sure the script is executable
chmod +x build.sh

# Build the C++ library first
echo "Building C++ library..."
# Note: ./build.sh must be updated to compile and link cpp/relocate.cpp
# alongside cpp/selfhollow.cpp for the relocation feature.
./build.sh
if [ $? -ne 0 ]; then
    echo "Failed to build C++ library."
    exit 1
fi

# Now build the Go application
echo "Building Go application..."
go mod tidy
go build -ldflags="-s -w" -trimpath -o go-http-memexec.exe
if [ $? -ne 0 ]; then
    echo "Failed to build Go application."
    exit 1
fi

echo "Build completed successfully!"
echo "Output binary: go-http-memexec.exe"

