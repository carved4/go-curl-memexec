#!/bin/bash

echo "Building C++ RunPE library..."

# Navigate to cpp directory
cd cpp || exit 1

# Check if we're on Windows
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" || "$OSTYPE" == "cygwin" ]]; then
    # Windows with MinGW or similar
    echo "Detected Windows environment"
    
    # Compile the C++ files into object files
    echo "Compiling selfhollow.cpp..."
    g++ -c selfhollow.cpp -o selfhollow.o -Wall -Wno-array-bounds -std=c++17 -O2
    if [ $? -ne 0 ]; then echo "Failed to compile selfhollow.cpp"; cd ..; exit 1; fi
    
    echo "Compiling relocate.cpp..."
    g++ -c relocate.cpp -o relocate.o -Wall -std=c++17 -O2
    if [ $? -ne 0 ]; then echo "Failed to compile relocate.cpp"; rm -f selfhollow.o; cd ..; exit 1; fi
    
    # Create static library from both object files
    echo "Creating static library librunpe.a..."
    ar rcs librunpe.a selfhollow.o relocate.o
    if [ $? -ne 0 ]; then echo "Failed to create static library"; rm -f selfhollow.o relocate.o; cd ..; exit 1; fi
    
    # Copy the library to the parent directory for Go to find it
    cp librunpe.a ..
    
    # Clean up temporary object files
    rm -f selfhollow.o relocate.o
else
    echo "Error: This library is only supported on Windows platforms"
    cd ..
    exit 1
fi

# Navigate back to the parent directory
cd ..

echo "C++ library build completed"
exit 0 