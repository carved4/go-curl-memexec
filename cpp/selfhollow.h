#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Returns true on success, false on error. On failure GetLastError() is set.
bool SelfHollowStrict(unsigned char* payload, size_t payload_size);


#ifdef __cplusplus
}
#endif