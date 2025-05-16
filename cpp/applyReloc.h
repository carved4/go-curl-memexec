#pragma once
#include <windows.h>
#include <stdint.h>

bool applyReloc(uint64_t newBase, uint64_t oldBase, void* modulePtr, SIZE_T moduleSize); 