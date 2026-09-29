// Byte-pattern scanning and tiny memory helpers shared by the unlocker and
// its offline test tool.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace unlocker {

struct SigByte {
  uint8_t value = 0;
  bool wild = false;
};

// Parses a pattern such as "48 8B 05 ?? ?? ?? ??" (whitespace separated,
// case insensitive). "??" matches any byte. A malformed pattern parses to no
// bytes at all, so it can never turn into a shorter, less specific pattern.
std::vector<SigByte> ParseSig(const std::string& text);

// Addresses of every match of sig inside [base, base + size).
std::vector<uint8_t*> ScanAll(uint8_t* base, size_t size, const std::vector<SigByte>& sig);
std::vector<uint8_t*> ScanAll(uint8_t* base, size_t size, const std::string& text);

// Writes n bytes at dst, temporarily lifting page protection. Writes of up
// to 8 bytes go out as a single store where the address allows it, so no
// other thread can ever observe half of the patch.
bool WriteBytes(void* dst, const void* src, size_t n);

// Base and image size of this process' own main module (stellaris.exe).
bool MainModuleInfo(uintptr_t* base, size_t* size);

}  // namespace unlocker
