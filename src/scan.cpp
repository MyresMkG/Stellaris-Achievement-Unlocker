#include "scan.h"

#include <windows.h>

#include <cstring>
#include <vector>

namespace unlocker {

// A malformed pattern yields nothing at all: a silently truncated one would
// be shorter, less specific, and could match somewhere unintended.
std::vector<SigByte> ParseSig(const std::string& text) {
  const auto hex = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  std::vector<SigByte> out;
  size_t i = 0;
  while (i < text.size()) {
    while (i < text.size() && (text[i] == ' ' || text[i] == '\t')) ++i;
    if (i >= text.size()) break;
    if (text[i] == '?') {
      if (i + 1 >= text.size() || text[i + 1] != '?') return {};
      out.push_back(SigByte{0, true});
      i += 2;
      continue;
    }
    if (i + 1 >= text.size()) return {};
    const int hi = hex(text[i]);
    const int lo = hex(text[i + 1]);
    if (hi < 0 || lo < 0) return {};
    out.push_back(SigByte{static_cast<uint8_t>((hi << 4) | lo), false});
    i += 2;
  }
  return out;
}

std::vector<uint8_t*> ScanAll(uint8_t* base, size_t size, const std::vector<SigByte>& sig) {
  std::vector<uint8_t*> out;
  const size_t n = sig.size();
  if (n == 0 || size < n) return out;

  size_t anchor = 0;
  while (anchor < n && sig[anchor].wild) ++anchor;
  if (anchor == n) return out;  // all-wildcard pattern matches everywhere; refuse

  const size_t last = size - n;
  size_t i = 0;
  while (i <= last) {
    const uint8_t* hit = static_cast<const uint8_t*>(
        std::memchr(base + i + anchor, sig[anchor].value, size - (i + anchor)));
    if (hit == nullptr) break;
    const size_t cand = static_cast<size_t>(hit - base) - anchor;
    if (cand > last) break;
    bool ok = true;
    for (size_t k = 0; k < n; ++k) {
      if (!sig[k].wild && base[cand + k] != sig[k].value) {
        ok = false;
        break;
      }
    }
    if (ok) out.push_back(base + cand);
    i = cand + 1;
  }
  return out;
}

std::vector<uint8_t*> ScanAll(uint8_t* base, size_t size, const std::string& text) {
  return ScanAll(base, size, ParseSig(text));
}

// Writes n bytes at dst, temporarily lifting page protection. Writes of up
// to 8 bytes go out as one store whenever the address allows it, so a thread
// running through this code can never fetch a half-written instruction.
bool WriteBytes(void* dst, const void* src, size_t n) {
  if (n == 0) return true;

  // Two candidate windows, both 8 bytes wide: the naturally aligned block
  // holding the patch (a single aligned store is atomic by definition), or,
  // when the patch straddles two blocks, the window ending at the patch as
  // long as it stays inside one cache line (a store confined to a cache line
  // is never torn on any hardware this runs on).
  uintptr_t window = 0;
  if (n <= sizeof(uint64_t)) {
    const uintptr_t at = reinterpret_cast<uintptr_t>(dst);
    const uintptr_t first = at & ~static_cast<uintptr_t>(7);
    const uintptr_t last = (at + n + 7) & ~static_cast<uintptr_t>(7);
    if (last - first == sizeof(uint64_t)) {
      window = first;
    } else if (at + n >= sizeof(uint64_t)) {
      const uintptr_t loose = at + n - sizeof(uint64_t);
      if ((loose >> 6) == ((loose + 7) >> 6)) window = loose;
    }
  }

  void* const area = window != 0 ? reinterpret_cast<void*>(window) : dst;
  const size_t area_n = window != 0 ? sizeof(uint64_t) : n;

  DWORD old = 0;
  if (!VirtualProtect(area, area_n, PAGE_EXECUTE_READWRITE, &old)) return false;
  if (window != 0) {
    uint64_t merged = 0;
    std::memcpy(&merged, reinterpret_cast<const void*>(window), sizeof(merged));
    std::memcpy(reinterpret_cast<uint8_t*>(&merged) +
                    (reinterpret_cast<uintptr_t>(dst) - window),
                src, n);
    *reinterpret_cast<volatile uint64_t*>(window) = merged;
  } else {
    std::memcpy(dst, src, n);
  }
  VirtualProtect(area, area_n, old, &old);
  FlushInstructionCache(GetCurrentProcess(), dst, n);
  return true;
}

bool MainModuleInfo(uintptr_t* base, size_t* size) {
  HMODULE mod = GetModuleHandleW(nullptr);
  if (mod == nullptr) return false;
  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mod);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
      reinterpret_cast<const uint8_t*>(mod) + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
  *base = reinterpret_cast<uintptr_t>(mod);
  *size = nt->OptionalHeader.SizeOfImage;
  return true;
}

}  // namespace unlocker
