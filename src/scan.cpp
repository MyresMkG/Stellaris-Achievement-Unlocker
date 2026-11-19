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

namespace {

// One naturally aligned 8-byte read-modify-write store. It carries the n patch
// bytes that belong at dst (which must lie inside the block) and leaves every
// other byte of the block alone. A single aligned store of this width is atomic,
// so a thread fetching this code can never observe half of it.
bool StoreBlock(uintptr_t block, uintptr_t dst, const uint8_t* src, size_t n) {
  DWORD old = 0;
  if (!VirtualProtect(reinterpret_cast<void*>(block), sizeof(uint64_t),
                      PAGE_EXECUTE_READWRITE, &old)) {
    return false;
  }
  uint64_t merged = 0;
  std::memcpy(&merged, reinterpret_cast<const void*>(block), sizeof(merged));
  std::memcpy(reinterpret_cast<uint8_t*>(&merged) + (dst - block), src, n);
  *reinterpret_cast<volatile uint64_t*>(block) = merged;
  VirtualProtect(reinterpret_cast<void*>(block), sizeof(uint64_t), old, &old);
  FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(dst), n);
  return true;
}

}  // namespace

// Writes n bytes at dst, temporarily lifting page protection. A patch that fits
// in one naturally aligned 8-byte block goes out as a single store, which is
// atomic by definition; one that straddles two blocks but stays inside a cache
// line goes out as one store too (a store confined to a cache line is never torn
// on any hardware this runs on).
//
// A patch that crosses a cache line cannot be written atomically at all, so it
// is split at the 8-byte boundaries and written from its end downwards: every
// store is still atomic, the first byte of the patched instruction lands last,
// and the only thing another thread can catch is the seam between two blocks. No
// patch point in kSpecs needs that path - the widest one is two bytes, which
// always fits a block - and a point that did would want a shorter encoding
// rather than a cleverer writer.
bool WriteBytes(void* dst, const void* src, size_t n) {
  if (n == 0) return true;

  const uintptr_t at = reinterpret_cast<uintptr_t>(dst);
  const uint8_t* const bytes = static_cast<const uint8_t*>(src);

  if (n <= sizeof(uint64_t)) {
    const uintptr_t first = at & ~static_cast<uintptr_t>(7);
    const uintptr_t last = (at + n + 7) & ~static_cast<uintptr_t>(7);
    if (last - first == sizeof(uint64_t)) return StoreBlock(first, at, bytes, n);
    if (at + n >= sizeof(uint64_t)) {
      const uintptr_t loose = at + n - sizeof(uint64_t);
      if ((loose >> 6) == ((loose + 7) >> 6)) return StoreBlock(loose, at, bytes, n);
    }
  }

  for (uintptr_t end = at + n; end > at;) {
    uintptr_t block = (end - 1) & ~static_cast<uintptr_t>(7);
    uintptr_t from = block > at ? block : at;
    if (end - from > sizeof(uint64_t)) {
      from = end - sizeof(uint64_t);
      block = from & ~static_cast<uintptr_t>(7);
    }
    if (!StoreBlock(block, from, bytes + (from - at), static_cast<size_t>(end - from))) {
      return false;
    }
    end = from;
  }
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
