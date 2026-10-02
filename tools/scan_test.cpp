// Offline verification for achievement_unlocker.dll.
//
// Maps a stellaris.exe file the same way the loader would (every section at
// its RVA), then runs the unlocker's own scanning and patching code over it.
// This proves the signatures and patch offsets against a real game build
// without launching the game.
//
// usage:
//   scan_test <path-to-stellaris.exe>
//
// exits 0 when every site is found, patched and re-detected as patched, and
// the achievements manager slot resolves.
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "../src/scan.h"
#include "../src/unlocker.h"

namespace {

bool MapImage(const char* path, std::vector<uint8_t>* image, size_t* size) {
  FILE* f = std::fopen(path, "rb");
  if (f == nullptr) {
    std::printf("cannot open %s\n", path);
    return false;
  }
  std::fseek(f, 0, SEEK_END);
  const long len = std::ftell(f);
  std::fseek(f, 0, SEEK_SET);
  if (len <= 0) {
    std::fclose(f);
    return false;
  }
  std::vector<uint8_t> file(static_cast<size_t>(len));
  const size_t got = std::fread(file.data(), 1, file.size(), f);
  std::fclose(f);
  if (got != file.size()) return false;

  // The tool is pointed at arbitrary files, so every header access below is
  // bounds checked: a truncated or hand-made PE must not read or write
  // outside the buffers.
  if (file.size() < sizeof(IMAGE_DOS_HEADER)) return false;
  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(file.data());
  if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) return false;
  const size_t nt_at = static_cast<size_t>(dos->e_lfanew);
  if (nt_at > file.size() || file.size() - nt_at < sizeof(IMAGE_NT_HEADERS64)) return false;
  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(file.data() + nt_at);
  if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

  const size_t image_size = nt->OptionalHeader.SizeOfImage;
  if (image_size < nt->OptionalHeader.SizeOfHeaders) return false;
  image->assign(image_size, 0);
  size_t headers = nt->OptionalHeader.SizeOfHeaders;
  if (headers > file.size()) headers = file.size();
  if (headers > image_size) headers = image_size;
  std::memcpy(image->data(), file.data(), headers);

  const auto* sec = IMAGE_FIRST_SECTION(nt);
  const size_t sec_at = static_cast<size_t>(
      reinterpret_cast<const uint8_t*>(sec) - file.data());
  const size_t nsec = nt->FileHeader.NumberOfSections;
  if (nsec > (file.size() - sec_at) / sizeof(IMAGE_SECTION_HEADER)) return false;
  for (size_t i = 0; i < nsec; ++i) {
    const auto& s = sec[i];
    if (s.SizeOfRawData == 0 || s.PointerToRawData == 0) continue;
    size_t n = s.SizeOfRawData;
    if (s.Misc.VirtualSize != 0 && s.Misc.VirtualSize < n) n = s.Misc.VirtualSize;
    if (s.PointerToRawData + n > file.size()) continue;
    if (s.VirtualAddress + n > image_size) continue;
    std::memcpy(image->data() + s.VirtualAddress, file.data() + s.PointerToRawData, n);
  }
  *size = image_size;
  return true;
}

void Report(const char* title, const unlocker::ApplyResult& r, uintptr_t base) {
  std::printf("%s\n", title);
  for (const unlocker::SiteResult& s : r.sites) {
    if (s.patch_address != 0) {
      std::printf("  %-28s %-18s patch byte rva 0x%zX\n", s.name.c_str(), s.state.c_str(),
                  static_cast<size_t>(s.patch_address - base));
    } else {
      std::printf("  %-28s %s\n", s.name.c_str(), s.state.c_str());
    }
  }
  std::printf("  %-28s rva 0x%zX\n", "AccessInstance",
              r.access_instance ? static_cast<size_t>(r.access_instance - base) : 0);
  std::printf("  %-28s rva 0x%zX (%s)\n\n", "manager slot",
              r.mgr_slot ? static_cast<size_t>(r.mgr_slot - base) : 0,
              r.slot_source.c_str());
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::printf("usage: scan_test <path-to-stellaris.exe>\n");
    return 2;
  }

  std::vector<uint8_t> image;
  size_t size = 0;
  if (!MapImage(argv[1], &image, &size)) {
    std::printf("cannot map %s as a 64-bit PE image\n", argv[1]);
    return 2;
  }
  const uintptr_t base = reinterpret_cast<uintptr_t>(image.data());
  std::printf("file: %s\nimage size 0x%zX\n\n", argv[1], size);

  bool ok = true;

  const unlocker::ApplyResult dry = unlocker::ApplyAll(image.data(), image.size(), false);
  Report("pass 1: dry run (nothing written)", dry, base);
  for (const unlocker::SiteResult& s : dry.sites) {
    if (s.state != "would patch") ok = false;
  }
  if (dry.mgr_slot == 0) ok = false;

  const unlocker::ApplyResult done = unlocker::ApplyAll(image.data(), image.size(), true);
  Report("pass 2: applied", done, base);
  for (const unlocker::SiteResult& s : done.sites) {
    if (s.state != "patched") ok = false;
  }

  const unlocker::ApplyResult again = unlocker::ApplyAll(image.data(), image.size(), false);
  Report("pass 3: re-scan (idempotency)", again, base);
  for (const unlocker::SiteResult& s : again.sites) {
    if (s.state != "already patched") ok = false;
  }
  if (again.mgr_slot == 0) ok = false;

  std::printf("%s\n", ok ? "OK" : "FAILED");
  return ok ? 0 : 1;
}
