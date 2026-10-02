// DLL entry point.
//
// Everything interesting happens on a worker thread: DllMain runs under the
// loader lock, and touching game memory there could deadlock the game's own
// startup.
#include <windows.h>

#include <string>

#include "log.h"
#include "scan.h"
#include "unlocker.h"

namespace {

HMODULE g_self = nullptr;

// Identifies the build in the first log line, so a log file can be traced
// back to the DLL that produced it.
constexpr char kBuild[] = "r3 2026-10-02";

// When a file with this name sits next to the DLL, the unlocker only resolves
// and reports; it writes nothing and does not touch the flags.
bool ProbeOnly() {
  wchar_t path[1024] = {0};
  const DWORD n = GetModuleFileNameW(g_self, path, ARRAYSIZE(path));
  if (n == 0 || n >= ARRAYSIZE(path)) {
    unlocker::Log("cannot determine my own path; probe-only mode cannot be checked");
    return false;
  }
  const std::wstring file(path, n);
  const size_t slash = file.find_last_of(L"\\/");
  const std::wstring dir =
      (slash == std::wstring::npos) ? std::wstring(L".") : file.substr(0, slash);
  const std::wstring flag = dir + L"\\achievement_unlocker_probe_only.txt";
  return GetFileAttributesW(flag.c_str()) != INVALID_FILE_ATTRIBUTES;
}

DWORD WINAPI Worker(void*) {
  unlocker::LogInit(g_self);
  unlocker::Log("achievement_unlocker attaching (%s)", kBuild);

  uintptr_t base = 0;
  size_t size = 0;
  if (!unlocker::MainModuleInfo(&base, &size)) {
    unlocker::Log("cannot locate the main module; nothing to do");
    return 0;
  }
  unlocker::Log("main module at %p, image size 0x%zX",
                reinterpret_cast<void*>(base), size);

  const bool probe = ProbeOnly();
  if (probe) {
    unlocker::Log("probe-only mode: resolving and reporting, nothing will be written");
  }

  const unlocker::ApplyResult r =
      unlocker::ApplyAll(reinterpret_cast<uint8_t*>(base), size, !probe);
  for (const unlocker::SiteResult& s : r.sites) {
    if (s.patch_address != 0) {
      unlocker::Log("%-26s %-16s patch byte rva 0x%zX",
                    s.name.c_str(), s.state.c_str(),
                    static_cast<size_t>(s.patch_address - base));
    } else {
      unlocker::Log("%-26s %s", s.name.c_str(), s.state.c_str());
    }
  }

  if (r.mgr_slot != 0) {
    unlocker::Log("achievements manager resolved: AccessInstance rva 0x%zX, slot rva 0x%zX (%s)",
                  static_cast<size_t>(r.access_instance - base),
                  static_cast<size_t>(r.mgr_slot - base), r.slot_source.c_str());
  } else {
    unlocker::Log("could not resolve the achievements manager (%s); only the byte patches remain in effect",
                  r.slot_source.c_str());
  }

  if (probe) {
    unlocker::Log("probe finished");
    return 0;
  }
  if (r.mgr_slot == 0) return 0;

  unlocker::MonitorLoop(base, size, r.mgr_slot, 200);
  return 0;
}

}  // namespace

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    g_self = instance;
    DisableThreadLibraryCalls(instance);
    HANDLE thread = CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);
    if (thread != nullptr) CloseHandle(thread);
  }
  return TRUE;
}
