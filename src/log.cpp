#include "log.h"

#include <windows.h>

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>

namespace unlocker {
namespace {

std::mutex g_mutex;
std::string g_path;
FILE* g_file = nullptr;
std::atomic<DWORD> g_start{0};

// UTF-8 view of a wide path, for messages only.
std::string Narrow(const std::wstring& wide) {
  if (wide.empty()) return std::string();
  const int n = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
  if (n <= 0) return std::string();
  std::string out(static_cast<size_t>(n - 1), '\0');
  WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, out.data(), n, nullptr, nullptr);
  return out;
}

}  // namespace

const std::string& LogPath() { return g_path; }

void LogInit(void* module_handle) {
  std::lock_guard<std::mutex> lock(g_mutex);
  g_start.store(GetTickCount());

  // A truncated path would name a directory that does not exist and lose the
  // whole log, so leave room and fall back to a relative name instead. The
  // chosen path is written into the log itself.
  wchar_t module[1024] = {0};
  const DWORD n =
      GetModuleFileNameW(static_cast<HMODULE>(module_handle), module, ARRAYSIZE(module));
  if (n == 0 || n >= ARRAYSIZE(module)) {
    wcscpy(module, L"achievement_unlocker");
  }
  std::wstring base(module);
  const size_t slash = base.find_last_of(L"\\/");
  const std::wstring dir =
      (slash == std::wstring::npos) ? std::wstring(L".") : base.substr(0, slash);
  const std::wstring path = dir + L"\\achievement_unlocker.log";
  g_path = Narrow(path);

  g_file = _wfopen(path.c_str(), L"w");
  if (g_file != nullptr) {
    fprintf(g_file, "achievement_unlocker log\n");
    fprintf(g_file, "log file: %s\n", LogPath().c_str());
    fflush(g_file);
  }
}

void Log(const char* fmt, ...) {
  char body[2048];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(body, sizeof(body), fmt, ap);
  va_end(ap);

  const DWORD now = GetTickCount();
  const DWORD start = g_start.load();  // LogInit can run on another thread
  char line[2200];
  snprintf(line, sizeof(line), "[%6lu.%03lu] %s\n",
           static_cast<unsigned long>((now - start) / 1000),
           static_cast<unsigned long>((now - start) % 1000), body);

  OutputDebugStringA(line);
  std::lock_guard<std::mutex> lock(g_mutex);
  if (g_file != nullptr) {
    fputs(line, g_file);
    fflush(g_file);
  }
}

}  // namespace unlocker
