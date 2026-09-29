// Logging: a plain text log next to the DLL plus OutputDebugString, so the
// unlocker can be diagnosed without a debugger attached.
#pragma once

#include <string>

namespace unlocker {

// Creates/truncates the log and records the module path.
void LogInit(void* module_handle);

// printf-style line, prefixed with seconds since process start.
void Log(const char* fmt, ...);

// Path of the log file (empty before LogInit).
const std::string& LogPath();

}  // namespace unlocker
