// The actual achievement-unlock logic: the byte patches below (four that keep
// achievements enabled, two that unlock the console in ironman games, one that
// silences the now-untrue "checksum modified" notice) plus a monitor that keeps
// the achievements manager's flag bytes in the "allowed" state.
//
// Most patch points carry fallback signatures next to their primary one, so a
// game build that moved the code slightly still gets patched instead of
// silently losing the point. See the comment on kSpecs.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace unlocker {

struct SiteResult {
  std::string name;
  std::string state;        // "patched" / "would patch" / "already patched" / "not found" / ...
  uintptr_t match_address = 0;
  uintptr_t patch_address = 0;
};

struct ApplyResult {
  std::vector<SiteResult> sites;
  uintptr_t access_instance = 0;  // CAchievementsManager::AccessInstance()
  uintptr_t mgr_slot = 0;         // static pointer holding the manager instance
  std::string slot_source;        // which derivation produced mgr_slot, and
                                  // whether the two of them agreed
  std::vector<std::string> notes; // things worth saying out loud that are not
                                  // a state change, e.g. a fallback signature
                                  // standing in for a primary one
};

// Applies the byte patches inside the given image. With write=false nothing
// is modified; the report describes what would happen. Cosmetic patches are
// skipped when include_cosmetic is false; they are reported as such. Patch
// points whose primary signature is missing get one more chance through their
// fallback signatures before they are reported as not found.
ApplyResult ApplyAll(uint8_t* base, size_t size, bool write, bool include_cosmetic = true);

// Forces the manager flag bytes (80=0 81=1 82=1 83=0 84=0) every interval_ms,
// but only while the object at the slot still looks like the manager.
// Never returns.
void MonitorLoop(uintptr_t base, size_t size, uintptr_t mgr_slot, unsigned interval_ms);

}  // namespace unlocker
