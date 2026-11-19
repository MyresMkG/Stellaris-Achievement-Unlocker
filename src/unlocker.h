// The actual achievement-unlock logic: the byte patches below (four that keep
// achievements enabled, two that unlock the console in ironman games, two that
// silence the now-untrue "checksum modified" notice - one in the version text,
// one in its tooltip) plus a monitor that keeps the achievements manager's
// flag bytes in the "allowed" state.
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

// The old-save repair (r9): one call site in the game's frame update is
// retargeted so that a save which carried no active achievement list gets that
// list rebuilt from the achievement catalogue (see unlocker.cpp).
struct HookResult {
  std::string state;      // "hooked" / "would hook" / "already hooked" / a reason
  uintptr_t update = 0;   // CAchievementsManager::Update(CAchievementsManager*, CEventScope*)
  uintptr_t on_game_start = 0;  // CAchievementsManager::OnGameStart(CAchievementsManager*, CEventScope*)
  uintptr_t call_site = 0;      // the call instruction that is retargeted
  uintptr_t hook_fn = 0;        // our own thunk, for the offline stub check
  uintptr_t stub = 0;           // the "mov rax, hook; jmp rax" page, once installed
};

struct ApplyResult {
  std::vector<SiteResult> sites;
  HookResult hook;
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
