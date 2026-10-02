#include "unlocker.h"

#include <windows.h>

#include <cstdio>
#include <cstring>

#include "log.h"
#include "scan.h"

namespace unlocker {
namespace {

struct PatchSpec {
  const char* name;
  const char* sig_before;
  const char* sig_after;
  size_t delta;
  const char* from;
  const char* to;
};

// Every signature below matches exactly once in the 4.5.0 and 4.5.1 game
// executables (verified offline with tools/scan_test.exe).
const PatchSpec kSpecs[] = {
    // game-file checksum compare: turn "test eax,eax" into "xor eax,eax" so
    // the "checksum modified" verdict never sticks (mods no longer disable
    // achievements).
    {"mods / file checksum",
     "8B F0 85 C0 41 0F 94 C6", "8B F0 31 C0 41 0F 94 C6", 2, "85 C0", "31 C0"},
    // a successful console command no longer writes the "cheated" flag into
    // the current game state (and thus into save games).
    {"console use -> save flag",
     "C6 80 FC 00 00 00 01 E8", "C6 80 FC 00 00 00 00 E8", 6, "01", "00"},
    // ... nor into the achievements manager. The "after" pattern stays
    // inside the patched instruction on purpose: pinning bytes of the next
    // instruction would report an already patched image as "not found" if
    // that instruction ever changes shape.
    {"console use -> manager flag",
     "C6 80 83 00 00 00 01", "C6 80 83 00 00 00 00", 6, "01", "00"},
    // loading a save that was marked "cheated" no longer copies that flag
    // into the achievements manager.
    {"save load -> manager flag",
     "0F B6 8E FC 00 00 00 88 88 83 00 00 00",
     "0F B6 8E FC 00 00 00 90 90 90 90 90 90", 7, "88 88 83 00 00 00",
     "90 90 90 90 90 90"},
    // Ironman console lock. Every frame the game derives "console disabled"
    // from the ironman flag ([[CGameState+0x9B0]+0x11E]) and stores the result
    // both into the console command manager and into the console's
    // stay-hidden latch. Forcing the derived value to 0 makes the console
    // open and run commands in ironman games; the is_ironman trigger itself
    // is deliberately left alone. The patched byte is the immediate of
    // "mov dil,1" in CGameIdler::Idle, the branch taken when the game is
    // ironman or multiplayer.
    {"ironman console (idle)",
     "45 38 BE 80 01 00 00 75 ?? 48 8B 05 ?? ?? ?? ?? 48 8B 88 B0 09 00 00 "
     "44 38 B9 1E 01 00 00 75 ?? 40 32 FF EB ?? 40 B7 01",
     "45 38 BE 80 01 00 00 75 ?? 48 8B 05 ?? ?? ?? ?? 48 8B 88 B0 09 00 00 "
     "44 38 B9 1E 01 00 00 75 ?? 40 32 FF EB ?? 40 B7 00",
     0x27, "01", "00"},
    // The same derived value in CGameIdler::RestoreDeviceObjects ("mov bl,1").
    // bl is dead right after the store there, so the patch has no other
    // effect.
    {"ironman console (restore)",
     "80 BE 80 01 00 00 00 75 ?? 48 8B 05 ?? ?? ?? ?? 48 8B 88 B0 09 00 00 "
     "80 B9 1E 01 00 00 00 75 ?? 32 DB EB ?? B3 01",
     "80 BE 80 01 00 00 00 75 ?? 48 8B 05 ?? ?? ?? ?? 48 8B 88 B0 09 00 00 "
     "80 B9 1E 01 00 00 00 75 ?? 32 DB EB ?? B3 00",
     0x25, "01", "00"},
};

// CAchievementsManager::AccessInstance() allocates 0x88 bytes and starts with
// a load of its singleton pointer. This signature both locates that load and
// verifies what the call sites below found.
const char kMgrSlotSig[] =
    "48 8B 05 ?? ?? ?? ?? 48 85 C0 0F 85 ?? ?? ?? ?? B9 88 00 00 00 E8";

std::vector<uint8_t> Bytes(const char* hex) {
  std::vector<uint8_t> out;
  for (const SigByte& b : ParseSig(hex)) out.push_back(b.value);
  return out;
}

bool InRange(uintptr_t p, uintptr_t base, size_t size) {
  return p >= base && p - base < size;
}

// Target of the call at p, or 0 when p is not a complete call instruction
// inside [base, base + size).
uintptr_t CallTarget(uint8_t* p, uintptr_t base, size_t size) {
  if (!InRange(reinterpret_cast<uintptr_t>(p), base, size)) return 0;
  if (size - (reinterpret_cast<uintptr_t>(p) - base) < 5) return 0;
  if (*p != 0xE8) return 0;
  int32_t disp = 0;
  std::memcpy(&disp, p + 1, sizeof(disp));
  return reinterpret_cast<uintptr_t>(p) + 5 + static_cast<int64_t>(disp);
}

uintptr_t FindMovRaxRip(uint8_t* p, size_t max) {
  for (size_t i = 0; i + 7 <= max; ++i) {
    if (p[i] == 0x48 && p[i + 1] == 0x8B && p[i + 2] == 0x05) {
      return reinterpret_cast<uintptr_t>(p + i);
    }
  }
  return 0;
}

// True when the whole wildcard pattern matches at p, and p lies inside the
// image. Used to tell a real manager load from a lookalike.
bool MatchesAt(uint8_t* p, uintptr_t base, size_t size, const char* sig) {
  const std::vector<SigByte> pat = ParseSig(sig);
  const uintptr_t at = reinterpret_cast<uintptr_t>(p);
  if (pat.empty() || !InRange(at, base, size)) return false;
  if (size - (at - base) < pat.size()) return false;
  for (size_t k = 0; k < pat.size(); ++k) {
    if (!pat[k].wild && p[k] != pat[k].value) return false;
  }
  return true;
}

}  // namespace

ApplyResult ApplyAll(uint8_t* base, size_t size, bool write) {
  ApplyResult r;
  uintptr_t match_a = 0;   // spec 0: checksum compare
  uintptr_t match_b2 = 0;  // spec 2: console -> manager store

  for (size_t i = 0; i < sizeof(kSpecs) / sizeof(kSpecs[0]); ++i) {
    const PatchSpec& spec = kSpecs[i];
    const std::vector<uint8_t> from = Bytes(spec.from);
    const std::vector<uint8_t> to = Bytes(spec.to);
    const size_t sig_len = ParseSig(spec.sig_before).size();

    SiteResult s;
    s.name = spec.name;

    // A hand-edited signature that no longer lines up must not end up as a
    // patch at some other address (or as a silent no-op write).
    if (from.empty() || from.size() != to.size() ||
        spec.delta + to.size() > sig_len) {
      s.state = "bad patch spec";
      r.sites.push_back(std::move(s));
      continue;
    }

    std::vector<uint8_t*> hits = ScanAll(base, size, spec.sig_before);
    if (hits.size() == 1) {
      uint8_t* at = hits[0] + spec.delta;
      s.match_address = reinterpret_cast<uintptr_t>(hits[0]);
      s.patch_address = reinterpret_cast<uintptr_t>(at);
      if (std::memcmp(at, from.data(), from.size()) != 0) {
        s.state = "unexpected bytes";
      } else if (!write) {
        s.state = "would patch";
      } else if (WriteBytes(at, to.data(), to.size())) {
        s.state = "patched";
      } else {
        s.state = "write failed";
      }
    } else if (hits.empty()) {
      std::vector<uint8_t*> done = ScanAll(base, size, spec.sig_after);
      if (done.size() == 1) {
        s.state = "already patched";
        s.match_address = reinterpret_cast<uintptr_t>(done[0]);
        s.patch_address = s.match_address + spec.delta;
      } else if (done.empty()) {
        s.state = "signature not found";
      } else {
        // The patched form is there, but more than once: the site cannot be
        // pinned down, which is not the same as "not found".
        s.state = "already patched (not unique)";
      }
    } else {
      s.state = "signature found more than once";
    }

    if (i == 0) match_a = s.match_address;
    if (i == 2) match_b2 = s.match_address;
    r.sites.push_back(std::move(s));
  }

  const uintptr_t image_base = reinterpret_cast<uintptr_t>(base);

  // Resolve CAchievementsManager::AccessInstance() from the call site inside
  // the checksum patch, falling back to the one next to the console store.
  if (match_a != 0) {
    const uintptr_t t = CallTarget(reinterpret_cast<uint8_t*>(match_a + 8), image_base, size);
    if (InRange(t, image_base, size)) r.access_instance = t;
  }
  if (r.access_instance == 0 && match_b2 != 0) {
    const uintptr_t t = CallTarget(reinterpret_cast<uint8_t*>(match_b2 - 5), image_base, size);
    if (InRange(t, image_base, size)) r.access_instance = t;
  }

  // The static slot holding the manager instance is loaded at the top of
  // AccessInstance(). Two independent derivations exist - the call site and
  // the wildcard signature - and the slot is only trusted when they agree,
  // or when the single candidate matches the signature's shape exactly.
  // Forcing flags in an unrelated object every 200 ms is the one failure this
  // code cannot recover from, so refusing is the safe direction.
  uintptr_t mov_call = 0;
  if (r.access_instance != 0 &&
      size - (r.access_instance - image_base) >= 0x20) {
    mov_call = FindMovRaxRip(reinterpret_cast<uint8_t*>(r.access_instance), 0x20);
  }
  uintptr_t mov_sig = 0;
  {
    const std::vector<uint8_t*> hits = ScanAll(base, size, kMgrSlotSig);
    if (hits.size() == 1) mov_sig = reinterpret_cast<uintptr_t>(hits[0]);
  }

  uintptr_t mov = 0;
  if (mov_call != 0 && mov_sig != 0) {
    if (mov_call == mov_sig) {
      mov = mov_call;
      r.slot_source = "call site + signature agree";
    } else {
      char buf[96];
      std::snprintf(buf, sizeof(buf),
                    "derivations disagree (call site 0x%zX, signature 0x%zX)",
                    static_cast<size_t>(mov_call - image_base),
                    static_cast<size_t>(mov_sig - image_base));
      r.slot_source = buf;
    }
  } else if (mov_call != 0) {
    if (MatchesAt(reinterpret_cast<uint8_t*>(mov_call), image_base, size, kMgrSlotSig)) {
      mov = mov_call;
      r.slot_source = "call site only, signature shape ok";
    } else {
      r.slot_source = "call site does not look like the manager load";
    }
  } else if (mov_sig != 0) {
    mov = mov_sig;
    r.slot_source = "signature only";
  } else {
    r.slot_source = "not found";
  }
  if (mov != 0) {
    int32_t disp = 0;
    std::memcpy(&disp, reinterpret_cast<uint8_t*>(mov) + 3, sizeof(disp));
    const uintptr_t slot = mov + 7 + static_cast<int64_t>(disp);
    if (InRange(slot, image_base, size)) {
      r.mgr_slot = slot;
    } else {
      r.slot_source = "slot address outside the image";
    }
  }
  return r;
}

void MonitorLoop(uintptr_t base, size_t size, uintptr_t mgr_slot, unsigned interval_ms) {
  Log("monitor: manager slot %p, every %u ms",
      reinterpret_cast<void*>(mgr_slot), interval_ms);
  uint8_t last[5];
  std::memset(last, 0xFF, sizeof(last));
  bool waited = false;
  bool not_manager = false;
  bool reported_good = false;

  for (;;) {
    Sleep(interval_ms);
    uint8_t* mgr = *reinterpret_cast<uint8_t**>(mgr_slot);
    if (mgr == nullptr) {
      if (!waited) {
        Log("manager not created yet; waiting");
        waited = true;
      }
      continue;
    }
    if (waited) {
      Log("manager created at %p", mgr);
      waited = false;
    }

    // Write only to an object that can still be recognised as the manager:
    // its vtable lives in the game image, and the four flags the game itself
    // reads as booleans hold 0 or 1. Anything else means the slot moved to
    // some other object and a blind write would corrupt it.
    const uintptr_t vtbl = *reinterpret_cast<uintptr_t*>(mgr);
    const uint8_t cur[5] = {mgr[0x80], mgr[0x81], mgr[0x82], mgr[0x83], mgr[0x84]};
    bool suspicious = !InRange(vtbl, base, size);
    for (int k = 1; k < 5 && !suspicious; ++k) suspicious = cur[k] > 1;
    if (suspicious) {
      if (!not_manager) {
        Log("object at %p is not recognisable as the achievements manager "
            "(vtable %p, flags 80=%u 81=%u 82=%u 83=%u 84=%u); not writing",
            mgr, reinterpret_cast<void*>(vtbl), cur[0], cur[1], cur[2], cur[3], cur[4]);
        not_manager = true;
      }
      continue;
    }
    not_manager = false;

    if (cur[0] == 0 && cur[1] == 1 && cur[2] == 1 && cur[3] == 0 && cur[4] == 0) {
      if (!reported_good) {
        Log("flags already good at %p (80=0 81=1 82=1 83=0 84=0)", mgr);
        reported_good = true;
      }
      std::memcpy(last, cur, sizeof(cur));
      continue;
    }
    if (std::memcmp(cur, last, sizeof(cur)) != 0) {
      Log("flags at %p were 80=%u 81=%u 82=%u 83=%u 84=%u -> forcing 0/1/1/0/0",
          mgr, cur[0], cur[1], cur[2], cur[3], cur[4]);
    }
    std::memcpy(last, cur, sizeof(cur));
    mgr[0x80] = 0;
    mgr[0x81] = 1;
    mgr[0x82] = 1;
    mgr[0x83] = 0;
    mgr[0x84] = 0;
  }
}

}  // namespace unlocker
