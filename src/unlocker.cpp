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
  bool cosmetic = false;  // display-only; can be turned off without losing
                          // any of the achievement/console behaviour
  bool fallback = false;  // only tried when the primary signature of the same
                          // name was not found at all
};

// Every primary signature below matches exactly once in the 4.5.0 and 4.5.1
// game executables (verified offline with tools/scan_test.exe); each fallback
// states its own coverage in the comments at the bottom of the table.
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
    // The same file-checksum compare as the first patch, but as a second,
    // independent caller: this one jumps over the "checksum modified" notice
    // in the version display when the checksums match. The workshop guide
    // ("How to enable Achievements with ANY mod") patches exactly this site by
    // hand as "48 8B 12 .. 85 C0" -> "33 C0"; it is the only other consumer of
    // the checksum verdict that is reachable from the version string, and
    // patching it changes nothing but which string gets built for the UI - the
    // game still computes and compares the real checksum, and the achievement
    // gate above is a different call site.
    //
    // The fourteen leading bytes pin the prologue of this caller: 4.4.1 spells
    // the achievement tooltip's checksum compare the same way (its only
    // difference there is "add rdx,0x320" in place of "lea rdx,[rbx+0x320]"),
    // so the bare pattern matches twice in that build. With the prologue the
    // site is unique in 4.4.1 and 4.5.0 alike; the unprefixed form stays as a
    // fallback for a build whose prologue drifts again.
    {"checksum warning (UI)",
     "48 8D 93 20 03 00 00 48 83 7A 18 10 72 03 "
     "48 8B 12 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8D",
     "48 8D 93 20 03 00 00 48 83 7A 18 10 72 03 "
     "48 8B 12 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 0F 84 ?? ?? ?? ?? 48 8D",
     29, "85 C0", "31 C0", true},
    // The notice's second caller: the version-number tooltip, built when the
    // mouse rests on the version text in the main menu. It asks
    // IsChecksumOk() and appends the localised "checksum modified" line when
    // that returns false - the words players actually read. The caller above
    // does not carry them: on 4.5 it only colours the digest next to the
    // version number, which is why this point was split off in r7. "or al,1"
    // pins the predicate's verdict to "ok" for this one display use, so the
    // tooltip stops claiming a problem the game no longer acts on (patch 1
    // keeps achievements enabled); no game state changes. Cosmetic for the
    // same reason as the notice.
    {"checksum warning (tooltip)",
     "48 8B 0D ?? ?? ?? ?? 48 81 C1 10 03 00 00 E8 ?? ?? ?? ?? 48 8B C8 "
     "E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 48 8D 15",
     "48 8B 0D ?? ?? ?? ?? 48 81 C1 10 03 00 00 E8 ?? ?? ?? ?? 48 8B C8 "
     "E8 ?? ?? ?? ?? 0C 01 0F 85 ?? ?? ?? ?? 48 8D 15",
     27, "84 C0", "0C 01", true},

    // ------------------------------------------------------------------
    // Fallback signatures. Each one is only consulted when the primary of the
    // same name is gone entirely, and each was verified to match exactly once
    // in 4.5.0 and 4.5.1 - a fallback can therefore never steal the site the
    // primary already pinned down, and a version that makes one ambiguous has
    // it refused by the same "must be unique" rule as everything else.
    //
    // The community patch database for this game keeps per-version patterns
    // and shows what actually moves between releases. For the checksum
    // compare it is the register of "mov esi,eax": 8B F8 on 4.1.6-4.3,
    // 8B {any} on the current line. The fallback below leaves that byte open
    // instead of pinning 8B F0, and still anchors on the lea/call pair in
    // front of it.
    {"mods / file checksum",
     "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? 85 C0 ?? 0F 94 ?? E8",
     "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B ?? 31 C0 ?? 0F 94 ?? E8",
     14, "85 C0", "31 C0", false, true},
    // Last resort for the same point: the tail alone, for a build where the
    // way the comparison is called changed but its result handling did not.
    {"mods / file checksum",
     "8B ?? 85 C0 ?? 0F 94 ?? E8", "8B ?? 31 C0 ?? 0F 94 ?? E8",
     2, "85 C0", "31 C0", false, true},

    // ------------------------------------------------------------------
    // 4.2.4 (Corvus, build 2025-12-10) fallbacks. The 4.2 line is older than
    // the 4.4/4.5 one but still what a rolled-back Steam depot serves, and it
    // moves four of the seven points. Two of them (the file-checksum compare
    // and the restore half of the ironman pair) already resolve through the
    // fallbacks above; the entries below cover the rest. Each was verified to
    // match exactly once in the 4.2.4 image and nowhere in 4.5.0/4.5.1, and a
    // fallback is only ever consulted when the primary of its own name is
    // gone, so none of this can change the builds verified above.
    //
    // These come before the looser per-point fallbacks further down on
    // purpose. On 4.2.4 the looser ironman pattern matches a second, unrelated
    // site as well; that second match is refused as ambiguous only while the
    // real site is still unpatched. Pinned entries first means the loose form
    // is never reached on this build, so a pre-patched 4.2.4 is reported as
    // "already patched" instead of being written to somewhere else.
    //
    // What moved in 4.2.4 (the field offsets of the smaller CGameState):
    //   * the "cheated" flag sits at +0xD4 instead of +0xFC, which moves both
    //     the console callback's store and the load-time mirror;
    //   * the ironman test reads [this+0x158] and [[gs+0x928]+0xEE] and tests
    //     r12b (4.5: +0x180, [+0x9B0]+0x11E, r15b); the three disps are left
    //     open with only their top byte pinned, the same shape the 4.4.1 pair
    //     further down uses, so a moved field offset keeps the site (scan_test's
    //     drift check C exercises exactly that byte);
    //   * the version-notice string lives at +0x280, and its prologue is
    //     "lea rdx,[rsi+0x280]" - the bare notice pattern further down matches
    //     twice there (notice + achievement tooltip, the 4.4.1 situation
    //     again), so only a prologue-pinned entry can pin the notice down.
    {"console use -> save flag",
     "C6 80 D4 00 00 00 01 E8", "C6 80 D4 00 00 00 00 E8",
     6, "01", "00", false, true},
    {"save load -> manager flag",
     "0F B6 8C 24 D4 00 00 00 88 88 83 00 00 00",
     "0F B6 8C 24 D4 00 00 00 90 90 90 90 90 90",
     8, "88 88 83 00 00 00", "90 90 90 90 90 90", false, true},
    {"ironman console (idle)",
     "45 38 A6 ?? ?? ?? 00 75 ?? 48 8B 05 ?? ?? ?? ?? 48 8B 88 ?? ?? ?? 00 "
     "44 38 A1 ?? ?? ?? 00 75 ?? 40 32 FF EB ?? 40 B7 01",
     "45 38 A6 ?? ?? ?? 00 75 ?? 48 8B 05 ?? ?? ?? ?? 48 8B 88 ?? ?? ?? 00 "
     "44 38 A1 ?? ?? ?? 00 75 ?? 40 32 FF EB ?? 40 B7 00",
     0x27, "01", "00", false, true},
    // The bare notice fallback further down cannot be reached on 4.2.4 (it
    // matches the tooltip as well); this one can, and it also makes a
    // statically pre-patched 4.2.4 report "already patched" instead of the
    // tooltip being patched in its place.
    {"checksum warning (UI)",
     "48 8D 96 80 02 00 00 48 83 7A 18 10 72 03 "
     "48 8B 12 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8D",
     "48 8D 96 80 02 00 00 48 83 7A 18 10 72 03 "
     "48 8B 12 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 0F 84 ?? ?? ?? ?? 48 8D",
     29, "85 C0", "31 C0", true, true},
    // 4.2.4's copy of the tooltip does not call a predicate at all: it reads
    // the version string through the application pointer ("mov rdx,[rip] /
    // add rdx,0x280") and compares it with the constant inline, which is the
    // second of the two sites the entry above had to tell apart. Its mismatch
    // block is the one that localises the "checksum modified" line, so forcing
    // "equal" here silences the tooltip exactly like the notice entry above
    // silences the version text.
    {"checksum warning (tooltip)",
     "48 8B 15 ?? ?? ?? ?? 48 81 C2 80 02 00 00 48 83 7A 18 10 72 03 "
     "48 8B 12 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8D",
     "48 8B 15 ?? ?? ?? ?? 48 81 C2 80 02 00 00 48 83 7A 18 10 72 03 "
     "48 8B 12 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 0F 84 ?? ?? ?? ?? 48 8D",
     36, "85 C0", "31 C0", true, true},

    // Same idea for the ironman console point: drop the leading
    // "cmp [r14+0x180], r15b / jne" (the multiplayer field offset is the part
    // most likely to move) and keep everything from the ironman test on.
    {"ironman console (idle)",
     "44 38 B9 1E 01 00 00 75 ?? 40 32 FF EB ?? 40 B7 01",
     "44 38 B9 1E 01 00 00 75 ?? 40 32 FF EB ?? 40 B7 00",
     16, "01", "00", false, true},
    {"ironman console (restore)",
     "80 B9 1E 01 00 00 00 75 ?? 32 DB EB ?? B3 01",
     "80 B9 1E 01 00 00 00 75 ?? 32 DB EB ?? B3 00",
     14, "01", "00", false, true},

    // ------------------------------------------------------------------
    // 4.4.1 (Pegasus, build 2026-06-10) fallbacks. Every site below is the
    // same code as its 4.5 counterpart, but three details moved: the manager
    // mirror is read off the stack ("[rsp+0xFC]", a SIB form) instead of
    // "[rsi+0xFC]", CGameState sits at +0x9C8 with the ironman byte at +0x116
    // (4.5: +0x9B0 / +0x11E), and spl stands in for r15b in the two ironman
    // tests. The primaries therefore miss 4.4.1 entirely; each of the three
    // entries below was verified to match exactly once in the 4.4.1 image and
    // nowhere in 4.5, so adding them cannot change 4.5 behaviour.
    {"save load -> manager flag",
     "0F B6 8C 24 FC 00 00 00 88 88 83 00 00 00",
     "0F B6 8C 24 FC 00 00 00 90 90 90 90 90 90",
     8, "88 88 83 00 00 00", "90 90 90 90 90 90", false, true},
    // The two ironman points with both structure offsets left open - only the
    // top byte of each disp is pinned, which is what keeps the pattern unique
    // in either build. Each lands on the same byte its 4.5 primary patches
    // (a "mov reg,1" immediate 0x10 / 0xE into the window).
    {"ironman console (idle)",
     "44 38 ?? ?? ?? 00 00 75 ?? 40 32 FF EB ?? 40 B7 01",
     "44 38 ?? ?? ?? 00 00 75 ?? 40 32 FF EB ?? 40 B7 00",
     16, "01", "00", false, true},
    {"ironman console (restore)",
     "80 B9 ?? ?? ?? 00 00 75 ?? 32 DB EB ?? B3 01",
     "80 B9 ?? ?? ?? 00 00 75 ?? 32 DB EB ?? B3 00",
     14, "01", "00", false, true},
    // The version-notice point without the prologue pinned onto the primary
    // above: covers a build whose prologue drifts but whose comparison does
    // not. On 4.4.1 and 4.2.4 this form matches twice - the tooltip caller and
    // the notice - and is refused by the uniqueness rule, which is exactly why
    // it can only ever be a fallback.
    {"checksum warning (UI)",
     "48 8B 12 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8D",
     "48 8B 12 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 0F 84 ?? ?? ?? ?? 48 8D",
     15, "85 C0", "31 C0", true, true},
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

// Locates and (optionally) applies one signature. Everything that decides
// whether a write happens lives here, so a fallback signature goes through
// exactly the same checks as a primary one.
SiteResult TrySite(uint8_t* base, size_t size, const PatchSpec& spec, bool write) {
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
    return s;
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
  return s;
}

const SiteResult* FindSite(const std::vector<SiteResult>& sites, const char* name) {
  for (const SiteResult& s : sites) {
    if (s.name == name) return &s;
  }
  return nullptr;
}

}  // namespace

ApplyResult ApplyAll(uint8_t* base, size_t size, bool write, bool include_cosmetic) {
  const size_t count = sizeof(kSpecs) / sizeof(kSpecs[0]);
  std::vector<SiteResult> results(count);
  std::vector<bool> filled(count, false);

  // A fallback is only worth trying when the primary of the same name found
  // nothing at all - never when it matched ambiguously, because the fallbacks
  // are looser than the primaries, not tighter.
  const auto primary_missing = [&](const char* name) {
    for (size_t j = 0; j < count; ++j) {
      if (kSpecs[j].fallback || std::strcmp(kSpecs[j].name, name) != 0) continue;
      return filled[j] && results[j].state == "signature not found";
    }
    return false;
  };

  ApplyResult r;
  for (int phase = 0; phase < 2; ++phase) {
    for (size_t i = 0; i < count; ++i) {
      const PatchSpec& spec = kSpecs[i];
      if (spec.fallback != (phase == 1)) continue;
      if (phase == 1 && !primary_missing(spec.name)) continue;

      SiteResult s;
      s.name = spec.name;
      if (spec.cosmetic && !include_cosmetic) {
        s.state = "skipped (cosmetic off)";
      } else {
        s = TrySite(base, size, spec, write);
        s.name = spec.name;
      }

      if (phase == 0) {
        results[i] = std::move(s);
        filled[i] = true;
        continue;
      }
      // Only a fallback that really pinned the site down replaces the
      // primary's "not found"; otherwise the primary's report stands, so the
      // log keeps exactly one line per patch point.
      if (s.patch_address == 0) continue;
      for (size_t j = 0; j < count; ++j) {
        if (!kSpecs[j].fallback && std::strcmp(kSpecs[j].name, spec.name) == 0) {
          r.notes.push_back(std::string(spec.name) +
                            ": primary signature gone, a fallback matched");
          results[j] = std::move(s);
          break;
        }
      }
    }
  }

  for (size_t i = 0; i < count; ++i) {
    if (!kSpecs[i].fallback) r.sites.push_back(std::move(results[i]));
  }

  // The achievements manager is reached through the call next to two of the
  // patch points above; look them up by name rather than by table position so
  // adding or reordering entries cannot silently change which site is used.
  const SiteResult* site_a = FindSite(r.sites, "mods / file checksum");
  const SiteResult* site_b2 = FindSite(r.sites, "console use -> manager flag");
  const uintptr_t match_a = site_a != nullptr ? site_a->match_address : 0;
  const uintptr_t match_b2 = site_b2 != nullptr ? site_b2->match_address : 0;

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
