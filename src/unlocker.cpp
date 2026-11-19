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
    // Loading a save that was marked "cheated" no longer copies that flag into
    // the achievements manager. The store is skipped with a two-byte "jmp +4"
    // instead of being overwritten with six nops: two bytes always fit inside
    // one naturally aligned 8-byte block, so the write is a single atomic store
    // on every build. The six-byte form straddled an 8-byte block boundary -
    // and on 4.5.2/4.5.3 a 64-byte cache line as well - which pushed the write
    // onto the plain memcpy path that WriteBytes exists to avoid. The bytes the
    // jump skips stay untouched, so the idempotency pattern stops right after
    // them instead of pinning them.
    {"save load -> manager flag",
     "0F B6 8E FC 00 00 00 88 88 83 00 00 00",
     "0F B6 8E FC 00 00 00 EB 04", 7, "88 88", "EB 04"},
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
     "0F B6 8C 24 D4 00 00 00 EB 04",
     8, "88 88", "EB 04", false, true},
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
     "0F B6 8C 24 FC 00 00 00 EB 04",
     8, "88 88", "EB 04", false, true},
    // 4.4.1-4.4.6 inline the tooltip compare like 4.2.4, with the checksum
    // string at +0x320 instead of +0x280. Keep that displacement explicit so
    // the version-text caller cannot be mistaken for the tooltip.
    {"checksum warning (tooltip)",
     "48 8B 15 ?? ?? ?? ?? 48 81 C2 20 03 00 00 48 83 7A 18 10 72 03 "
     "48 8B 12 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? 48 8D",
     "48 8B 15 ?? ?? ?? ?? 48 81 C2 20 03 00 00 48 83 7A 18 10 72 03 "
     "48 8B 12 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 31 C0 0F 84 ?? ?? ?? ?? 48 8D",
     36, "85 C0", "31 C0", true, true},
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

// True when t is the entry of CAchievementsManager::AccessInstance(). The
// signature pins the "mov rax,[slot]; test; jne; mov ecx,0x88; call operator_new"
// that starts the work, but not the function: every build verified so far opens
// with a four-byte frame allocation ("sub rsp,0x28") in front of that load, so
// the signature hit is a few bytes inside the entry and must not be used as the
// entry itself.
bool LooksLikeAccessInstance(uintptr_t t, uintptr_t base, size_t size) {
  if (!InRange(t, base, size)) return false;
  const uintptr_t load = FindMovRaxRip(reinterpret_cast<uint8_t*>(t), 0x10);
  return load != 0 && MatchesAt(reinterpret_cast<uint8_t*>(load), base, size, kMgrSlotSig);
}

// The direct call to AccessInstance() that sits beside a patch point, found by
// the shape of its target rather than by a fixed offset. The offset matters:
// the checksum point has a fallback spelling whose "call" sits one byte earlier
// than the primary's, so "match + 8" lands inside that call's displacement (4.2.4
// resolves the point through exactly that fallback). Trusting whatever byte sits
// at a fixed offset there could hand back an address that merely happens to be
// inside the image; a candidate whose target does not look like AccessInstance
// is never accepted.
uintptr_t CallToAccessInstance(uint8_t* at, uintptr_t base, size_t size, size_t span,
                               bool forward) {
  for (size_t i = 0; i + 5 <= span; ++i) {
    uint8_t* const p = forward ? at + i : at - i;
    if (!InRange(reinterpret_cast<uintptr_t>(p), base, size)) break;
    if (*p != 0xE8) continue;
    const uintptr_t t = CallTarget(p, base, size);
    if (t != 0 && LooksLikeAccessInstance(t, base, size)) return t;
  }
  return 0;
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

// ---------------------------------------------------------------------------
// Rebuilding the active achievement list of a save that was written while
// achievements were disabled.
//
// Such a save carries no 0x2fbb list. Loading it leaves the manager's active
// list at zero entries, and Update() - the only place that can unlock anything
// - iterates exactly that list, so nothing unlocks for the rest of the
// session. No byte patch helps here: the missing list is data, not a flag.
//
// The game has a second builder that never looks at the save: the one used
// when a new game starts, OnGameStart(CEventScope&). It walks the achievement
// catalogue (read from common/achievements.txt at startup), skips entries
// Steam already reports as unlocked, and honours each entry's "possible"
// block. Calling it once after a load rebuilds the list, and the next save
// writes 0x2fbb again - which repairs the save for good.
//
// Update(CEventScope&) is the only caller that already has a live scope in
// hand, so it is the natural place to do that. Rather than hooking its
// prologue (this tool has no disassembler to copy instructions with), the
// single call to it is retargeted: four bytes, no trampoline, and RCX/RDX
// already hold (manager, scope) - exactly what the rebuild needs.
//
// Locating, without a version table:
//   * OnGameStart zeroes its two counters (+0x44, +0x7c) before anything else,
//     so a call target whose first 0x40 bytes contain both "89 ?? 44" and
//     "89 ?? 7c" is a candidate;
//   * Update tests [this+0x85] immediately before calling it, so the candidate
//     call is the one preceded by "85 00 00 00" and a short jcc;
//   * Update's entry is the nearest function start above that call, and it
//     must look like a prologue (stack allocation or register spill);
//   * the instruction to retarget is the image's single direct call to Update,
//     and an AccessInstance call must sit within 64 bytes in front of it - that
//     is what makes it the achievements pump rather than some other caller.
// Verified against 4.2.4, 4.4.1-4.4.6 and 4.5.1-4.5.4: one candidate, one
// guarded call, one call site and the AccessInstance call 15 bytes before it
// in every build. Refusing beats guessing: if any of the five checks fails,
// nothing is retargeted and the other eight patches carry on.
// ---------------------------------------------------------------------------

constexpr size_t kActiveCount = 0x44;  // CAchievementsManager +0x44

using UpdateFn = void (*)(void*, void*);
UpdateFn g_real_update = nullptr;
UpdateFn g_real_on_game_start = nullptr;
uintptr_t g_hook_base = 0;
size_t g_hook_size = 0;
uint8_t* g_hook_stub = nullptr;  // set once the call site has been retargeted

// A DLL is not guaranteed to land within the +/-2 GB a rel32 call can reach,
// so the call site is pointed at a three-instruction stub allocated near it:
// mov rax, <hook>; jmp rax. The stack already holds the return address, so the
// hook returns straight to the original caller.
uint8_t* AllocNear(uintptr_t target, size_t n) {
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  const uintptr_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
  const uintptr_t lo = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
  const uintptr_t hi = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);
  for (uintptr_t d = gran; d < 0x70000000ull; d += gran) {
    for (int up = 0; up < 2; ++up) {
      const uintptr_t cand = up ? target + d : target - d;
      if (cand < lo || cand + n > hi) continue;
      void* const p = VirtualAlloc(reinterpret_cast<void*>(cand), n,
                                   MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
      if (p != nullptr) return static_cast<uint8_t*>(p);
    }
  }
  return nullptr;
}

struct CallRef {
  uint8_t* at = nullptr;
  uintptr_t target = 0;
};

bool LooksLikeManager(const uint8_t* mgr, uintptr_t base, size_t size) {
  uintptr_t vtbl = 0;
  std::memcpy(&vtbl, mgr, sizeof(vtbl));
  if (!InRange(vtbl, base, size)) return false;
  for (int k = 0x81; k <= 0x84; ++k) {
    if (mgr[k] > 1) return false;
  }
  return true;
}

// "mov dword [reg+0x44], reg32" immediately followed by the same for +0x7c:
// the two list counters OnGameStart clears before it does anything else.
bool HasZeroedCounters(const uint8_t* p, size_t n) {
  for (size_t i = 0; i + 6 <= n; ++i) {
    if (p[i] == 0x89 && p[i + 2] == 0x44 && p[i + 3] == 0x89 && p[i + 5] == 0x7C) return true;
  }
  return false;
}

// The "cmp byte [reg+0x85], 0" that guards the OnGameStart call inside Update,
// followed by a short jcc (je or jne depending on how the guard was spelled).
bool GuardsOnGameStart(const uint8_t* at, const uint8_t* lower) {
  const uint8_t* first = (at - lower > 48) ? at - 48 : lower;
  for (const uint8_t* p = first; p + 4 <= at; ++p) {
    if (p[0] != 0x85 || p[1] != 0x00 || p[2] != 0x00 || p[3] != 0x00) continue;
    bool jcc = false;
    for (const uint8_t* q = p + 4; q < at; ++q) {
      if (*q == 0x74 || *q == 0x75) {
        jcc = true;
        break;
      }
    }
    // A decoy earlier in the window must not end the search: the real guard is
    // seven to nine bytes before the call, so a false "85 00 00 00" in front of
    // it used to swallow the whole pattern.
    if (jcc) return true;
  }
  return false;
}

// A function entry this tool is willing to retarget must look like a real
// prologue: a stack allocation or a register spill within the first 0x30
// bytes. Covers 4.2.4 (spill first), 4.4.x ("sub rsp, imm8") and 4.5.x
// (spill, then "sub rsp, imm32" at +0x16).
bool LooksLikeFunctionEntry(const uint8_t* p) {
  for (size_t i = 0; i + 4 <= 0x30; ++i) {
    if (p[i] == 0x48 && p[i + 1] == 0x83 && p[i + 2] == 0xEC) return true;
    if (p[i] == 0x48 && p[i + 1] == 0x81 && p[i + 2] == 0xEC) return true;
    if (p[i] == 0x48 && p[i + 1] == 0x89 && p[i + 2] == 0x5C && p[i + 3] == 0x24) return true;
  }
  return false;
}

// Nearest function start above "at": a "ret" followed by int3 padding. The
// boundary is at most a few hundred bytes up, so the search is capped.
uint8_t* FunctionStartAbove(uint8_t* at, uint8_t* lower) {
  size_t span = static_cast<size_t>(at - lower);
  if (span > 0x800) span = 0x800;
  for (size_t i = 2; i < span; ++i) {
    uint8_t* p = at - i;
    if (*p != 0xC3 || p[1] != 0xCC) continue;
    uint8_t* q = p + 1;
    while (q < at && *q == 0xCC) ++q;
    return q;
  }
  return nullptr;
}

bool TextSectionOf(uint8_t* base, size_t size, uint8_t** out, size_t* out_n) {
  if (size < sizeof(IMAGE_DOS_HEADER)) return false;
  const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) return false;
  const size_t nt_at = static_cast<size_t>(dos->e_lfanew);
  if (nt_at > size || size - nt_at < sizeof(IMAGE_NT_HEADERS64)) return false;
  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + nt_at);
  if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
  const auto* sec = IMAGE_FIRST_SECTION(nt);
  for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
    if (std::memcmp(sec[i].Name, ".text", 5) != 0) continue;
    const size_t va = sec[i].VirtualAddress;
    size_t n = sec[i].Misc.VirtualSize;
    if (n == 0 || n > size - va) n = sec[i].SizeOfRawData;
    if (va >= size || n > size - va) return false;
    *out = base + va;
    *out_n = n;
    return true;
  }
  return false;
}

// Pacing for the rebuild. The first attempts are a second apart so a save that
// lost its list is repaired on the frame it is loaded; from there the interval
// backs off to 30 s but never stops.
//
// It must never stop: the active list is zero for reasons that have nothing to
// do with a broken save. CAchievementsManager::Clear() zeroes it every time the
// player returns to the main menu, and the catalogue can legitimately have
// nothing left to hand out. A latch - "three failures and we are done, reset
// when the list becomes non-empty again" - could therefore be burned in a state
// a broken save never leaves, and a save loaded later in the same session was
// then silently left unrepaired. Only a load can empty a list the player just
// had, and that transition resets the pacing below.
DWORD RebuildDelayMs(uint32_t tries) {
  if (tries <= 3) return 1000;
  if (tries <= 5) return 5000;
  return 30000;
}

// Runs on the game's own thread, in place of the call to Update. Everything
// here is guarded, so a swapped-out or half-initialised object is left alone.
void HookAchievementsUpdate(void* manager, void* scope) {
  static bool announced = false;
  static uintptr_t watched = 0;     // manager instance currently being watched
  static uint32_t last_active = 0;  // last non-zero list size seen; 0 = none yet
  static uint32_t tries = 0;        // attempts since the pacing was reset
  static DWORD next_try = 0;        // GetTickCount() of the next attempt

  if (!announced) {
    announced = true;
    Log("achievements update hook: first tick, Update is being called");
  }

  // Nothing is read or written before the object passes the same "is this still
  // the manager" test the monitor loop uses.
  if (manager != nullptr && scope != nullptr && g_real_on_game_start != nullptr &&
      LooksLikeManager(static_cast<const uint8_t*>(manager), g_hook_base, g_hook_size)) {
    auto* m = static_cast<uint8_t*>(manager);
    const DWORD now = GetTickCount();
    if (watched != reinterpret_cast<uintptr_t>(manager)) {
      watched = reinterpret_cast<uintptr_t>(manager);
      last_active = 0;
      tries = 0;
      next_try = now;
    }
    const uint32_t active = *reinterpret_cast<const uint32_t*>(m + kActiveCount);
    if (active > 0) {
      if (last_active == 0) {
        // A list exists again: this is a running game, so a later load of a
        // save that carries none may need us and should not have to wait.
        if (tries != 0) {
          Log("active achievement list is non-empty again (%u entries); rebuild re-armed",
              active);
        }
        tries = 0;
        next_try = now;
      }
      last_active = active;
    } else {
      if (last_active != 0) {
        // The list the player just had is gone: a save was loaded, or a load
        // cleared it. Start over with the fast interval.
        last_active = 0;
        tries = 0;
        next_try = now;
      }
      // While the backend is not ready (0x85) the game's own Update already
      // retries OnGameStart(CEventScope&) every frame - the guarded call this
      // hook sits in front of - so doing it here as well would only duplicate
      // that work and burn attempts while there is nothing to rebuild from.
      if (m[0x85] == 0 && static_cast<int32_t>(now - next_try) >= 0) {
        g_real_on_game_start(manager, scope);
        const uint32_t after = *reinterpret_cast<const uint32_t*>(m + kActiveCount);
        if (after > 0) {
          tries = 0;
          Log("rebuilt the active achievement list this save carried none of: %u entries", after);
        } else {
          ++tries;
          const DWORD delay = RebuildDelayMs(tries);
          next_try = now + delay;
          if (tries <= 3 || (tries % 10) == 0) {
            Log("active achievement list is still empty after attempt %u "
                "(no country in scope, or nothing left to unlock); next attempt in %lu ms",
                tries, static_cast<unsigned long>(delay));
          }
        }
      }
    }
  }
  if (g_real_update != nullptr) g_real_update(manager, scope);
}

HookResult FindAndInstallHook(uint8_t* base, size_t size, bool write,
                               uintptr_t access_instance) {
  HookResult r;
  r.hook_fn = reinterpret_cast<uintptr_t>(&HookAchievementsUpdate);
  const uintptr_t image_base = reinterpret_cast<uintptr_t>(base);
  uint8_t* text = nullptr;
  size_t text_n = 0;
  if (!TextSectionOf(base, size, &text, &text_n)) {
    r.state = "not found (no .text section)";
    return r;
  }

  int guard_hits = 0;
  CallRef guard;
  for (size_t i = 0; i + 5 <= text_n; ++i) {
    if (text[i] != 0xE8) continue;
    int32_t disp = 0;
    std::memcpy(&disp, text + i + 1, sizeof(disp));
    uint8_t* const at = text + i;
    const uintptr_t target =
        reinterpret_cast<uintptr_t>(at) + 5 + static_cast<intptr_t>(disp);
    if (!InRange(target, image_base, size) || size - (target - image_base) < 0x48) continue;
    if (!HasZeroedCounters(reinterpret_cast<const uint8_t*>(target), 0x48)) continue;
    if (!GuardsOnGameStart(at, text)) continue;
    guard.at = at;
    guard.target = target;
    ++guard_hits;
  }
  if (guard_hits != 1) {
    char buf[96];
    std::snprintf(buf, sizeof(buf), "not found (%d guarded OnGameStart calls)", guard_hits);
    r.state = buf;
    return r;
  }

  uint8_t* const update = FunctionStartAbove(guard.at, text);
  if (update == nullptr) {
    r.state = "not found (no function start above the guarded call)";
    return r;
  }
  if (!LooksLikeFunctionEntry(update)) {
    r.state = "not found (the boundary above the guarded call is not a prologue)";
    return r;
  }

  int site_hits = 0;
  int hooked_hits = 0;
  CallRef site;
  for (size_t i = 0; i + 5 <= text_n; ++i) {
    if (text[i] != 0xE8) continue;
    int32_t disp = 0;
    std::memcpy(&disp, text + i + 1, sizeof(disp));
    uint8_t* const at = text + i;
    const uintptr_t target =
        reinterpret_cast<uintptr_t>(at) + 5 + static_cast<intptr_t>(disp);
    if (target == reinterpret_cast<uintptr_t>(update)) {
      site.at = at;
      site.target = target;
      ++site_hits;
    } else if (target == reinterpret_cast<uintptr_t>(&HookAchievementsUpdate) ||
               (g_hook_stub != nullptr && target == reinterpret_cast<uintptr_t>(g_hook_stub))) {
      site.at = at;
      ++hooked_hits;
    }
  }

  r.update = reinterpret_cast<uintptr_t>(update);
  r.on_game_start = guard.target;
  r.call_site = reinterpret_cast<uintptr_t>(site.at);

  if (site_hits == 0 && hooked_hits == 1) {
    r.state = "already hooked";
    return r;
  }
  if (site_hits != 1) {
    char buf[96];
    std::snprintf(buf, sizeof(buf), "call site not unique (%d)", site_hits);
    r.state = buf;
    return r;
  }
  // This must be the achievements pump, not merely a call to Update: the game
  // reaches it with a fresh manager from AccessInstance() a few bytes earlier -
  // 15 bytes before the call in every build from 4.2.4 to 4.5.4. Without that
  // evidence nothing is retargeted. Pointing a call in an unrelated function at
  // our stub is the one failure this code cannot undo, so refuse instead.
  bool anchored = false;
  if (access_instance != 0) {
    const size_t site_off = static_cast<size_t>(site.at - text);
    const size_t from = site_off > 64 ? site_off - 64 : 0;
    for (size_t i = from; i + 5 <= site_off; ++i) {
      if (text[i] != 0xE8) continue;
      int32_t disp = 0;
      std::memcpy(&disp, text + i + 1, sizeof(disp));
      const uintptr_t target =
          reinterpret_cast<uintptr_t>(text + i) + 5 + static_cast<intptr_t>(disp);
      if (target == access_instance) {
        anchored = true;
        break;
      }
    }
  }
  if (!anchored) {
    r.state = access_instance == 0
                  ? "not found (achievements manager unresolved, call site unverified)"
                  : "not found (no AccessInstance call beside the update call site)";
    return r;
  }

  if (!write) {
    r.state = "would hook";
    return r;
  }

  uint8_t* const stub = AllocNear(reinterpret_cast<uintptr_t>(site.at), 16);
  if (stub == nullptr) {
    r.state = "no executable stub within rel32 range";
    return r;
  }
  stub[0] = 0x48;  // mov rax, imm64
  stub[1] = 0xB8;
  const uint64_t hook_addr = reinterpret_cast<uint64_t>(&HookAchievementsUpdate);
  std::memcpy(stub + 2, &hook_addr, sizeof(hook_addr));
  stub[10] = 0xFF;  // jmp rax
  stub[11] = 0xE0;
  FlushInstructionCache(GetCurrentProcess(), stub, 12);
  DWORD stub_old = 0;
  VirtualProtect(stub, 16, PAGE_EXECUTE_READ, &stub_old);

  // The real functions and the stub must all be in place before the retarget
  // lands, or a thread arriving in the hook first would skip an update.
  g_real_update = reinterpret_cast<UpdateFn>(update);
  g_real_on_game_start = reinterpret_cast<UpdateFn>(guard.target);
  g_hook_base = image_base;
  g_hook_size = size;
  g_hook_stub = stub;
  r.stub = reinterpret_cast<uintptr_t>(stub);

  const intptr_t delta = reinterpret_cast<intptr_t>(stub) -
                         (reinterpret_cast<intptr_t>(site.at) + 5);
  if (delta != static_cast<int32_t>(delta)) {
    r.state = "stub out of rel32 range";
    return r;
  }
  const int32_t rel = static_cast<int32_t>(delta);
  if (!WriteBytes(site.at + 1, &rel, sizeof(rel))) {
    r.state = "write failed";
    return r;
  }
  r.state = "hooked";
  return r;
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

  // Independent derivation of the manager singleton's static slot: the load the
  // signature pins. It is not the function's entry - a frame allocation sits in
  // front of it on every build verified so far - which is what
  // LooksLikeAccessInstance has to account for.
  uintptr_t mov_sig = 0;
  {
    const std::vector<uint8_t*> hits = ScanAll(base, size, kMgrSlotSig);
    if (hits.size() == 1) mov_sig = reinterpret_cast<uintptr_t>(hits[0]);
  }

  // Resolve CAchievementsManager::AccessInstance() from the call that sits next
  // to a patch point. Both derivations are shape-checked (see
  // CallToAccessInstance): the checksum point's fallback spelling moves its call
  // away from "+8", and reading a fixed offset there is exactly how a wrong
  // address would be adopted - which costs the old-save hook its anchor and
  // silently disables the very fix this file is about.
  uintptr_t access = 0;
  bool access_from_call = false;
  if (match_a != 0) {
    access = CallToAccessInstance(reinterpret_cast<uint8_t*>(match_a), image_base, size, 0x20,
                                  true);
    access_from_call = access != 0;
  }
  if (access == 0 && match_b2 != 0) {
    access = CallToAccessInstance(reinterpret_cast<uint8_t*>(match_b2), image_base, size, 0x14,
                                  false);
    access_from_call = access != 0;
  }
  // No third derivation on purpose. The signature hit is the load *inside*
  // AccessInstance(), not its entry (see LooksLikeAccessInstance), and handing
  // that address to the hook would put it four bytes past the function it is
  // supposed to anchor on. Refusing leaves the old-save hook off on such a
  // build, which is the outcome this file prefers everywhere else.
  r.access_instance = access;

  // The static slot holding the manager instance is loaded near the top of
  // AccessInstance(). Two independent derivations exist - the call site and
  // the wildcard signature - and the slot is only trusted when they agree,
  // or when the single candidate matches the signature's shape exactly.
  // Forcing flags in an unrelated object every 200 ms is the one failure this
  // code cannot recover from, so refusing is the safe direction.
  uintptr_t mov_call = 0;
  if (access_from_call && access != 0 && size - (access - image_base) >= 0x20) {
    mov_call = FindMovRaxRip(reinterpret_cast<uint8_t*>(access), 0x20);
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

  // Old-save repair: retarget the single call that drives the achievements
  // update, so a save that lost its active list can have it rebuilt.
  r.hook = FindAndInstallHook(base, size, write, r.access_instance);
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
