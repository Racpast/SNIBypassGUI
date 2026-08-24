// Copyright © 2026 Racpast. All Rights Reserved.
//
// This file is part of SNIBypassGUI, a proprietary software project.
//
// NOTICE: All information contained herein is, and remains the property of
// Racpast. The intellectual and technical concepts contained herein are
// proprietary to Racpast and are protected by copyright law and international
// treaties. Dissemination of this information or reproduction of this material
// is strictly forbidden unless prior written permission is obtained from Racpast.
//
// Unauthorized copying, modification, distribution, or use of this file,
// via any medium, is strictly prohibited.
//
// For licensing inquiries: snibypassgui@gmail.com or racpast@gmail.com
//
// See the LICENSE file in the project root for full terms and conditions.

#pragma once
// WinDivert-based DNS interceptor.
//
// Intercepts outbound DNS queries over multiple protocols and, for any query whose
// name matches a rule, injects a synthesized response straight back to the
// requesting stack and drops the original. Everything else is reinjected unchanged,
// so non-hijacked DNS reaches the real resolver untouched.
//
// Supported protocols:
//   - UDP DNS (port 53): standard DNS queries
//   - TCP DNS (port 53): passive interception with stateful reassembly
//   - MDNS (port 5353): multicast DNS, local network service discovery
//   - LLMNR (port 5355): Link-Local Multicast Name Resolution (Windows)
//
// Rule file syntax (hosts-style, space separated, action first):
//   ACTION domain [domain...]
// ACTION is either an IP (v4 or v6, the redirect target) or the literal "NX"
// (answer NXDOMAIN). Each domain carries an explicit matching prefix:
//   .a.com     apex and every subdomain (suffix match)
//   exact.com  that host only (exact match)
//   !b.a.com   exclude exactly b.a.com from any positive rule
//   !.c.a.com  exclude c.a.com and its whole subtree
// Exclusions win over every positive rule. A line with no ACTION is a parse error
// and is skipped; there is no implicit "bare domain means 127.0.0.1".
//
// Nothing on the machine is reconfigured: no adapter DNS change, no service
// install. Closing the WinDivert handle returns resolution to normal instantly.
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace Dns {

// Forward declaration to avoid including file_watcher.h in the header.
class FileWatcher;

enum : uint16_t { kTypeA = 1, kTypeAaaa = 28, kTypeSvcb = 64, kTypeHttps = 65 };
enum : uint16_t { kClassIn = 1 };

// How a rule's `domain` is compared against a query name.
//   Exact  matches that host only ("exact.com" is not "www.exact.com")
//   Suffix matches the apex and every subdomain (".a.com" covers a.com, x.a.com)
enum class MatchKind { Exact, Suffix };

// What a matched query gets.
//   Redirect synthesizes an A/AAAA answer pointing at v4/v6
//   Block    answers NXDOMAIN
enum class RuleAction { Redirect, Block };

// One hijack rule. `domain` is a bare lowercased name with no leading or
// trailing dot; `kind` selects exact versus suffix matching explicitly.
struct Rule {
    RuleAction  action = RuleAction::Redirect;
    MatchKind   kind = MatchKind::Suffix;
    std::string domain;
    uint8_t     v4[4] = {127, 0, 0, 1};
    uint8_t     v6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};  // ::1
    // Which families this redirect can actually answer. A rule loaded from a file
    // carries exactly one address, so a v4-only rule answers A and returns NODATA
    // for AAAA (and vice versa) instead of handing back a bogus default address.
    bool        hasV4 = true;
    bool        hasV6 = true;
    uint32_t    ttl = 60;
};

// Carves a name (Exact) or a subtree (Suffix) out of every positive rule. Checked
// before any Rule; a hit means "pass through as if unmatched".
struct Exclusion {
    MatchKind   kind = MatchKind::Exact;
    std::string domain;
};

// A parsed DNS question (the first question only).
struct Query {
    uint16_t    id = 0;
    uint16_t    flags = 0;
    std::string name;            // lowercased, dotted, no trailing dot
    uint16_t    qtype = 0;
    uint16_t    qclass = 0;
    size_t      questionEnd = 0;  // offset just past QNAME+QTYPE+QCLASS
};

// ---- Pure logic (no WinDivert involved; unit tested) ------------------------

// Parse the header and first question of a DNS message. Bounds checked; returns
// false on a malformed, compressed, or empty question.
bool ParseQuery(const uint8_t* dns, size_t len, Query& out);

// Normalize a domain for storage and matching: lowercase, strip a leading dot and
// any trailing dot.
std::string NormalizeDomain(std::string d);

bool SuffixMatch(const std::string& name, const std::string& suffix);
bool ExactMatch(const std::string& name, const std::string& domain);

// A single domain token from a rule line, with its explicit matching prefix.
enum class DomainPrefix { None, Dot, Bang, BangDot };  // exact, suffix, !exact, !suffix

struct ParsedDomain {
    DomainPrefix prefix = DomainPrefix::None;
    std::string  domain;
};

// A parsed rule line: an action (IP redirect or NX block) plus its domains.
struct ParsedLine {
    bool                      isBlock = false;  // true means NXDOMAIN
    bool                      hasV6 = false;    // redirect family, when !isBlock
    uint8_t                   v4[4] = {};
    uint8_t                   v6[16] = {};
    std::vector<ParsedDomain> domains;
};

// Parse one rule line. Returns false with a diagnostic in `err` for a blank or
// comment line, or a syntax error (missing action, bad IP, no domains).
bool ParseRuleLine(const std::string& line, ParsedLine& out, std::string& err);

// How a matched-domain query of `qtype` should be handled.
enum class Action { PassThrough, Answer, NoData };
Action DecideAction(uint16_t qtype);

// Build a response payload for `q` using `rule`. For a Redirect rule, Answer
// appends one A/AAAA record and NoData yields an empty NOERROR answer; a Redirect
// that lacks the queried family (e.g. an AAAA query against a v4-only rule) is
// downgraded to NODATA rather than emitting a default address. A Block rule
// yields NXDOMAIN regardless of `action`, as long as it is not PassThrough.
std::vector<uint8_t> BuildResponse(const uint8_t* query, size_t qlen, const Query& q,
                                   const Rule& rule, Action action);

// ---- Interceptor (owns the rules and the WinDivert capture thread) ---------------

// Thread-safe rule set for double-buffered hot-reload. The interceptor loop reads
// from the active set while a hot-reload callback writes to the standby set, then
// swaps them atomically.
class RuleSet {
public:
    RuleSet() = default;
    RuleSet(const RuleSet&) = delete;
    RuleSet& operator=(const RuleSet&) = delete;

    void AddRule(const Rule& r);
    void AddExclusion(const Exclusion& e);
    void Clear();
    size_t RuleCount() const;
    const Rule* Match(const std::string& name) const;

private:
    std::vector<Rule> m_rules;
    std::vector<Exclusion> m_excludes;
};

class Interceptor {
public:
    Interceptor();
    ~Interceptor();
    Interceptor(const Interceptor&) = delete;
    Interceptor& operator=(const Interceptor&) = delete;

    // Load "ACTION domain..." lines from a hosts-style file into the active rule set.
    // Returns rules loaded.
    size_t LoadRules(const std::wstring& path);

    // Direct rule manipulation (for testing or programmatic setup).
    void   AddRule(const Rule& r);
    void   AddExclusion(const Exclusion& e);
    void   ClearRules();
    size_t RuleCount() const;

    // Enable hot-reload: monitor `path` and automatically reload rules when it changes.
    // The file is debounced (500ms by default) to handle editors that write in chunks.
    // Hot-reload uses double buffering: the new rules are loaded into a standby set,
    // then atomically swapped with the active set, so queries never see a "no rules"
    // window during reload.
    // Safe to call before or after Start(). Does nothing if already watching this path.
    void EnableHotReload(const std::wstring& path, unsigned debounceMs = 500);

    // Disable hot-reload monitoring. Safe to call even if not enabled.
    void DisableHotReload();

    // Open WinDivert and run the capture loop on a worker thread. Requires
    // administrator. `winDivertDll` is the full path to WinDivert.dll; empty means
    // the copy beside the executable. The DLL loads its own WinDivert64.sys from
    // that same directory, so the driver needs no separate configuration.
    //
    // Captures outbound DNS traffic on:
    //   - UDP ports 53 (DNS), 5353 (MDNS), 5355 (LLMNR)
    //   - TCP port 53 (DNS over TCP, with stateful reassembly)
    bool Start(const std::wstring& winDivertDll = std::wstring());
    void Stop();
    bool Running() const { return m_running.load(); }

private:
    void Loop();
    const Rule* MatchLocked(const std::string& name) const;

    mutable std::mutex            m_mx;
    std::shared_ptr<RuleSet>      m_activeRules;   // active set, read by Loop()
    void*                         m_handle = nullptr;  // WinDivert HANDLE
    std::thread                   m_thread;
    std::atomic<bool>             m_running{false};
    std::unique_ptr<FileWatcher>  m_watcher;
    std::wstring                  m_rulesPath;  // path being monitored for hot-reload
};

}  // namespace Dns
