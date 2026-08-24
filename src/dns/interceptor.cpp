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

#include "dns/interceptor.h"

// Standard library headers come first. windivert.h pulls in windows.h, which
// defines the SAL annotation macros __in / __out; those would otherwise clobber
// identically named parameters inside libstdc++ headers.
#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <sstream>
#include <unordered_map>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

// Every WinDivert entry point is resolved at runtime, so neutralize the header's
// dllimport prototypes (it guards on WINDIVERTEXPORT) and keep only its structs,
// enums and constants.
#define WINDIVERTEXPORT
#include "windivert.h"

#include "app/logging.h"
#include "app/paths.h"
#include "app/text.h"
#include "dns/file_watcher.h"

namespace Dns {
namespace {

using PfnOpen = HANDLE(WINAPI*)(const char*, WINDIVERT_LAYER, INT16, UINT64);
using PfnRecv = BOOL(WINAPI*)(HANDLE, VOID*, UINT, UINT*, WINDIVERT_ADDRESS*);
using PfnSend = BOOL(WINAPI*)(HANDLE, const VOID*, UINT, UINT*, const WINDIVERT_ADDRESS*);
using PfnShutdown = BOOL(WINAPI*)(HANDLE, WINDIVERT_SHUTDOWN);
using PfnClose = BOOL(WINAPI*)(HANDLE);
using PfnParsePacket = BOOL(WINAPI*)(const VOID*, UINT, PWINDIVERT_IPHDR*,
                                     PWINDIVERT_IPV6HDR*, UINT8*, PWINDIVERT_ICMPHDR*,
                                     PWINDIVERT_ICMPV6HDR*, PWINDIVERT_TCPHDR*,
                                     PWINDIVERT_UDPHDR*, PVOID*, UINT*, PVOID*, UINT*);
using PfnCalcChecksums = BOOL(WINAPI*)(VOID*, UINT, WINDIVERT_ADDRESS*, UINT64);

struct WinDivertApi {
    HMODULE         dll = nullptr;
    PfnOpen         Open = nullptr;
    PfnRecv         Recv = nullptr;
    PfnSend         Send = nullptr;
    PfnShutdown     Shutdown = nullptr;
    PfnClose        Close = nullptr;
    PfnParsePacket  Parse = nullptr;
    PfnCalcChecksums Calc = nullptr;

    bool ok() const {
        return dll && Open && Recv && Send && Shutdown && Close && Parse && Calc;
    }
};

WinDivertApi   g_api;  // process wide, loaded once
std::once_flag g_apiOnce;

// GetProcAddress returns FARPROC; routing through a plain function-pointer type
// keeps the conversion to each concrete signature well formed.
template <typename Fn>
Fn ResolveEntry(HMODULE dll, const char* name) {
    return reinterpret_cast<Fn>(reinterpret_cast<void (*)()>(GetProcAddress(dll, name)));
}

void LoadWinDivertOnce(const std::wstring& dllPath) {
    std::call_once(g_apiOnce, [&] {
        // Loaded by full path so the DLL search order cannot be hijacked. The
        // caller resolves the path from [Paths] WinDivert in paths.ini, defaulting
        // to the copy beside the executable.
        const std::wstring path = dllPath.empty() ? (ExeDir() + L"WinDivert.dll") : dllPath;
        g_api.dll = LoadLibraryW(path.c_str());
        if (!g_api.dll) {
            LOGE(L"LoadLibrary WinDivert.dll failed: " + std::to_wstring(GetLastError()));
            return;
        }
        g_api.Open = ResolveEntry<PfnOpen>(g_api.dll, "WinDivertOpen");
        g_api.Recv = ResolveEntry<PfnRecv>(g_api.dll, "WinDivertRecv");
        g_api.Send = ResolveEntry<PfnSend>(g_api.dll, "WinDivertSend");
        g_api.Shutdown = ResolveEntry<PfnShutdown>(g_api.dll, "WinDivertShutdown");
        g_api.Close = ResolveEntry<PfnClose>(g_api.dll, "WinDivertClose");
        g_api.Parse = ResolveEntry<PfnParsePacket>(g_api.dll, "WinDivertHelperParsePacket");
        g_api.Calc = ResolveEntry<PfnCalcChecksums>(g_api.dll, "WinDivertHelperCalcChecksums");
        if (!g_api.ok()) LOGE(L"WinDivert.dll is missing an expected export.");
    });
}

// DNS and IP header fields are big-endian on the wire.
uint16_t Read16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

uint16_t Swap16(uint16_t x) {
    return static_cast<uint16_t>((x >> 8) | (x << 8));
}

void Put16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x));
}

void Put32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(static_cast<uint8_t>(x >> 24));
    v.push_back(static_cast<uint8_t>(x >> 16));
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x));
}

char Lower(char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

bool DomainCovers(MatchKind kind, const std::string& domain, const std::string& name) {
    return kind == MatchKind::Suffix ? SuffixMatch(name, domain) : ExactMatch(name, domain);
}

// ============================================================================
// TCP DNS interception
// ----------------------------------------------------------------------------
// DNS over TCP is intercepted *passively*, never by faking a three-way
// handshake. The real client<->resolver handshake is allowed to complete
// untouched; we only inspect outbound data segments (client -> :53) and
// reassemble the 2-byte length-prefixed query.
//
//   * If the reassembled name matches a rule, we synthesize the answer as if it
//     came from the resolver: a single PSH,FIN,ACK carrying <len><DNS> that both
//     delivers the answer and closes our (spoofed) half gracefully, so the
//     client's read returns the data followed by a clean EOF. Data and FIN in one
//     segment is ordinary TCP (RFC 793): the FIN simply consumes the sequence
//     number just past the last data byte, so the bookkeeping is unchanged while
//     one fewer packet is injected. The client's own FIN is later acknowledged
//     from the server's identity. The original query is dropped, and a single RST
//     is sent *to the real resolver* (spoofed as the client) so its now-orphaned
//     connection is torn down immediately instead of lingering half-open.
//
//   * If the name does NOT match (or is a pass-through query type), nothing is
//     forged: the segment is reinjected verbatim so the real resolver answers.
//     Non-hijacked DNS is therefore never disturbed and never receives a RST.
//
// Sequence bookkeeping uses only what the wire already tells us: the client's
// ACK number is exactly the sequence the resolver would send next, and the
// client's sequence plus payload length is exactly what we must acknowledge, so
// the synthesized stream is byte-accurate for both single- and multi-segment
// queries. All emitted packets are freshly built with a bounds-checked buffer
// and a clean 20-byte TCP header; no field is ever read past the captured frame.
// ============================================================================

// Per-flow state, keyed by the 4-tuple. Created lazily when the first data
// segment arrives and dropped as soon as a verdict is reached (or on timeout).
struct TcpConn {
    bool                 hijacked = false;     // we have taken over this flow
    bool                 haveSeq = false;      // expectedSeq initialized
    uint32_t             expectedSeq = 0;      // next in-order client data seq
    std::vector<uint8_t> recvBuf;              // reassembled <len><DNS> bytes
    std::vector<uint8_t> respPayload;          // synthesized answer, for retransmits
    uint32_t             respSeq = 0;          // server seq at start of the answer
    uint32_t             respAck = 0;          // ack covering the entire query
    uint32_t             finSeq = 0;           // server seq of our FIN
    uint32_t             ourSeq = 0;           // server seq after our FIN (+1)
    uint64_t             lastSeen = 0;         // for idle cleanup
};

// FNV-1a over the packed 4-tuple key (src[16] dst[16] sport[2] dport[2]).
struct KeyHash {
    size_t operator()(const std::array<uint8_t, 36>& k) const noexcept {
        uint64_t h = 1469598103934665603ULL;
        for (uint8_t b : k) {
            h ^= b;
            h *= 1099511628211ULL;
        }
        return static_cast<size_t>(h);
    }
};

}  // namespace

// ---- RuleSet implementation (double-buffered hot-reload support) ----------------

void RuleSet::AddRule(const Rule& r) {
    m_rules.push_back(r);
}

void RuleSet::AddExclusion(const Exclusion& e) {
    m_excludes.push_back(e);
}

void RuleSet::Clear() {
    m_rules.clear();
    m_excludes.clear();
}

size_t RuleSet::RuleCount() const {
    return m_rules.size();
}

const Rule* RuleSet::Match(const std::string& name) const {
    // Exclusions win over every positive rule.
    for (const Exclusion& e : m_excludes)
        if (DomainCovers(e.kind, e.domain, name)) return nullptr;
    for (const Rule& r : m_rules)
        if (DomainCovers(r.kind, r.domain, name)) return &r;
    return nullptr;
}

// ---- Helper functions --------------------------------------------------------

std::string NormalizeDomain(std::string d) {
    for (char& c : d) c = Lower(c);
    while (!d.empty() && d.front() == '.') d.erase(d.begin());
    while (!d.empty() && d.back() == '.') d.pop_back();
    return d;
}

bool SuffixMatch(const std::string& name, const std::string& suffix) {
    if (suffix.empty() || name.empty()) return false;
    if (name == suffix) return true;
    // `name` must be "<something>.<suffix>".
    if (name.size() > suffix.size() + 1) {
        const size_t at = name.size() - suffix.size();
        if (name[at - 1] == '.' && name.compare(at, suffix.size(), suffix) == 0) return true;
    }
    return false;
}

bool ExactMatch(const std::string& name, const std::string& domain) {
    return !name.empty() && !domain.empty() && name == domain;
}

bool ParseRuleLine(const std::string& line, ParsedLine& out, std::string& err) {
    out = ParsedLine{};
    err.clear();

    const size_t first = line.find_first_not_of(" \t");
    if (first == std::string::npos) {
        err = "blank";
        return false;
    }
    if (line[first] == '#' ||
        (line[first] == '/' && first + 1 < line.size() && line[first + 1] == '/')) {
        err = "comment";
        return false;
    }

    std::vector<std::string> tokens;
    {
        std::istringstream ls(line);
        std::string t;
        while (ls >> t) tokens.push_back(t);
    }
    if (tokens.empty()) {
        err = "blank";
        return false;
    }

    // The first token is the action: "NX" (case-insensitive) or an IP literal.
    const std::string& action = tokens[0];
    std::string lowered = action;
    for (char& c : lowered) c = Lower(c);
    if (lowered == "nx") {
        out.isBlock = true;
    } else if (action.find(':') != std::string::npos) {
        IN6_ADDR parsed = {};
        if (InetPtonA(AF_INET6, action.c_str(), &parsed) != 1) {
            err = "bad IPv6 action";
            return false;
        }
        std::memcpy(out.v6, &parsed, sizeof(out.v6));
        out.hasV6 = true;
    } else {
        IN_ADDR parsed = {};
        if (InetPtonA(AF_INET, action.c_str(), &parsed) != 1) {
            err = "missing or bad action";
            return false;
        }
        std::memcpy(out.v4, &parsed, sizeof(out.v4));
        out.hasV6 = false;
    }

    // Remaining tokens are domains, each with an explicit prefix.
    for (size_t i = 1; i < tokens.size(); ++i) {
        const std::string& token = tokens[i];
        DomainPrefix prefix = DomainPrefix::None;
        std::string body;
        if (token.size() >= 2 && token[0] == '!' && token[1] == '.') {
            prefix = DomainPrefix::BangDot;
            body = token.substr(2);
        } else if (token[0] == '!') {
            prefix = DomainPrefix::Bang;
            body = token.substr(1);
        } else if (token[0] == '.') {
            prefix = DomainPrefix::Dot;
            body = token.substr(1);
        } else {
            body = token;
        }
        std::string normalized = NormalizeDomain(body);
        if (normalized.empty()) continue;  // stray prefix with no domain
        out.domains.push_back({prefix, std::move(normalized)});
    }
    if (out.domains.empty()) {
        err = "no domains";
        return false;
    }
    return true;
}

Action DecideAction(uint16_t qtype) {
    if (qtype == kTypeA || qtype == kTypeAaaa) return Action::Answer;
    // Force HTTPS/SVCB to NODATA so an alternative-endpoint or ECH record cannot
    // bypass the loopback redirect for a hijacked name.
    if (qtype == kTypeHttps || qtype == kTypeSvcb) return Action::NoData;
    return Action::PassThrough;
}

bool ParseQuery(const uint8_t* dns, size_t len, Query& out) {
    if (!dns || len < 12) return false;
    out.id = Read16(dns);
    out.flags = Read16(dns + 2);
    if (Read16(dns + 4) < 1) return false;  // QDCOUNT

    std::string name;
    size_t off = 12;
    for (;;) {
        if (off >= len) return false;
        const uint8_t label = dns[off];
        if (label == 0) {
            ++off;
            break;
        }
        if (label & 0xC0) return false;  // compression is not expected in a question
        ++off;
        if (off + label > len) return false;
        if (!name.empty()) name.push_back('.');
        for (uint8_t i = 0; i < label; ++i)
            name.push_back(Lower(static_cast<char>(dns[off + i])));
        off += label;
        if (name.size() > 253) return false;  // RFC 1035 maximum
    }
    if (off + 4 > len) return false;
    out.qtype = Read16(dns + off);
    out.qclass = Read16(dns + off + 2);
    out.name = std::move(name);
    out.questionEnd = off + 4;
    return true;
}

std::vector<uint8_t> BuildResponse(const uint8_t* query, size_t qlen, const Query& q,
                                   const Rule& rule, Action action) {
    if (action == Action::PassThrough) return {};
    if (q.questionEnd == 0 || q.questionEnd > qlen) return {};

    // Start from the original header and question, verbatim.
    std::vector<uint8_t> r(query, query + q.questionEnd);

    // A Block rule answers NXDOMAIN for any query type.
    const bool block = (rule.action == RuleAction::Block);
    bool answer = !block && action == Action::Answer;

    // A Redirect rule only holds one address family. If the query asks for the
    // family this rule does not carry (AAAA against a v4-only rule, or A against
    // a v6-only rule), downgrade to NODATA (NOERROR, no answer) so the redirect
    // is not bypassed and no bogus default address is returned.
    if (answer && rule.action == RuleAction::Redirect) {
        if (q.qtype == kTypeA && !rule.hasV4) answer = false;
        else if (q.qtype == kTypeAaaa && !rule.hasV6) answer = false;
    }

    // Header high byte: QR=1, RD=1, RA=1. Low byte: RCODE (0, or 3 for NXDOMAIN).
    r[2] = 0x81;
    r[3] = block ? 0x83 : 0x80;
    r[6] = 0;
    r[7] = answer ? 1 : 0;  // ANCOUNT
    r[8] = 0;
    r[9] = 0;  // NSCOUNT
    r[10] = 0;
    r[11] = 0;  // ARCOUNT, dropping any EDNS OPT

    if (answer) {
        Put16(r, 0xC00C);      // NAME as a pointer to the question at offset 12
        Put16(r, q.qtype);     // TYPE (A or AAAA)
        Put16(r, kClassIn);    // CLASS
        Put32(r, rule.ttl);
        if (q.qtype == kTypeA) {
            Put16(r, sizeof(rule.v4));
            r.insert(r.end(), rule.v4, rule.v4 + sizeof(rule.v4));
        } else {
            Put16(r, sizeof(rule.v6));
            r.insert(r.end(), rule.v6, rule.v6 + sizeof(rule.v6));
        }
    }
    return r;
}

Interceptor::Interceptor() : m_activeRules(std::make_shared<RuleSet>()) {}

Interceptor::~Interceptor() {
    DisableHotReload();
    Stop();
}

void Interceptor::EnableHotReload(const std::wstring& path, unsigned debounceMs) {
    // If already watching this path, do nothing.
    if (m_watcher && m_rulesPath == path) return;

    // Stop any existing watcher.
    DisableHotReload();

    m_rulesPath = path;

    // Create a new watcher with a callback that reloads rules using double buffering.
    // The callback loads into a fresh rule set, then atomically swaps it with the active
    // one, so the interceptor loop never sees a "no rules" window during the reload.
    m_watcher = std::make_unique<FileWatcher>(path, [this, path]() {
        LOGI(L"Hot-reload: reloading DNS rules from " + path);

        // Load into a fresh standby set.
        std::ifstream in(path.c_str(), std::ios::binary);
        if (!in) {
            LOGE(L"Hot-reload: cannot open " + path);
            return;
        }
        const std::string raw((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());

        auto standby = std::make_shared<RuleSet>();
        std::istringstream lines(raw);
        std::string line;
        int lineNo = 0;
        size_t loaded = 0;
        while (std::getline(lines, line)) {
            ++lineNo;
            if (!line.empty() && line.back() == '\r') line.pop_back();

            ParsedLine parsed;
            std::string err;
            if (!ParseRuleLine(line, parsed, err)) {
                if (err != "blank" && err != "comment") {
                    LOGW(L"Hot-reload: line " + std::to_wstring(lineNo) + L": " + Utf8ToWide(err));
                }
                continue;
            }

            for (const ParsedDomain& pd : parsed.domains) {
                const MatchKind kind = (pd.prefix == DomainPrefix::Dot || pd.prefix == DomainPrefix::BangDot)
                                        ? MatchKind::Suffix : MatchKind::Exact;
                const bool isExclusion = (pd.prefix == DomainPrefix::Bang || pd.prefix == DomainPrefix::BangDot);

                if (isExclusion) {
                    Exclusion e;
                    e.kind = kind;
                    e.domain = pd.domain;
                    standby->AddExclusion(e);
                } else {
                    Rule r;
                    r.action = parsed.isBlock ? RuleAction::Block : RuleAction::Redirect;
                    r.kind = kind;
                    r.domain = pd.domain;
                    if (!parsed.isBlock) {
                        std::memcpy(r.v4, parsed.v4, sizeof(r.v4));
                        std::memcpy(r.v6, parsed.v6, sizeof(r.v6));
                        r.hasV4 = !parsed.hasV6;
                        r.hasV6 = parsed.hasV6;
                    }
                    standby->AddRule(r);
                    ++loaded;
                }
            }
        }

        // Atomically swap the standby set into the active slot.
        {
            std::lock_guard<std::mutex> lock(m_mx);
            m_activeRules = standby;
        }

        LOGI(L"Hot-reload: loaded " + std::to_wstring(loaded) + L" rule(s).");
    }, debounceMs);

    m_watcher->Start();
}

void Interceptor::DisableHotReload() {
    if (m_watcher) {
        m_watcher->Stop();
        m_watcher.reset();
    }
    m_rulesPath.clear();
}

void Interceptor::ClearRules() {
    std::lock_guard<std::mutex> lock(m_mx);
    m_activeRules = std::make_shared<RuleSet>();
}

void Interceptor::AddRule(const Rule& r) {
    std::lock_guard<std::mutex> lock(m_mx);
    m_activeRules->AddRule(r);
}

void Interceptor::AddExclusion(const Exclusion& e) {
    std::lock_guard<std::mutex> lock(m_mx);
    m_activeRules->AddExclusion(e);
}

size_t Interceptor::RuleCount() const {
    std::lock_guard<std::mutex> lock(m_mx);
    return m_activeRules->RuleCount();
}

const Rule* Interceptor::MatchLocked(const std::string& name) const {
    // Called with m_mx held; reads the active rule set snapshot.
    return m_activeRules->Match(name);
}

size_t Interceptor::LoadRules(const std::wstring& path) {
    std::ifstream in(path.c_str(), std::ios::binary);
    if (!in) return 0;
    const std::string raw((std::istreambuf_iterator<char>(in)),
                          std::istreambuf_iterator<char>());

    // Create a fresh rule set for atomic replacement.
    auto newRules = std::make_shared<RuleSet>();

    std::istringstream lines(raw);
    std::string line;
    int lineNo = 0;
    size_t loaded = 0;
    while (std::getline(lines, line)) {
        ++lineNo;
        if (!line.empty() && line.back() == '\r') line.pop_back();

        ParsedLine parsed;
        std::string err;
        if (!ParseRuleLine(line, parsed, err)) {
            // Blank and comment lines are skipped silently; real syntax errors log.
            if (err != "blank" && err != "comment")
                LOGW(L"hosts: line " + std::to_wstring(lineNo) + L": " + Utf8ToWide(err));
            continue;
        }

        for (const ParsedDomain& domain : parsed.domains) {
            const bool isExclusion = domain.prefix == DomainPrefix::Bang ||
                                     domain.prefix == DomainPrefix::BangDot;
            const MatchKind kind = (domain.prefix == DomainPrefix::Dot ||
                                    domain.prefix == DomainPrefix::BangDot)
                                       ? MatchKind::Suffix
                                       : MatchKind::Exact;
            if (isExclusion) {
                newRules->AddExclusion({kind, domain.domain});
                continue;
            }
            Rule r;
            r.kind = kind;
            r.domain = domain.domain;
            if (parsed.isBlock) {
                r.action = RuleAction::Block;
            } else {
                r.action = RuleAction::Redirect;
                // A rule line carries exactly one address family. Record which one
                // so a query for the other family answers NODATA instead of the
                // struct's default loopback address.
                if (parsed.hasV6) {
                    std::memcpy(r.v6, parsed.v6, sizeof(r.v6));
                    r.hasV6 = true;
                    r.hasV4 = false;
                } else {
                    std::memcpy(r.v4, parsed.v4, sizeof(r.v4));
                    r.hasV4 = true;
                    r.hasV6 = false;
                }
            }
            newRules->AddRule(r);
            ++loaded;
        }
    }

    // Atomically replace the active rule set.
    {
        std::lock_guard<std::mutex> lock(m_mx);
        m_activeRules = newRules;
    }

    return loaded;
}

void Interceptor::Loop() {
    std::vector<uint8_t> buf(WINDIVERT_MTU_MAX);
    HANDLE handle = static_cast<HANDLE>(m_handle);
    std::unordered_map<std::array<uint8_t, 36>, TcpConn, KeyHash> tcpConns;
    uint64_t packetCount = 0;

    while (m_running.load()) {
        UINT recvLen = 0;
        WINDIVERT_ADDRESS addr;
        if (!g_api.Recv(handle, buf.data(), static_cast<UINT>(buf.size()), &recvLen, &addr)) {
            if (GetLastError() == ERROR_NO_DATA) break;  // shutting down
            if (!m_running.load()) break;
            continue;
        }

        ++packetCount;
        // Cleanup idle TCP flows every 1024 packets.
        if ((packetCount & 0x3FF) == 0) {
            const uint64_t now = GetTickCount64();
            for (auto it = tcpConns.begin(); it != tcpConns.end();) {
                if (now - it->second.lastSeen > 30000)
                    it = tcpConns.erase(it);
                else
                    ++it;
            }
        }

        PWINDIVERT_IPHDR   ip4 = nullptr;
        PWINDIVERT_IPV6HDR ip6 = nullptr;
        PWINDIVERT_TCPHDR  tcp = nullptr;
        PWINDIVERT_UDPHDR  udp = nullptr;
        PVOID              payload = nullptr;
        UINT               payloadLen = 0;
        UINT8              proto = 0;
        if (!g_api.Parse(buf.data(), recvLen, &ip4, &ip6, &proto, nullptr, nullptr, &tcp, &udp,
                         &payload, &payloadLen, nullptr, nullptr)) {
            // Unparseable frame: never touch it, just reinject.
            g_api.Send(handle, buf.data(), recvLen, nullptr, &addr);
            continue;
        }

        bool handled = false;

        // ====================================================================
        // TCP DNS (port 53) — passive interception, IPv4 and plain IPv6.
        // ====================================================================
        if (addr.Outbound && tcp && (ip4 || ip6) && Swap16(tcp->DstPort) == 53) {
            const uint8_t* base = buf.data();
            // Length of everything before the TCP header (IPv4 header + options,
            // or the fixed IPv6 header). ipOff is 0 at the NETWORK layer.
            const size_t l3len = static_cast<size_t>(
                reinterpret_cast<const uint8_t*>(tcp) - base);

            // Hijack plain IPv4 (options allowed) or a header-only IPv6 packet.
            // Anything exotic (IPv6 extension headers) is passed through as-is.
            const bool families =
                ip4 || (ip6 && l3len == sizeof(WINDIVERT_IPV6HDR));

            if (families && l3len + 20 <= recvLen) {
                std::array<uint8_t, 36> key{};
                if (ip4) {
                    std::memcpy(&key[0], &ip4->SrcAddr, 4);
                    std::memcpy(&key[16], &ip4->DstAddr, 4);
                } else {
                    std::memcpy(&key[0], ip6->SrcAddr, 16);
                    std::memcpy(&key[16], ip6->DstAddr, 16);
                }
                std::memcpy(&key[32], &tcp->SrcPort, 2);
                std::memcpy(&key[34], &tcp->DstPort, 2);

                const uint32_t seq = ntohl(tcp->SeqNum);
                const uint32_t ackn = ntohl(tcp->AckNum);
                const uint64_t now = GetTickCount64();

                // Emit a freshly built TCP/IP packet. `toClient` spoofs the
                // resolver (server -> client, injected inbound); otherwise the
                // packet keeps the client -> server orientation (outbound). Only
                // the captured L3 header is copied (bounds-checked above); the
                // TCP header is written clean, so no client option is ever echoed
                // and nothing is read past the frame.
                auto emit = [&](bool toClient, uint32_t seqv, uint32_t ackv, bool fin,
                                bool rst, bool psh, bool ackf, const uint8_t* data,
                                size_t dataLen) {
                    const size_t total = l3len + 20 + dataLen;
                    std::vector<uint8_t> pkt(total);
                    std::memcpy(pkt.data(), base, l3len);

                    if (ip4) {
                        auto* h = reinterpret_cast<WINDIVERT_IPHDR*>(pkt.data());
                        if (toClient) {
                            h->SrcAddr = ip4->DstAddr;
                            h->DstAddr = ip4->SrcAddr;
                        } else {
                            h->SrcAddr = ip4->SrcAddr;
                            h->DstAddr = ip4->DstAddr;
                        }
                        h->Length = htons(static_cast<uint16_t>(total));
                        h->TTL = 64;
                        h->Checksum = 0;
                    } else {
                        auto* h = reinterpret_cast<WINDIVERT_IPV6HDR*>(pkt.data());
                        if (toClient) {
                            std::memcpy(h->SrcAddr, ip6->DstAddr, sizeof(h->SrcAddr));
                            std::memcpy(h->DstAddr, ip6->SrcAddr, sizeof(h->DstAddr));
                        } else {
                            std::memcpy(h->SrcAddr, ip6->SrcAddr, sizeof(h->SrcAddr));
                            std::memcpy(h->DstAddr, ip6->DstAddr, sizeof(h->DstAddr));
                        }
                        h->Length = htons(static_cast<uint16_t>(20 + dataLen));
                        h->HopLimit = 64;
                    }

                    auto* t = reinterpret_cast<WINDIVERT_TCPHDR*>(pkt.data() + l3len);
                    std::memset(t, 0, 20);
                    if (toClient) {
                        t->SrcPort = tcp->DstPort;  // :53
                        t->DstPort = tcp->SrcPort;  // client's ephemeral port
                    } else {
                        t->SrcPort = tcp->SrcPort;
                        t->DstPort = tcp->DstPort;
                    }
                    t->SeqNum = htonl(seqv);
                    t->AckNum = htonl(ackv);
                    t->HdrLength = 5;
                    t->Fin = fin ? 1 : 0;
                    t->Rst = rst ? 1 : 0;
                    t->Psh = psh ? 1 : 0;
                    t->Ack = ackf ? 1 : 0;
                    t->Window = htons(64240);
                    t->Checksum = 0;
                    if (dataLen) std::memcpy(pkt.data() + l3len + 20, data, dataLen);

                    WINDIVERT_ADDRESS a = addr;
                    a.Outbound = toClient ? 0 : 1;
                    a.IPChecksum = 0;
                    a.TCPChecksum = 0;
                    g_api.Calc(pkt.data(), static_cast<UINT>(pkt.size()), &a, 0);
                    g_api.Send(handle, pkt.data(), static_cast<UINT>(pkt.size()), nullptr, &a);
                };

                auto it = tcpConns.find(key);
                const bool known = it != tcpConns.end();
                const bool hijacked = known && it->second.hijacked;

                if (tcp->Syn) {
                    // Start of a connection: never forged. Drop any stale state
                    // for a reused 4-tuple and let the real handshake proceed.
                    if (known) tcpConns.erase(it);
                    // handled == false -> pass through
                } else if (tcp->Rst) {
                    // Teardown. On our hijacked flow the resolver side is already
                    // gone, so the stray RST is dropped; otherwise it is a real
                    // flow's RST and must reach the resolver.
                    if (known) tcpConns.erase(it);
                    handled = hijacked;
                } else if (hijacked) {
                    TcpConn& c = it->second;
                    c.lastSeen = now;
                    if (payload && payloadLen > 0) {
                        // The client retransmitted its query — it never saw our
                        // answer. Replay the exact response, carrying the FIN in
                        // the same segment.
                        emit(true, c.respSeq, c.respAck, true, false, true, true,
                             c.respPayload.data(), c.respPayload.size());  // PSH,FIN,ACK + data
                    } else if (tcp->Fin) {
                        // Client is closing its half (CLOSE_WAIT -> LAST_ACK on its
                        // side). Acknowledge its FIN as the resolver to finish the
                        // four-way close cleanly.
                        emit(true, c.ourSeq, seq + 1, false, false, false, true, nullptr, 0);
                    }
                    // A hijacked flow's packets must never reach the resolver.
                    handled = true;
                } else if (payload && payloadLen > 0) {
                    TcpConn& c = tcpConns[key];
                    c.lastSeen = now;
                    if (!c.haveSeq) {
                        c.expectedSeq = seq;
                        c.haveSeq = true;
                    }

                    bool inOrder = true;
                    if (seq == c.expectedSeq) {
                        const uint8_t* d = static_cast<const uint8_t*>(payload);
                        c.recvBuf.insert(c.recvBuf.end(), d, d + payloadLen);
                        c.expectedSeq += payloadLen;
                    } else if (seq + payloadLen <= c.expectedSeq) {
                        // Pure retransmit of bytes we already hold: nothing new.
                    } else {
                        // Out-of-order gap: reassembly would be unreliable. Stop
                        // tracking and let the real resolver own the whole flow.
                        tcpConns.erase(key);
                        inOrder = false;
                    }

                    if (inOrder && c.recvBuf.size() >= 2) {
                        const size_t dnsLen = Read16(c.recvBuf.data());
                        if (c.recvBuf.size() >= dnsLen + 2) {
                            const uint8_t* dnsMsg = c.recvBuf.data() + 2;

                            Query q;
                            const Rule* rule = nullptr;
                            if (ParseQuery(dnsMsg, dnsLen, q) && q.qclass == kClassIn) {
                                std::lock_guard<std::mutex> lock(m_mx);
                                rule = MatchLocked(q.name);
                            }

                            Action act = Action::PassThrough;
                            if (rule)
                                act = (rule->action == RuleAction::Block)
                                          ? Action::NoData
                                          : DecideAction(q.qtype);

                            std::vector<uint8_t> dns;
                            if (rule && act != Action::PassThrough)
                                dns = BuildResponse(dnsMsg, dnsLen, q, *rule, act);

                            if (!dns.empty()) {
                                // Wrap the DNS message in its 2-byte length prefix.
                                std::vector<uint8_t> resp;
                                Put16(resp, static_cast<uint16_t>(dns.size()));
                                resp.insert(resp.end(), dns.begin(), dns.end());

                                // The client's ACK is exactly the resolver's next
                                // send sequence; its seq+payloadLen is exactly the
                                // end of the (contiguous) query we must acknowledge.
                                const uint32_t respSeq = ackn;
                                const uint32_t respAck = seq + payloadLen;
                                const uint32_t finSeq =
                                    respSeq + static_cast<uint32_t>(resp.size());

                                emit(true, respSeq, respAck, true, false, true, true,
                                     resp.data(), resp.size());        // PSH,FIN,ACK + data
                                // Tear down the resolver's now-orphaned connection.
                                // Its rcv_nxt equals this segment's seq (the query
                                // never reached it), so this RST is accepted.
                                emit(false, seq, ackn, false, true, false, true, nullptr, 0);

                                c.hijacked = true;
                                c.respPayload = std::move(resp);
                                c.respSeq = respSeq;
                                c.respAck = respAck;
                                c.finSeq = finSeq;
                                c.ourSeq = finSeq + 1;
                                c.recvBuf.clear();
                                c.recvBuf.shrink_to_fit();
                                handled = true;  // drop the original query
                            } else {
                                // No rule, or a pass-through query type: deliver the
                                // query untouched so the real resolver answers.
                                tcpConns.erase(key);
                                // handled == false -> reinjected below
                            }
                        }
                        // Incomplete query: fall through, forward this segment and
                        // keep buffering until the rest arrives.
                    }
                    // Gap / duplicate / incomplete -> pass through below.
                }
                // Bare ACK on an untracked flow -> pass through below.
            }
        }
        // ====================================================================
        // UDP DNS (port 53, 5353 MDNS, 5355 LLMNR)
        // ====================================================================
        else if (addr.Outbound && udp && payload && payloadLen >= 12) {
            const uint16_t dstPort = Swap16(udp->DstPort);

            Query q;
            if (!ParseQuery(static_cast<const uint8_t*>(payload), payloadLen, q)) {
                // Malformed - pass through
                g_api.Send(handle, buf.data(), recvLen, nullptr, &addr);
                continue;
            }

            std::string queryName = q.name;

            // MDNS: strip .local suffix
            if (dstPort == 5353 && queryName.size() > 6 &&
                queryName.substr(queryName.size() - 6) == ".local") {
                queryName = queryName.substr(0, queryName.size() - 6);
            }

            const Rule* rule = (q.qclass == kClassIn) ? MatchLocked(q.name) : nullptr;

            if (rule) {
                const Action action = (rule->action == RuleAction::Block)
                                          ? Action::NoData
                                          : DecideAction(q.qtype);
                if (action != Action::PassThrough) {
                    const std::vector<uint8_t> resp = BuildResponse(
                        static_cast<const uint8_t*>(payload), payloadLen, q, *rule, action);

                    if (!resp.empty()) {
                        const uint8_t* base = buf.data();
                        const bool inBounds =
                            static_cast<const uint8_t*>(payload) >
                                reinterpret_cast<const uint8_t*>(udp) &&
                            reinterpret_cast<const uint8_t*>(udp) >= base &&
                            static_cast<size_t>(static_cast<const uint8_t*>(payload) - base) <=
                                recvLen;

                        if (inBounds) {
                            const size_t payloadOff =
                                static_cast<size_t>(static_cast<const uint8_t*>(payload) - base);
                            const size_t udpOff = static_cast<size_t>(
                                reinterpret_cast<const uint8_t*>(udp) - base);

                            std::vector<uint8_t> out(payloadOff + resp.size());
                            std::memcpy(out.data(), base, payloadOff);
                            std::memcpy(out.data() + payloadOff, resp.data(), resp.size());

                            if (ip4) {
                                auto* h = reinterpret_cast<WINDIVERT_IPHDR*>(out.data());
                                const uint32_t originalDst = h->DstAddr;
                                h->DstAddr = h->SrcAddr;

                                // Never use multicast as source (224-239.x.x.x).
                                // originalDst is network order, so its first wire
                                // octet is the low byte.
                                const uint8_t firstOctet =
                                    static_cast<uint8_t>(originalDst & 0xFF);
                                if (firstOctet >= 224 && firstOctet <= 239) {
                                    h->SrcAddr = h->DstAddr;  // Use querier's IP
                                } else {
                                    h->SrcAddr = originalDst;  // Spoof DNS server
                                }

                                h->Length = Swap16(static_cast<uint16_t>(out.size()));
                                h->TTL = 64;
                                h->Checksum = 0;
                            } else if (ip6) {
                                auto* h = reinterpret_cast<WINDIVERT_IPV6HDR*>(out.data());
                                // DstAddr is stored in network byte order; the
                                // multicast prefix ff00::/8 is the first wire byte.
                                const bool isMulticast =
                                    reinterpret_cast<const uint8_t*>(h->DstAddr)[0] == 0xFF;

                                uint32_t originalDst[4];
                                std::memcpy(originalDst, h->DstAddr, sizeof(originalDst));

                                for (int i = 0; i < 4; ++i) {
                                    h->DstAddr[i] = h->SrcAddr[i];
                                    h->SrcAddr[i] = isMulticast ? h->DstAddr[i] : originalDst[i];
                                }

                                h->Length = Swap16(static_cast<uint16_t>(8 + resp.size()));
                            }

                            auto* outUdp = reinterpret_cast<WINDIVERT_UDPHDR*>(out.data() + udpOff);
                            std::swap(outUdp->SrcPort, outUdp->DstPort);
                            outUdp->Length = Swap16(static_cast<uint16_t>(8 + resp.size()));
                            outUdp->Checksum = 0;

                            WINDIVERT_ADDRESS reply = addr;
                            reply.Outbound = 0;
                            reply.IPChecksum = 0;
                            reply.UDPChecksum = 0;
                            reply.TCPChecksum = 0;
                            g_api.Calc(out.data(), static_cast<UINT>(out.size()), &reply, 0);
                            g_api.Send(handle, out.data(), static_cast<UINT>(out.size()),
                                       nullptr, &reply);
                            handled = true;
                        }
                    }
                }
            }
        }

        // Pass through unhandled packets
        if (!handled) {
            g_api.Send(handle, buf.data(), recvLen, nullptr, &addr);
        }
    }
}

bool Interceptor::Start(const std::wstring& winDivertDll) {
    if (m_running.load()) return true;
    LoadWinDivertOnce(winDivertDll);
    if (!g_api.ok()) {
        m_handle = nullptr;
        return false;
    }

    // Capture outbound DNS: UDP/TCP:53, MDNS:5353, LLMNR:5355
    HANDLE handle = g_api.Open(
        "outbound and ("
        "(udp and (udp.DstPort == 53 or udp.DstPort == 5353 or udp.DstPort == 5355)) or "
        "(tcp and tcp.DstPort == 53)"
        ")",
        WINDIVERT_LAYER_NETWORK, 0, 0);

    if (handle == INVALID_HANDLE_VALUE) {
        m_handle = nullptr;
        return false;
    }
    m_handle = handle;
    m_running.store(true);
    m_thread = std::thread([this] { Loop(); });
    return true;
}

void Interceptor::Stop() {
    if (!m_running.exchange(false)) return;
    if (m_handle) g_api.Shutdown(static_cast<HANDLE>(m_handle), WINDIVERT_SHUTDOWN_BOTH);
    if (m_thread.joinable()) m_thread.join();
    if (m_handle) {
        g_api.Close(static_cast<HANDLE>(m_handle));
        m_handle = nullptr;
    }
}

}  // namespace Dns
