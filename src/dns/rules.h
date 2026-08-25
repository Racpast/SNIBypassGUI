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
// The redirect rule model: what a rule file says, and what a query name matches.
//
// Rule file syntax (hosts-style, space separated, action first):
//   ACTION domain [domain...]
// ACTION is either an IP (v4 or v6, the redirect target) or the literal "NX"
// (answer NXDOMAIN). Each domain carries an explicit matching prefix:
//   .a.com     apex and every subdomain (suffix match)
//   exact.com  that host only (exact match)
// A line with no ACTION is a parse error and is skipped; there is no implicit
// "bare domain means 127.0.0.1".
//
// Those two forms are exactly the two forms the Name Resolution Policy Table can
// express, and that correspondence is the point: the rule file IS the policy
// table, written once and installed verbatim. A rule set therefore never has to
// disagree with the NRPT about which names are redirected, which is what an
// exclusion syntax would have forced — the NRPT can only carve a name out of an
// enclosing subtree by routing it to a literal DNS server address pinned into the
// registry, and any such address is wrong the moment the machine changes network.
//
// This header is pure logic: no sockets, no registry, no Windows. It is what the
// unit tests exercise, and both consumers — the policy table, which needs the
// namespaces, and the local resolver, which needs the match — read the same
// parsed set.
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace Dns {

// How a rule's `domain` is compared against a query name.
//   Exact  matches that host only ("exact.com" is not "www.exact.com")
//   Suffix matches the apex and every subdomain (".a.com" covers a.com, x.a.com)
enum class MatchKind { Exact, Suffix };

// What a matched query gets.
//   Redirect synthesizes an A/AAAA answer pointing at v4/v6
//   Block    answers NXDOMAIN
enum class RuleAction { Redirect, Block };

// One redirect rule. `domain` is a bare lowercased name with no leading or
// trailing dot; `kind` selects exact versus suffix matching explicitly.
struct Rule {
    RuleAction action = RuleAction::Redirect;
    MatchKind kind = MatchKind::Suffix;
    std::string domain;
    uint8_t v4[4] = {127, 0, 0, 1};
    uint8_t v6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};  // ::1
    // Which families this redirect can actually answer. A rule loaded from a file
    // carries exactly one address, so a v4-only rule answers A and returns NODATA
    // for AAAA (and vice versa) instead of handing back a bogus default address.
    bool hasV4 = true;
    bool hasV6 = true;
    uint32_t ttl = 60;
};

// Normalize a domain for storage and matching: lowercase, strip a leading dot and
// any trailing dot.
std::string NormalizeDomain(std::string d);

bool SuffixMatch(const std::string& name, const std::string& suffix);
bool ExactMatch(const std::string& name, const std::string& domain);

// A single domain token from a rule line, with the match kind its prefix selected.
struct ParsedDomain {
    MatchKind kind = MatchKind::Exact;
    std::string domain;
};

// A parsed rule line: an action (IP redirect or NX block) plus its domains.
struct ParsedLine {
    bool isBlock = false;  // true means NXDOMAIN
    bool hasV6 = false;    // redirect family, when !isBlock
    uint8_t v4[4] = {};
    uint8_t v6[16] = {};
    std::vector<ParsedDomain> domains;
};

// Parse one rule line. Returns false with a diagnostic in `err` for a blank or
// comment line, or a syntax error (missing action, bad IP, no domains).
bool ParseRuleLine(const std::string& line, ParsedLine& out, std::string& err);

// An immutable set of rules, published once and never mutated afterwards. That is
// what makes hot-reload safe without locking the read path: a reload builds a
// replacement and swaps the pointer, so a query in flight keeps reading the set it
// started with and the next one sees the new set whole.
class RuleSet {
public:
    RuleSet() = default;
    RuleSet(const RuleSet&) = delete;
    RuleSet& operator=(const RuleSet&) = delete;

    void AddRule(const Rule& r);
    size_t RuleCount() const;

    // The rule covering `name`, or null when no rule lists it.
    //
    // A null answer is not expected from a query the policy table routed here —
    // every installed namespace comes from a rule in this very set. It stays
    // meaningful anyway: during a hot-reload the two are momentarily out of step,
    // and a stale policy rule from an earlier run can outlive the set that
    // produced it. The resolver forwards those upstream rather than inventing an
    // answer for a name nobody claimed.
    const Rule* Match(const std::string& name) const;

    // The namespaces to install in the policy table, in its own syntax: ".a.com"
    // for a subtree, "exact.com" for a single host. Deduplicated, in first-seen
    // order.
    std::vector<std::string> Namespaces() const;

private:
    std::vector<Rule> m_rules;
};

// Parse a hosts-style rule file into a fresh, immutable rule set.
//
// This is the one place that turns file text into rules: the initial load and
// every hot-reload go through it, so the two can never drift apart in what they
// accept or how they report a bad line. Returns null if the file cannot be read;
// `loaded` receives the number of rules. `context` names the caller in log lines
// about bad syntax.
std::shared_ptr<const RuleSet> LoadRuleFile(const std::wstring& path, const wchar_t* context,
                                            size_t& loaded);

}  // namespace Dns
