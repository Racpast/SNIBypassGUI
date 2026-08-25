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

#include "dns/rules.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstring>
#include <fstream>
#include <sstream>
#include <unordered_set>
#include <utility>

#include "app/logging.h"
#include "app/text.h"

namespace Dns {
namespace {

char Lower(char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

bool DomainCovers(MatchKind kind, const std::string& domain, const std::string& name) {
    return kind == MatchKind::Suffix ? SuffixMatch(name, domain) : ExactMatch(name, domain);
}

}  // namespace

// ---- Matching helpers --------------------------------------------------------

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

// ---- Rule line parsing -------------------------------------------------------

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
        // A '!' once introduced an exclusion. The whole line is rejected rather
        // than the token quietly dropped: dropping it would silently start
        // redirecting the very name the author wrote the line to spare, whereas a
        // rejected line makes the site stop working and says why in the log.
        if (token[0] == '!') {
            err = "'!' exclusions are no longer supported";
            return false;
        }
        const bool suffix = token[0] == '.';
        std::string normalized = NormalizeDomain(suffix ? token.substr(1) : token);
        if (normalized.empty()) continue;  // stray prefix with no domain
        out.domains.push_back(
            {suffix ? MatchKind::Suffix : MatchKind::Exact, std::move(normalized)});
    }
    if (out.domains.empty()) {
        err = "no domains";
        return false;
    }
    return true;
}

// ---- RuleSet -----------------------------------------------------------------

void RuleSet::AddRule(const Rule& r) {
    m_rules.push_back(r);
}

size_t RuleSet::RuleCount() const {
    return m_rules.size();
}

const Rule* RuleSet::Match(const std::string& name) const {
    for (const Rule& r : m_rules)
        if (DomainCovers(r.kind, r.domain, name)) return &r;
    return nullptr;
}

std::vector<std::string> RuleSet::Namespaces() const {
    std::vector<std::string> out;
    std::unordered_set<std::string> seen;
    out.reserve(m_rules.size());
    for (const Rule& r : m_rules) {
        std::string ns = (r.kind == MatchKind::Suffix) ? ("." + r.domain) : r.domain;
        if (seen.insert(ns).second) out.push_back(std::move(ns));
    }
    return out;
}

// ---- Rule file ---------------------------------------------------------------

std::shared_ptr<const RuleSet> LoadRuleFile(const std::wstring& path, const wchar_t* context,
                                            size_t& loaded) {
    loaded = 0;
    std::ifstream in(path.c_str(), std::ios::binary);
    if (!in) return nullptr;
    const std::string raw((std::istreambuf_iterator<char>(in)),
                          std::istreambuf_iterator<char>());

    auto rules = std::make_shared<RuleSet>();
    std::istringstream lines(raw);
    std::string line;
    int lineNo = 0;
    while (std::getline(lines, line)) {
        ++lineNo;
        if (!line.empty() && line.back() == '\r') line.pop_back();

        ParsedLine parsed;
        std::string err;
        if (!ParseRuleLine(line, parsed, err)) {
            // Blank and comment lines are skipped silently; real syntax errors log.
            if (err != "blank" && err != "comment")
                LOGW(std::wstring(context) + L": line " + std::to_wstring(lineNo) + L": " +
                     Utf8ToWide(err));
            continue;
        }

        for (const ParsedDomain& domain : parsed.domains) {
            Rule r;
            r.kind = domain.kind;
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
            rules->AddRule(r);
            ++loaded;
        }
    }
    return rules;
}

}  // namespace Dns
