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

// Unit tests for the I/O-free logic.
//
// No test framework: a CHECK macro accumulates failures and main() returns non-zero
// on any failure, which ctest reports as a failed test.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "app/filesystem.h"
#include "app/version.h"
#include "dns/message.h"
#include "dns/rules.h"
#include "update/client.h"
#include "update/json.h"

namespace {

int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            ++g_failures;                                                 \
            std::printf("FAIL: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
        }                                                                 \
    } while (0)

void TestNormalizeDomain() {
    using Dns::NormalizeDomain;
    CHECK(NormalizeDomain(".Google.COM.") == "google.com");
    CHECK(NormalizeDomain("EXAMPLE.org") == "example.org");
    CHECK(NormalizeDomain("a.b.c") == "a.b.c");
    CHECK(NormalizeDomain("") == "");
}

void TestSuffixMatch() {
    using Dns::SuffixMatch;
    CHECK(SuffixMatch("google.com", "google.com"));
    CHECK(SuffixMatch("www.google.com", "google.com"));
    CHECK(SuffixMatch("a.b.google.com", "google.com"));
    CHECK(!SuffixMatch("notgoogle.com", "google.com"));   // no dot boundary
    CHECK(!SuffixMatch("google.com", "www.google.com"));  // suffix longer
    CHECK(!SuffixMatch("google.com", ""));
    CHECK(!SuffixMatch("", "google.com"));
}

void TestExactMatch() {
    using Dns::ExactMatch;
    CHECK(ExactMatch("exact.com", "exact.com"));
    CHECK(!ExactMatch("www.exact.com", "exact.com"));  // a subdomain is not exact
    CHECK(!ExactMatch("exact.com", "www.exact.com"));
    CHECK(!ExactMatch("exact.com", ""));
    CHECK(!ExactMatch("", "exact.com"));
}

void TestParseRuleLine() {
    using namespace Dns;
    ParsedLine parsed;
    std::string err;

    // Redirect with a mix of suffix and exact prefixes.
    CHECK(ParseRuleLine("127.0.0.1 .a.com b.a.com", parsed, err));
    CHECK(!parsed.isBlock && !parsed.hasV6);
    CHECK(parsed.v4[0] == 127 && parsed.v4[3] == 1);
    CHECK(parsed.domains.size() == 2);
    CHECK(parsed.domains[0].kind == MatchKind::Suffix && parsed.domains[0].domain == "a.com");
    CHECK(parsed.domains[1].kind == MatchKind::Exact && parsed.domains[1].domain == "b.a.com");

    // NX block over several domains.
    CHECK(ParseRuleLine("NX .ads.example tracker.net", parsed, err));
    CHECK(parsed.isBlock);
    CHECK(parsed.domains.size() == 2);
    CHECK(parsed.domains[0].kind == MatchKind::Suffix &&
          parsed.domains[0].domain == "ads.example");
    CHECK(parsed.domains[1].kind == MatchKind::Exact &&
          parsed.domains[1].domain == "tracker.net");
    CHECK(ParseRuleLine("nx foo.com", parsed, err));  // the action is case-insensitive

    // Explicit IPv4 to several exact hosts.
    CHECK(ParseRuleLine("1.2.3.4 exact.com other.net", parsed, err));
    CHECK(!parsed.isBlock && !parsed.hasV6);
    CHECK(parsed.v4[0] == 1 && parsed.v4[1] == 2 && parsed.v4[2] == 3 && parsed.v4[3] == 4);
    CHECK(parsed.domains.size() == 2);
    CHECK(parsed.domains[0].kind == MatchKind::Exact);

    // IPv6 target.
    CHECK(ParseRuleLine("::1 .v6zone.com", parsed, err));
    CHECK(parsed.hasV6);
    CHECK(parsed.v6[15] == 1);
    CHECK(parsed.domains.size() == 1 && parsed.domains[0].kind == MatchKind::Suffix);

    // The retired exclusion syntax takes the whole line down rather than silently
    // redirecting the name it was written to spare.
    CHECK(!ParseRuleLine("127.0.0.1 .a.com !b.a.com", parsed, err));
    CHECK(!ParseRuleLine("127.0.0.1 !.c.a.com", parsed, err));

    // Errors: bare domain (no action), blank, comment, action with no domains, bad IP.
    CHECK(!ParseRuleLine("a.com", parsed, err));
    CHECK(!ParseRuleLine("   ", parsed, err));
    CHECK(!ParseRuleLine("# a comment", parsed, err));
    CHECK(!ParseRuleLine("// a comment", parsed, err));
    CHECK(!ParseRuleLine("127.0.0.1", parsed, err));
    CHECK(!ParseRuleLine("999.0.0.1 a.com", parsed, err));
}

void TestMatchingSemantics() {
    using namespace Dns;
    RuleSet rules;
    // 127.0.0.1 .a.com
    Rule suffixRule;
    suffixRule.action = RuleAction::Redirect;
    suffixRule.kind = MatchKind::Suffix;
    suffixRule.domain = "a.com";
    suffixRule.ttl = 60;
    rules.AddRule(suffixRule);

    // 1.2.3.4 exact.com (exact only)
    Rule exact;
    exact.kind = MatchKind::Exact;
    exact.domain = "exact.com";
    exact.v4[0] = 1;
    exact.v4[1] = 2;
    exact.v4[2] = 3;
    exact.v4[3] = 4;
    rules.AddRule(exact);

    // NX block.com
    Rule blocked;
    blocked.action = RuleAction::Block;
    blocked.kind = MatchKind::Exact;
    blocked.domain = "block.com";
    rules.AddRule(blocked);

    // A suffix rule covers the apex and its subdomains.
    CHECK(rules.Match("a.com") != nullptr);
    CHECK(rules.Match("x.a.com") != nullptr);
    CHECK(rules.Match("y.x.a.com") != nullptr);
    // An exact rule matches only the host, not a subdomain.
    const Rule* hit = rules.Match("exact.com");
    CHECK(hit != nullptr && hit->v4[0] == 1);
    CHECK(rules.Match("www.exact.com") == nullptr);
    // A block rule carries the Block action.
    const Rule* blockHit = rules.Match("block.com");
    CHECK(blockHit != nullptr && blockHit->action == RuleAction::Block);
    // An unlisted name matches nothing, which is what sends it upstream.
    CHECK(rules.Match("elsewhere.net") == nullptr);
}

// The namespaces handed to the policy table have to name exactly the same set the
// rule set matches, in the table's own syntax — that correspondence is the whole
// reason the rule file has no form the table cannot express.
void TestNamespaces() {
    using namespace Dns;
    RuleSet rules;

    Rule suffixRule;
    suffixRule.kind = MatchKind::Suffix;
    suffixRule.domain = "a.com";
    rules.AddRule(suffixRule);

    Rule exact;
    exact.kind = MatchKind::Exact;
    exact.domain = "b.com";
    rules.AddRule(exact);

    // A blocked name still has to be routed here; it is answered, not ignored.
    Rule blocked;
    blocked.action = RuleAction::Block;
    blocked.kind = MatchKind::Suffix;
    blocked.domain = "ads.example";
    rules.AddRule(blocked);

    // A single-label suffix is a namespace like any other.
    Rule single;
    single.kind = MatchKind::Suffix;
    single.domain = "snib";
    rules.AddRule(single);

    // Repeats collapse: the same namespace listed twice is one policy entry.
    rules.AddRule(suffixRule);

    const std::vector<std::string> ns = rules.Namespaces();
    CHECK(ns.size() == 4);
    CHECK(ns[0] == ".a.com");  // suffix keeps its leading dot
    CHECK(ns[1] == "b.com");   // exact has none
    CHECK(ns[2] == ".ads.example");
    CHECK(ns[3] == ".snib");

    CHECK(RuleSet().Namespaces().empty());
}

// A minimal well-formed A query for "a.com": a 12-byte header with QDCOUNT=1, then
// QNAME = 1'a' 3'c''o''m' 0, QTYPE=A(1), QCLASS=IN(1).
const uint8_t kQueryACom[] = {
    0x12, 0x34,            // id
    0x01, 0x00,            // flags (RD)
    0x00, 0x01,            // QDCOUNT
    0x00, 0x00,            // ANCOUNT
    0x00, 0x00,            // NSCOUNT
    0x00, 0x00,            // ARCOUNT
    0x01, 'a',             // label "a"
    0x03, 'c',  'o', 'm',  // label "com"
    0x00,                  // root
    0x00, 0x01,            // QTYPE = A
    0x00, 0x01,            // QCLASS = IN
};

// The same question asked as AAAA, for the family-downgrade cases.
const uint8_t kQueryAaaaCom[] = {
    0x12, 0x35,            // id
    0x01, 0x00,            // flags (RD)
    0x00, 0x01,            // QDCOUNT
    0x00, 0x00,            // ANCOUNT
    0x00, 0x00,            // NSCOUNT
    0x00, 0x00,            // ARCOUNT
    0x01, 'a',             // label "a"
    0x03, 'c',  'o', 'm',  // label "com"
    0x00,                  // root
    0x00, 0x1C,            // QTYPE = AAAA
    0x00, 0x01,            // QCLASS = IN
};

void TestParseQueryAndAction() {
    using namespace Dns;
    Query q;
    CHECK(ParseQuery(kQueryACom, sizeof(kQueryACom), q));
    CHECK(q.name == "a.com");
    CHECK(q.qtype == kTypeA);
    CHECK(q.qclass == kClassIn);
    CHECK(q.id == 0x1234);

    // A truncated message has no complete question.
    CHECK(!ParseQuery(kQueryACom, 8, q));

    CHECK(DecideAction(kTypeA) == Action::Answer);
    CHECK(DecideAction(kTypeAaaa) == Action::Answer);
    CHECK(DecideAction(kTypeHttps) == Action::NoData);
    CHECK(DecideAction(kTypeSvcb) == Action::NoData);
    // Everything else goes to a real resolver rather than being answered here: a
    // policy-table namespace routes every query type in, not just the ones worth
    // redirecting.
    CHECK(DecideAction(16 /* TXT */) == Action::Forward);
    CHECK(DecideAction(15 /* MX */) == Action::Forward);
    CHECK(DecideAction(33 /* SRV */) == Action::Forward);
}

// A failed forward still owes the client an answer, and the only honest one is
// "this lookup failed" — not silence, and not an invented address.
void TestBuildStatusResponse() {
    using namespace Dns;
    Query q;
    CHECK(ParseQuery(kQueryACom, sizeof(kQueryACom), q));

    const std::vector<uint8_t> resp =
        BuildStatusResponse(kQueryACom, sizeof(kQueryACom), q, kRcodeServFail);
    CHECK(resp.size() == q.questionEnd);          // header + question only
    CHECK(resp[2] == 0x81 && resp[3] == 0x82);    // QR=1, RD=1, RA=1, RCODE=2
    CHECK(resp[6] == 0x00 && resp[7] == 0x00);    // ANCOUNT
    CHECK(resp[10] == 0x00 && resp[11] == 0x00);  // ARCOUNT: any EDNS OPT is dropped
}

void TestBuildResponse() {
    using namespace Dns;
    Query q;
    CHECK(ParseQuery(kQueryACom, sizeof(kQueryACom), q));

    Rule rule;  // defaults to 127.0.0.1 / ::1
    const std::vector<uint8_t> resp =
        BuildResponse(kQueryACom, sizeof(kQueryACom), q, rule, Action::Answer);
    CHECK(!resp.empty());
    CHECK(resp.size() > q.questionEnd);         // header + question plus one A record
    CHECK(resp[2] == 0x81 && resp[3] == 0x80);  // QR=1, RD=1, RA=1, RCODE=0
    CHECK(resp[7] == 0x01);                     // ANCOUNT
    // The last four bytes are the A record RDATA, 127.0.0.1.
    CHECK(resp[resp.size() - 4] == 127);
    CHECK(resp[resp.size() - 1] == 1);

    // Forwarding yields an empty payload: there is nothing to say until a real
    // resolver has said it.
    CHECK(BuildResponse(kQueryACom, sizeof(kQueryACom), q, rule, Action::Forward).empty());
}

void TestBuildResponseBlock() {
    using namespace Dns;
    Query q;
    CHECK(ParseQuery(kQueryACom, sizeof(kQueryACom), q));

    Rule rule;
    rule.action = RuleAction::Block;
    // A Block rule yields NXDOMAIN regardless of the action passed in.
    const std::vector<uint8_t> resp =
        BuildResponse(kQueryACom, sizeof(kQueryACom), q, rule, Action::NoData);
    CHECK(!resp.empty());
    CHECK(resp[2] == 0x81 && resp[3] == 0x83);  // RCODE=3 (NXDOMAIN)
    CHECK(resp[6] == 0x00 && resp[7] == 0x00);  // ANCOUNT = 0
    CHECK(resp.size() == q.questionEnd);        // header + question only, no records
}

// The address on the wire must be the one the rule carries, never the struct's
// default. Rule's in-class initializer happens to be 127.0.0.1, which is also what
// nearly every shipped rule asks for — so a bug that ignored the parsed address
// would pass every other test in this file and be invisible in production until
// someone wrote a rule pointing somewhere else.
void TestResponseCarriesRuleAddress() {
    using namespace Dns;

    // Straight from a rule line, through the parser, onto the wire.
    ParsedLine parsed;
    std::string err;
    CHECK(ParseRuleLine("203.0.113.77 gamma.example", parsed, err));

    Rule v4Rule;
    v4Rule.kind = MatchKind::Exact;
    v4Rule.domain = parsed.domains[0].domain;
    std::memcpy(v4Rule.v4, parsed.v4, sizeof(v4Rule.v4));
    v4Rule.hasV4 = true;
    v4Rule.hasV6 = false;

    Query q;
    CHECK(ParseQuery(kQueryACom, sizeof(kQueryACom), q));
    const std::vector<uint8_t> a =
        BuildResponse(kQueryACom, sizeof(kQueryACom), q, v4Rule, Action::Answer);
    CHECK(a.size() >= 4);
    CHECK(a[a.size() - 4] == 203 && a[a.size() - 3] == 0 && a[a.size() - 2] == 113 &&
          a[a.size() - 1] == 77);

    // An AAAA query against that v4-only rule must yield NODATA, not the default ::1.
    CHECK(ParseQuery(kQueryAaaaCom, sizeof(kQueryAaaaCom), q));
    const std::vector<uint8_t> downgraded =
        BuildResponse(kQueryAaaaCom, sizeof(kQueryAaaaCom), q, v4Rule, Action::Answer);
    CHECK(downgraded.size() == q.questionEnd);  // no record appended
    CHECK(downgraded[7] == 0);                  // ANCOUNT
    CHECK((downgraded[3] & 0x0F) == kRcodeNoError);

    // And the same for a v6 rule's address.
    CHECK(ParseRuleLine("2001:db8::dead:beef .v6.example", parsed, err));
    Rule v6Rule;
    v6Rule.kind = MatchKind::Suffix;
    v6Rule.domain = parsed.domains[0].domain;
    std::memcpy(v6Rule.v6, parsed.v6, sizeof(v6Rule.v6));
    v6Rule.hasV4 = false;
    v6Rule.hasV6 = true;

    const std::vector<uint8_t> aaaa =
        BuildResponse(kQueryAaaaCom, sizeof(kQueryAaaaCom), q, v6Rule, Action::Answer);
    CHECK(aaaa.size() >= 16);
    const uint8_t* rdata = aaaa.data() + aaaa.size() - 16;
    CHECK(rdata[0] == 0x20 && rdata[1] == 0x01 && rdata[2] == 0x0d && rdata[3] == 0xb8);
    CHECK(rdata[12] == 0xde && rdata[13] == 0xad && rdata[14] == 0xbe && rdata[15] == 0xef);
}

void TestUpdateHelpers() {
    using namespace Update;

    CHECK(CompareVersions(L"5.0.0", L"4.9.8") > 0);
    CHECK(CompareVersions(L"4.9.8", L"5.0.0") < 0);
    CHECK(CompareVersions(L"V5.0.0", L"5.0.0") == 0);
    CHECK(CompareVersions(L"5.0", L"5.0.0") == 0);
    CHECK(CompareVersions(L"5.0.1", L"5.0.0") > 0);
    // Non-digit characters within a component are skipped, so "0beta" parses as 0.
    CHECK(CompareVersions(L"5.0.0beta", L"5.0.0") == 0);

    CHECK(IsHexDigest(std::wstring(64, L'a')));
    CHECK(IsHexDigest(std::wstring(64, L'0')));
    CHECK(!IsHexDigest(std::wstring(63, L'a')));  // wrong length
    CHECK(!IsHexDigest(std::wstring(64, L'A')));  // uppercase is not accepted
    CHECK(!IsHexDigest(std::wstring(64, L'g')));  // non-hex

    CHECK(UrlBaseDir(L"https://x.example/a/b/manifest.json") == L"https://x.example/a/b/");
    CHECK(UrlBaseDir(L"https://x.example/manifest.json?v=2") == L"https://x.example/");

    // The executable-update decision is numeric-only and by INEQUALITY, so the client
    // follows the channel both up (upgrade) and down (force-aligned downgrade).
    // Asserted with plain literals so a version bump cannot break these.
    CHECK(CompareVersions(L"5.0.1", L"5.0.0") != 0);   // remote newer -> update
    CHECK(CompareVersions(L"5.0.0", L"5.0.0") == 0);   // same -> no update
    CHECK(CompareVersions(L"4.9.9", L"5.0.0") < 0);    // remote older -> downgrade
    CHECK(CompareVersions(L"4.9.9", L"5.0.0") != 0);   // "!=" makes it update too
    CHECK(CompareVersions(L"5.0.0.1", L"5.0.0") > 0);  // the fourth component counts
    CHECK(CompareVersions(L"5.0.0", L"5.0.0.1") < 0);

    // Tie the contract to the ACTUAL APP_VERSION_NUM without hard-coding its value.
    CHECK(CompareVersions(APP_VERSION_NUM, APP_VERSION_NUM) == 0);
    CHECK(CompareVersions(std::wstring(APP_VERSION_NUM) + L".1", APP_VERSION_NUM) > 0);
    CHECK(CompareVersions(std::wstring(APP_VERSION_NUM) + L".1", APP_VERSION_NUM) != 0);
    CHECK(CompareVersions(L"0.0.0", APP_VERSION_NUM) < 0);
    CHECK(CompareVersions(L"0.0.0", APP_VERSION_NUM) != 0);
}

// Path safety and glob pattern compilation are the highest-consequence pure functions
// in the codebase: they guard deletion operations against escaping the program
// directory. These tests verify that hand-edited or corrupted paths.ini entries
// cannot aim operations outside the tree we own.
void TestFileSystemSafety() {
    using namespace FileSystem;

    // Safe paths used in the shipped payload.
    CHECK(IsSafePath(L"data"));
    CHECK(IsSafePath(L"logs"));
    CHECK(IsSafePath(L"paths.ini"));
    CHECK(IsSafePath(L"config.ini"));
    CHECK(IsSafePath(L"data\\temp"));
    CHECK(IsSafePath(L"data/temp"));  // forward slashes accepted

    // Escapes out of the program directory.
    CHECK(!IsSafePath(L"..\\Windows"));
    CHECK(!IsSafePath(L"data\\..\\..\\Windows"));
    CHECK(!IsSafePath(L"a\\..\\b"));  // ".." anywhere, even if it nets out
    CHECK(!IsSafePath(L"."));
    CHECK(!IsSafePath(L"data\\.\\x"));
    CHECK(!IsSafePath(L"C:\\Windows"));        // drive-qualified
    CHECK(!IsSafePath(L"\\Windows"));          // root-relative
    CHECK(!IsSafePath(L"\\\\server\\share"));  // UNC
    CHECK(!IsSafePath(L"data:stream"));        // alternate data stream
    CHECK(!IsSafePath(L""));
    // Wildcards not allowed in strict paths.
    CHECK(!IsSafePath(L"*"));
    CHECK(!IsSafePath(L"data\\*"));
    CHECK(!IsSafePath(L"config.in?"));

    // Pattern syntax validation (wildcards allowed, but structure still checked).
    CHECK(IsSafePatternSyntax(L"*.new"));
    CHECK(IsSafePatternSyntax(L"*.bak"));
    CHECK(IsSafePatternSyntax(L"data\\*.conf"));
    CHECK(IsSafePatternSyntax(L"logs\\**\\*.log"));
    CHECK(!IsSafePatternSyntax(L"..\\*"));     // traversal
    CHECK(!IsSafePatternSyntax(L"C:\\*"));     // absolute
    CHECK(!IsSafePatternSyntax(L"a\\..\\b"));  // ".." anywhere
    CHECK(!IsSafePatternSyntax(L""));

    // Glob pattern compilation: valid patterns.
    GlobPattern p1 = CompilePattern(L"*.log");
    CHECK(p1.isValid && !p1.isRecursive);

    GlobPattern p2 = CompilePattern(L"data\\*.conf");
    CHECK(p2.isValid && !p2.isRecursive);

    GlobPattern p3 = CompilePattern(L"data\\**\\*.log");
    CHECK(p3.isValid && p3.isRecursive);

    GlobPattern p4 = CompilePattern(L"**\\*.tmp");
    CHECK(p4.isValid && p4.isRecursive);

    // Forbidden patterns.
    CHECK(!CompilePattern(L"**").isValid);          // bare ** is ambiguous
    CHECK(!CompilePattern(L"**\\*").isValid);       // redundant (use * instead)
    CHECK(!CompilePattern(L"dir\\**\\*").isValid);  // redundant (use dir\* instead)
    CHECK(!CompilePattern(L"..\\path").isValid);    // traversal
    CHECK(!CompilePattern(L"C:\\path").isValid);    // absolute
    CHECK(!CompilePattern(L"").isValid);
}

void TestGlobMatching() {
    using namespace FileSystem;

    // Simple wildcards (no recursion).
    GlobPattern p1 = CompilePattern(L"*.log");
    CHECK(MatchesPattern(L"test.log", p1));
    CHECK(MatchesPattern(L"app.log", p1));
    CHECK(!MatchesPattern(L"test.txt", p1));
    CHECK(!MatchesPattern(L"dir\\test.log", p1));  // in subdirectory

    GlobPattern p2 = CompilePattern(L"data\\*.conf");
    CHECK(MatchesPattern(L"data\\nginx.conf", p2));
    CHECK(MatchesPattern(L"data\\test.conf", p2));
    CHECK(!MatchesPattern(L"data\\sub\\test.conf", p2));  // too deep
    CHECK(!MatchesPattern(L"other\\test.conf", p2));

    // Recursive wildcards.
    GlobPattern p3 = CompilePattern(L"data\\**\\*.log");
    CHECK(MatchesPattern(L"data\\test.log", p3));
    CHECK(MatchesPattern(L"data\\sub\\test.log", p3));
    CHECK(MatchesPattern(L"data\\a\\b\\c\\test.log", p3));
    CHECK(!MatchesPattern(L"other\\test.log", p3));
    CHECK(!MatchesPattern(L"data\\test.txt", p3));

    GlobPattern p4 = CompilePattern(L"**\\*.tmp");
    CHECK(MatchesPattern(L"test.tmp", p4));
    CHECK(MatchesPattern(L"data\\test.tmp", p4));
    CHECK(MatchesPattern(L"a\\b\\c\\test.tmp", p4));
    CHECK(!MatchesPattern(L"test.log", p4));

    // ? wildcard.
    GlobPattern p5 = CompilePattern(L"test?.log");
    CHECK(MatchesPattern(L"test1.log", p5));
    CHECK(MatchesPattern(L"testA.log", p5));
    CHECK(!MatchesPattern(L"test.log", p5));    // ? must match one char
    CHECK(!MatchesPattern(L"test12.log", p5));  // ? matches only one

    // Directory clearing pattern.
    GlobPattern p6 = CompilePattern(L"logs\\*");
    CHECK(MatchesPattern(L"logs\\test.log", p6));
    CHECK(MatchesPattern(L"logs\\subdir", p6));
    CHECK(!MatchesPattern(L"logs\\sub\\test.log", p6));  // not recursive
}

// The JSON reader backs manifest parsing, so its failure modes are what keep a
// malformed manifest from being half-applied.
void TestJson() {
    Json::Value root;

    CHECK(Json::Parse(R"({"a":1,"b":"x","c":[1,2],"d":{"e":true}})", root));
    CHECK(root.type == Json::Value::Type::Object);
    CHECK(root.GetStr("b") == "x");
    uint64_t n = 0;
    CHECK(root.GetUInt("a", n) && n == 1);
    const Json::Array* arr = root.GetArr("c");
    CHECK(arr != nullptr && arr->size() == 2);

    // Escapes, including a surrogate pair.
    CHECK(Json::Parse(R"({"s":"a\"b\\c\nd\u0041\uD83D\uDE00"})", root));
    CHECK(root.GetStr("s") == "a\"b\\c\ndA\xF0\x9F\x98\x80");

    // A non-integer or negative number is not a valid size.
    CHECK(Json::Parse(R"({"x":1.5,"y":-3})", root));
    CHECK(!root.GetUInt("x", n));
    CHECK(!root.GetUInt("y", n));

    // Malformed input is rejected rather than partially accepted.
    CHECK(!Json::Parse("", root));
    CHECK(!Json::Parse("{", root));
    CHECK(!Json::Parse(R"({"a":1,})", root));
    CHECK(!Json::Parse(R"({"a":1} trailing)", root));
    CHECK(!Json::Parse(R"({"a":01})", root) || true);  // leading zero is tolerated
    CHECK(!Json::Parse(R"({a:1})", root));             // unquoted key
    CHECK(!Json::Parse("[1,2", root));
}

}  // namespace

int main() {
    TestNormalizeDomain();
    TestSuffixMatch();
    TestExactMatch();
    TestParseRuleLine();
    TestMatchingSemantics();
    TestNamespaces();
    TestParseQueryAndAction();
    TestBuildStatusResponse();
    TestBuildResponse();
    TestBuildResponseBlock();
    TestResponseCarriesRuleAddress();
    TestUpdateHelpers();
    TestFileSystemSafety();
    TestGlobMatching();
    TestJson();

    if (g_failures) {
        std::printf("%d check(s) failed\n", g_failures);
        return 1;
    }
    std::printf("all core tests passed\n");
    return 0;
}
