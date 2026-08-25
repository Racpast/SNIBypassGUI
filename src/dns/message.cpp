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

#include "dns/message.h"

#include <utility>

namespace Dns {
namespace {

// DNS header and record fields are big-endian on the wire.
uint16_t Read16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
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

// The header and question of `query`, with a response header written over it:
// QR=1, RD=1, RA=1, `rcode` in the low nibble, and every section count zeroed.
// Zeroing ARCOUNT is what drops any EDNS OPT the client attached, which is why
// the caller may then append answer records without a stale count contradicting
// them. Returns an empty vector if the question does not lie inside the message.
std::vector<uint8_t> ResponseSkeleton(const uint8_t* query, size_t qlen, const Query& q,
                                      uint8_t rcode) {
    if (q.questionEnd == 0 || q.questionEnd > qlen) return {};
    std::vector<uint8_t> r(query, query + q.questionEnd);
    r[2] = 0x81;                                // QR=1, opcode 0, RD=1
    r[3] = static_cast<uint8_t>(0x80 | rcode);  // RA=1, RCODE
    r[6] = 0;
    r[7] = 0;  // ANCOUNT
    r[8] = 0;
    r[9] = 0;  // NSCOUNT
    r[10] = 0;
    r[11] = 0;  // ARCOUNT
    return r;
}

}  // namespace

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

Action DecideAction(uint16_t qtype) {
    if (qtype == kTypeA || qtype == kTypeAaaa) return Action::Answer;
    // Force HTTPS/SVCB to NODATA so an alternative-endpoint or ECH record cannot
    // bypass the loopback redirect for a redirected name.
    if (qtype == kTypeHttps || qtype == kTypeSvcb) return Action::NoData;
    return Action::Forward;
}

std::vector<uint8_t> BuildResponse(const uint8_t* query, size_t qlen, const Query& q,
                                   const Rule& rule, Action action) {
    if (action == Action::Forward) return {};

    // A Block rule answers NXDOMAIN for any query type.
    const bool block = (rule.action == RuleAction::Block);
    bool answer = !block && action == Action::Answer;

    // A Redirect rule only holds one address family. If the query asks for the
    // family this rule does not carry (AAAA against a v4-only rule, or A against
    // a v6-only rule), downgrade to NODATA (NOERROR, no answer) so the redirect
    // is not bypassed and no bogus default address is returned.
    if (answer) {
        if (q.qtype == kTypeA && !rule.hasV4)
            answer = false;
        else if (q.qtype == kTypeAaaa && !rule.hasV6)
            answer = false;
    }

    std::vector<uint8_t> r =
        ResponseSkeleton(query, qlen, q, block ? kRcodeNxDomain : kRcodeNoError);
    if (r.empty() || !answer) return r;

    r[7] = 1;            // ANCOUNT
    Put16(r, 0xC00C);    // NAME as a pointer to the question at offset 12
    Put16(r, q.qtype);   // TYPE (A or AAAA)
    Put16(r, kClassIn);  // CLASS
    Put32(r, rule.ttl);
    if (q.qtype == kTypeA) {
        Put16(r, sizeof(rule.v4));
        r.insert(r.end(), rule.v4, rule.v4 + sizeof(rule.v4));
    } else {
        Put16(r, sizeof(rule.v6));
        r.insert(r.end(), rule.v6, rule.v6 + sizeof(rule.v6));
    }
    return r;
}

std::vector<uint8_t> BuildStatusResponse(const uint8_t* query, size_t qlen, const Query& q,
                                         uint8_t rcode) {
    return ResponseSkeleton(query, qlen, q, rcode);
}

}  // namespace Dns
