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
// DNS message wire format: read a question, write an answer.
//
// Only what a redirecting resolver needs. Anything this module declines to answer
// is forwarded verbatim to a real upstream, so there is deliberately no reader for
// answer, authority or additional sections — bytes we do not synthesize are bytes
// we never have to parse.
#include <cstdint>
#include <string>
#include <vector>

#include "dns/rules.h"

namespace Dns {

enum : uint16_t { kTypeA = 1, kTypeAaaa = 28, kTypeSvcb = 64, kTypeHttps = 65 };
enum : uint16_t { kClassIn = 1 };

// The response codes this resolver ever puts on the wire itself.
enum : uint8_t { kRcodeNoError = 0, kRcodeServFail = 2, kRcodeNxDomain = 3 };

// A parsed DNS question (the first question only).
struct Query {
    uint16_t id = 0;
    uint16_t flags = 0;
    std::string name;  // lowercased, dotted, no trailing dot
    uint16_t qtype = 0;
    uint16_t qclass = 0;
    size_t questionEnd = 0;  // offset just past QNAME+QTYPE+QCLASS
};

// Parse the header and first question of a DNS message. Bounds checked; returns
// false on a malformed, compressed, or empty question.
bool ParseQuery(const uint8_t* dns, size_t len, Query& out);

// How a query whose name matched a Redirect rule should be handled.
//   Answer  synthesize an address record
//   NoData  NOERROR with an empty answer section
//   Forward relay to a real upstream and pass its reply back
enum class Action { Forward, Answer, NoData };
Action DecideAction(uint16_t qtype);

// Build a response for `q` using `rule`. For a Redirect rule, Answer appends one
// A/AAAA record and NoData yields an empty NOERROR answer; a Redirect that lacks
// the queried family (e.g. an AAAA query against a v4-only rule) is downgraded to
// NODATA rather than emitting a default address. A Block rule yields NXDOMAIN
// regardless of `action`, as long as it is not Forward.
std::vector<uint8_t> BuildResponse(const uint8_t* query, size_t qlen, const Query& q,
                                   const Rule& rule, Action action);

// Build a bare response carrying `rcode` and no records: the header and question
// echoed back, everything else empty. This is how a failed forward is reported,
// since the client is owed an answer even when there was nowhere to get one.
std::vector<uint8_t> BuildStatusResponse(const uint8_t* query, size_t qlen, const Query& q,
                                         uint8_t rcode);

}  // namespace Dns
