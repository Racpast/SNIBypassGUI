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

// select() watches a fixed-size descriptor array whose bound is decided here,
// before anything can declare fd_set. The static_assert further down ties the
// value to the connection limits, so the two can never be raised apart.
#define FD_SETSIZE 128

#include "dns/resolver.h"

#include <mswsock.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>

#include <iphlpapi.h>

#include <cstring>
#include <utility>
#include <vector>

#include "app/logging.h"
#include "dns/message.h"

namespace Dns {
namespace {

// A message is length-prefixed with 16 bits on TCP, so this is the largest one
// that can exist on either transport.
constexpr size_t kMaxMessage = 65535;

// How many client connections are served at once, and how long one may sit idle.
// TCP here is the rare fallback after a truncated reply, not the normal path.
constexpr size_t kMaxTcpSessions = 32;
constexpr uint64_t kTcpIdleTimeoutMs = 15000;

// Outstanding forwards, and how long one waits before the client is told the
// lookup failed rather than left waiting for a reply that is not coming.
constexpr size_t kMaxPendingUdp = 256;
constexpr uint64_t kForwardTimeoutMs = 4000;

// A query is sent to this many of the machine's DNS servers at once. Asking two
// costs one extra datagram and removes the need to notice that the first one is
// dead and try the next: whichever answers first is the answer.
constexpr size_t kUpstreamsQueried = 2;

// How long a discovered server list is trusted before it is read again. Joining a
// VPN or renewing a lease replaces the machine's resolvers underneath us.
constexpr uint64_t kUpstreamRefreshMs = 10000;

// How often the loop wakes when nothing is happening, which is also the longest a
// Stop() waits and the resolution of every deadline above.
constexpr long kTickMs = 100;

// Every socket the loop can watch has to fit in one fd_set: two listeners, two
// upstream sockets, and a client plus an upstream connection per TCP session.
static_assert(kMaxTcpSessions * 2 + 4 <= FD_SETSIZE,
              "select() cannot watch that many sockets at once");

uint64_t Now() {
    return GetTickCount64();
}

// Winsock, started once for the process and never stopped.
//
// WSACleanup belongs to a program that is finished with sockets, and this one is
// finished with them only when it exits — at which point the kernel does the same
// work. Tying it to a static destructor instead would run it in an order no
// translation unit here controls, while a detached worker may still hold a socket.
bool EnsureWinsock() {
    static const bool ready = [] {
        WSADATA data;
        return WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }();
    return ready;
}

void SetNonBlocking(SOCKET s) {
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
}

// Stop Windows from failing a later recvfrom with WSAECONNRESET because an earlier
// datagram drew an ICMP port-unreachable. On a socket that talks to several
// servers at once, one dead server would otherwise poison reads for all of them.
void DisableUdpConnReset(SOCKET s) {
    BOOL off = FALSE;
    DWORD returned = 0;
    WSAIoctl(s, SIO_UDP_CONNRESET, &off, sizeof(off), nullptr, 0, &returned, nullptr, nullptr);
}

// Bind one listener on the resolver endpoint. SO_EXCLUSIVEADDRUSE is what stops
// another program from later binding the same address with SO_REUSEADDR and
// quietly taking delivery of the queries meant for us.
SOCKET BindListener(int type, int protocol) {
    SOCKET s = socket(AF_INET, type, protocol);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    BOOL exclusive = TRUE;
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive),
               sizeof(exclusive));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kResolverPort);
    if (InetPtonW(AF_INET, kResolverAddress, &addr.sin_addr) != 1 ||
        bind(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        const int err = WSAGetLastError();
        closesocket(s);
        WSASetLastError(err);
        return INVALID_SOCKET;
    }
    SetNonBlocking(s);
    return s;
}

// An ephemeral socket for talking to real DNS servers of one family.
SOCKET MakeUpstreamSocket(int family) {
    SOCKET s = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    DisableUdpConnReset(s);
    SetNonBlocking(s);
    return s;
}

// ---- Upstream discovery ------------------------------------------------------

struct Upstream {
    sockaddr_storage addr = {};
    int len = 0;
};

// Compare two addresses by family and address bytes, ignoring the port: the port
// is ours to set, and the same server must not be queried twice because two
// adapters list it.
bool SameHost(const sockaddr_storage& a, const sockaddr_storage& b) {
    if (a.ss_family != b.ss_family) return false;
    if (a.ss_family == AF_INET) {
        return std::memcmp(&reinterpret_cast<const sockaddr_in&>(a).sin_addr,
                           &reinterpret_cast<const sockaddr_in&>(b).sin_addr,
                           sizeof(in_addr)) == 0;
    }
    if (a.ss_family == AF_INET6) {
        return std::memcmp(&reinterpret_cast<const sockaddr_in6&>(a).sin6_addr,
                           &reinterpret_cast<const sockaddr_in6&>(b).sin6_addr,
                           sizeof(in6_addr)) == 0;
    }
    return false;
}

// True if `sa` is a server worth sending a query to.
bool UsableUpstream(const sockaddr* sa) {
    if (sa->sa_family == AF_INET) {
        const in_addr& v4 = reinterpret_cast<const sockaddr_in*>(sa)->sin_addr;
        if (v4.s_addr == 0) return false;  // "no server configured"

        // Our own listener: forwarding to it would be a loop with itself.
        in_addr self = {};
        InetPtonW(AF_INET, kResolverAddress, &self);
        return v4.s_addr != self.s_addr;
    }
    if (sa->sa_family == AF_INET6) {
        const in6_addr& v6 = reinterpret_cast<const sockaddr_in6*>(sa)->sin6_addr;
        const uint8_t* b = v6.s6_addr;

        bool allZero = true;
        for (int i = 0; i < 16; ++i)
            if (b[i] != 0) allZero = false;
        if (allZero) return false;

        // fec0:0:0:ffff::1 through ::3 are the placeholders Windows lists when a
        // machine has no IPv6 resolver of its own. Nothing answers on them.
        static const uint8_t kPlaceholderPrefix[14] = {0xFE, 0xC0, 0, 0, 0, 0, 0xFF,
                                                       0xFF, 0,    0, 0, 0, 0, 0};
        if (std::memcmp(b, kPlaceholderPrefix, sizeof(kPlaceholderPrefix)) == 0 && b[14] == 0 &&
            b[15] >= 1 && b[15] <= 3)
            return false;
        return true;
    }
    return false;
}

// The DNS servers configured on every adapter that is up, deduplicated and in the
// order Windows reports them — which is the order Windows itself would try.
std::vector<Upstream> DiscoverUpstreams() {
    std::vector<Upstream> out;

    ULONG size = 16 * 1024;
    std::vector<uint8_t> buffer;
    ULONG status = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 4 && status == ERROR_BUFFER_OVERFLOW; ++attempt) {
        buffer.assign(size, 0);
        status = GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                GAA_FLAG_SKIP_FRIENDLY_NAME,
            nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
    }
    if (status != NO_ERROR) {
        LOGW(L"Resolver: cannot read the machine's DNS servers (err " +
             std::to_wstring(status) + L").");
        return out;
    }

    for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); adapter;
         adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp) continue;
        for (auto* server = adapter->FirstDnsServerAddress; server; server = server->Next) {
            const sockaddr* sa = server->Address.lpSockaddr;
            const int len = server->Address.iSockaddrLength;
            if (!sa || len <= 0 || static_cast<size_t>(len) > sizeof(sockaddr_storage))
                continue;
            if (!UsableUpstream(sa)) continue;

            Upstream entry;
            std::memcpy(&entry.addr, sa, static_cast<size_t>(len));
            entry.len = len;
            if (entry.addr.ss_family == AF_INET)
                reinterpret_cast<sockaddr_in&>(entry.addr).sin_port = htons(53);
            else
                reinterpret_cast<sockaddr_in6&>(entry.addr).sin6_port = htons(53);

            bool duplicate = false;
            for (const Upstream& known : out)
                if (SameHost(known.addr, entry.addr)) duplicate = true;
            if (!duplicate) out.push_back(entry);
        }
    }
    return out;
}

// ---- In-flight state ---------------------------------------------------------

// A UDP query handed to the upstreams, waiting for one of them to answer.
struct PendingUdp {
    sockaddr_storage client = {};
    int clientLen = 0;
    uint16_t clientId = 0;    // the id to put back before replying
    uint16_t upstreamId = 0;  // the id we asked under, and our key
    uint64_t deadline = 0;
    std::vector<uint8_t> question;  // header + question, to answer with on failure
    Query query;
};

// One TCP client connection, and the upstream connection opened for it if the
// query it carried has to be forwarded. Exactly one query is served at a time; a
// second one that arrives early simply waits in `in` until the first is answered.
struct TcpSession {
    SOCKET client = INVALID_SOCKET;
    SOCKET upstream = INVALID_SOCKET;
    bool connecting = false;  // the upstream connect has not completed
    bool busy = false;        // a query is being served and owes a response

    std::vector<uint8_t> in;   // bytes read from the client
    std::vector<uint8_t> out;  // length-prefixed response owed to the client
    size_t outSent = 0;

    std::vector<uint8_t> upOut;  // length-prefixed query owed to the upstream
    size_t upSent = 0;
    std::vector<uint8_t> upIn;  // reply arriving from the upstream

    std::vector<uint8_t> question;  // header + question, to answer with on failure
    Query query;
    uint64_t deadline = 0;
};

void CloseSocket(SOCKET& s) {
    if (s != INVALID_SOCKET) {
        closesocket(s);
        s = INVALID_SOCKET;
    }
}

}  // namespace

// Everything the loop owns. Its destructor is the only place sockets are released,
// which is what lets a failed Start() unwind by simply letting the object go.
struct ResolverState {
    SOCKET udp = INVALID_SOCKET;
    SOCKET tcp = INVALID_SOCKET;
    SOCKET upstream4 = INVALID_SOCKET;
    SOCKET upstream6 = INVALID_SOCKET;

    std::vector<Upstream> upstreams;
    uint64_t upstreamsAt = 0;

    std::vector<PendingUdp> pending;
    std::vector<TcpSession> sessions;

    uint32_t idState = 0;          // xorshift state for upstream query ids
    std::vector<uint8_t> scratch;  // one datagram at a time

    ~ResolverState() {
        for (TcpSession& session : sessions) {
            CloseSocket(session.client);
            CloseSocket(session.upstream);
        }
        CloseSocket(udp);
        CloseSocket(tcp);
        CloseSocket(upstream4);
        CloseSocket(upstream6);
    }
};

namespace {

void RefreshUpstreams(ResolverState& s) {
    const uint64_t now = Now();
    if (s.upstreamsAt != 0 && now - s.upstreamsAt < kUpstreamRefreshMs) return;
    s.upstreams = DiscoverUpstreams();
    s.upstreamsAt = now;
}

// An unused transaction id for an upstream query.
//
// The id is what a reply is matched against, so it is drawn from a scrambled
// sequence rather than a counter: a predictable id is an invitation for an
// off-path forgery to land before the real answer does. Source address and
// question are checked as well, on the way in.
uint16_t NextUpstreamId(ResolverState& s) {
    for (int attempt = 0; attempt < 64; ++attempt) {
        s.idState ^= s.idState << 13;
        s.idState ^= s.idState >> 17;
        s.idState ^= s.idState << 5;
        const uint16_t candidate = static_cast<uint16_t>(s.idState);
        bool taken = false;
        for (const PendingUdp& p : s.pending)
            if (p.upstreamId == candidate) taken = true;
        if (!taken) return candidate;
    }
    return static_cast<uint16_t>(s.idState);
}

// The response this resolver would give for `q`, or an empty vector meaning the
// query is not ours to answer and must be forwarded.
std::vector<uint8_t> TryAnswer(const RuleSet& rules, const uint8_t* msg, size_t len,
                               const Query& q) {
    // Only a standard query is interpreted. A response arriving at a listener, an
    // UPDATE or a NOTIFY means something this resolver has no opinion about, and
    // rewriting its header as if it were a lookup would corrupt it.
    if ((q.flags & 0x8000) != 0) return {};       // QR: already a response
    if (((q.flags >> 11) & 0xF) != 0) return {};  // opcode other than QUERY
    if (q.qclass != kClassIn) return {};

    const Rule* rule = rules.Match(q.name);
    if (!rule) return {};

    // A Block rule owns every query type; BuildResponse turns it into NXDOMAIN
    // whatever action it is handed, so only a Redirect consults the query type.
    const Action action =
        (rule->action == RuleAction::Block) ? Action::NoData : DecideAction(q.qtype);
    if (action == Action::Forward) return {};
    return BuildResponse(msg, len, q, *rule, action);
}

// ---- UDP ---------------------------------------------------------------------

void SendUdp(ResolverState& s, const std::vector<uint8_t>& msg, const sockaddr_storage& to,
             int toLen) {
    if (msg.empty()) return;
    sendto(s.udp, reinterpret_cast<const char*>(msg.data()), static_cast<int>(msg.size()), 0,
           reinterpret_cast<const sockaddr*>(&to), toLen);
}

void ForwardUdp(ResolverState& s, const uint8_t* msg, size_t len, const Query& q,
                const sockaddr_storage& from, int fromLen) {
    RefreshUpstreams(s);

    std::vector<uint8_t> question(msg, msg + q.questionEnd);
    if (s.upstreams.empty() || s.pending.size() >= kMaxPendingUdp) {
        SendUdp(s, BuildStatusResponse(question.data(), question.size(), q, kRcodeServFail),
                from, fromLen);
        return;
    }

    // Relayed verbatim apart from the transaction id, so the client's own EDNS
    // advertisement — and therefore the size at which the upstream will truncate —
    // survives the trip.
    const uint16_t id = NextUpstreamId(s);
    std::vector<uint8_t> outbound(msg, msg + len);
    outbound[0] = static_cast<uint8_t>(id >> 8);
    outbound[1] = static_cast<uint8_t>(id);

    bool sent = false;
    size_t queried = 0;
    for (const Upstream& upstream : s.upstreams) {
        if (queried >= kUpstreamsQueried) break;
        const SOCKET sock = (upstream.addr.ss_family == AF_INET6) ? s.upstream6 : s.upstream4;
        if (sock == INVALID_SOCKET) continue;
        ++queried;
        if (sendto(sock, reinterpret_cast<const char*>(outbound.data()),
                   static_cast<int>(outbound.size()), 0,
                   reinterpret_cast<const sockaddr*>(&upstream.addr),
                   upstream.len) != SOCKET_ERROR)
            sent = true;
    }
    if (!sent) {
        SendUdp(s, BuildStatusResponse(question.data(), question.size(), q, kRcodeServFail),
                from, fromLen);
        return;
    }

    PendingUdp entry;
    entry.client = from;
    entry.clientLen = fromLen;
    entry.clientId = q.id;
    entry.upstreamId = id;
    entry.deadline = Now() + kForwardTimeoutMs;
    entry.question = std::move(question);
    entry.query = q;
    s.pending.push_back(std::move(entry));
}

void HandleUdpQuery(ResolverState& s, const RuleSet& rules) {
    sockaddr_storage from = {};
    int fromLen = sizeof(from);
    const int received = recvfrom(s.udp, reinterpret_cast<char*>(s.scratch.data()),
                                  static_cast<int>(s.scratch.size()), 0,
                                  reinterpret_cast<sockaddr*>(&from), &fromLen);
    if (received <= 0) return;

    const size_t len = static_cast<size_t>(received);
    Query q;
    // A message that cannot be read cannot be answered or meaningfully forwarded:
    // there is no question to echo back, so there is nothing to say.
    if (!ParseQuery(s.scratch.data(), len, q)) return;

    std::vector<uint8_t> response = TryAnswer(rules, s.scratch.data(), len, q);
    if (!response.empty()) {
        SendUdp(s, response, from, fromLen);
        return;
    }
    ForwardUdp(s, s.scratch.data(), len, q, from, fromLen);
}

void HandleUpstreamReply(ResolverState& s, SOCKET sock) {
    sockaddr_storage from = {};
    int fromLen = sizeof(from);
    const int received = recvfrom(sock, reinterpret_cast<char*>(s.scratch.data()),
                                  static_cast<int>(s.scratch.size()), 0,
                                  reinterpret_cast<sockaddr*>(&from), &fromLen);
    if (received < 12) return;
    const size_t len = static_cast<size_t>(received);

    // Three things have to agree before a datagram is treated as the answer: it
    // came from a server we actually use, it carries the id we asked under, and it
    // repeats the question we asked. Any one of them alone is forgeable.
    bool fromUpstream = false;
    for (const Upstream& upstream : s.upstreams)
        if (SameHost(upstream.addr, from)) fromUpstream = true;
    if (!fromUpstream) return;

    const uint16_t id = static_cast<uint16_t>((s.scratch[0] << 8) | s.scratch[1]);
    for (auto it = s.pending.begin(); it != s.pending.end(); ++it) {
        if (it->upstreamId != id) continue;
        if (len < it->question.size() ||
            std::memcmp(s.scratch.data() + 12, it->question.data() + 12,
                        it->question.size() - 12) != 0)
            return;

        s.scratch[0] = static_cast<uint8_t>(it->clientId >> 8);
        s.scratch[1] = static_cast<uint8_t>(it->clientId);
        sendto(s.udp, reinterpret_cast<const char*>(s.scratch.data()), received, 0,
               reinterpret_cast<const sockaddr*>(&it->client), it->clientLen);
        s.pending.erase(it);
        return;
    }
}

// ---- TCP ---------------------------------------------------------------------

// Prefix a response with its 16-bit length and queue it for the client.
void QueueResponse(TcpSession& t, const std::vector<uint8_t>& message) {
    t.out.clear();
    t.out.reserve(message.size() + 2);
    t.out.push_back(static_cast<uint8_t>(message.size() >> 8));
    t.out.push_back(static_cast<uint8_t>(message.size()));
    t.out.insert(t.out.end(), message.begin(), message.end());
    t.outSent = 0;
}

void CloseUpstream(TcpSession& t) {
    CloseSocket(t.upstream);
    t.connecting = false;
    t.upOut.clear();
    t.upSent = 0;
    t.upIn.clear();
}

// Give up on a forward and tell the client the lookup failed, which is the one
// thing it must not be left wondering about.
void FailTcpForward(TcpSession& t) {
    CloseUpstream(t);
    QueueResponse(
        t, BuildStatusResponse(t.question.data(), t.question.size(), t.query, kRcodeServFail));
    t.deadline = Now() + kTcpIdleTimeoutMs;
}

void StartTcpForward(ResolverState& s, TcpSession& t) {
    RefreshUpstreams(s);
    if (s.upstreams.empty()) {
        FailTcpForward(t);
        return;
    }
    // One server, not two: a second connection would double the work to salvage a
    // path that is already the fallback after a truncated UDP reply.
    const Upstream& upstream = s.upstreams.front();
    SOCKET sock = socket(upstream.addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        FailTcpForward(t);
        return;
    }
    SetNonBlocking(sock);
    if (connect(sock, reinterpret_cast<const sockaddr*>(&upstream.addr), upstream.len) ==
            SOCKET_ERROR &&
        WSAGetLastError() != WSAEWOULDBLOCK) {
        closesocket(sock);
        FailTcpForward(t);
        return;
    }
    t.upstream = sock;
    t.connecting = true;
    t.deadline = Now() + kForwardTimeoutMs;
}

// Serve the next complete query sitting in the client's buffer, if there is one
// and nothing else is in flight. Returns false when the connection is unusable.
bool ServeBufferedQuery(ResolverState& s, TcpSession& t, const RuleSet& rules) {
    if (t.busy || t.in.size() < 2) return true;
    const size_t len = static_cast<size_t>((t.in[0] << 8) | t.in[1]);
    if (len == 0) return false;              // a framing this broken has no recovery
    if (t.in.size() < len + 2) return true;  // still arriving

    Query q;
    if (!ParseQuery(t.in.data() + 2, len, q)) return false;

    t.busy = true;
    std::vector<uint8_t> response = TryAnswer(rules, t.in.data() + 2, len, q);
    if (!response.empty()) {
        QueueResponse(t, response);
        t.in.erase(t.in.begin(), t.in.begin() + static_cast<ptrdiff_t>(len) + 2);
        return true;
    }

    // Forwarded whole, length prefix included, and under the client's own
    // transaction id: one query owns this connection, so there is nothing to
    // demultiplex and no reason to rewrite it.
    t.question.assign(t.in.begin() + 2,
                      t.in.begin() + 2 + static_cast<ptrdiff_t>(q.questionEnd));
    t.query = q;
    t.upOut.assign(t.in.begin(), t.in.begin() + static_cast<ptrdiff_t>(len) + 2);
    t.upSent = 0;
    t.in.erase(t.in.begin(), t.in.begin() + static_cast<ptrdiff_t>(len) + 2);
    StartTcpForward(s, t);
    return true;
}

bool ReadFromClient(ResolverState& s, TcpSession& t, const RuleSet& rules) {
    char buffer[4096];
    const int received = recv(t.client, buffer, sizeof(buffer), 0);
    if (received == 0) return false;  // the client closed its half
    if (received < 0) return WSAGetLastError() == WSAEWOULDBLOCK;
    if (t.in.size() + static_cast<size_t>(received) > kMaxMessage + 2) return false;

    t.in.insert(t.in.end(), buffer, buffer + received);
    if (!t.busy) t.deadline = Now() + kTcpIdleTimeoutMs;
    return ServeBufferedQuery(s, t, rules);
}

bool WriteToClient(ResolverState& s, TcpSession& t, const RuleSet& rules) {
    while (t.outSent < t.out.size()) {
        const int sent = send(t.client, reinterpret_cast<const char*>(t.out.data()) + t.outSent,
                              static_cast<int>(t.out.size() - t.outSent), 0);
        if (sent == SOCKET_ERROR) return WSAGetLastError() == WSAEWOULDBLOCK;
        t.outSent += static_cast<size_t>(sent);
    }
    t.out.clear();
    t.outSent = 0;
    t.busy = false;
    t.deadline = Now() + kTcpIdleTimeoutMs;
    // The client may already have pipelined the next one while this was in flight.
    return ServeBufferedQuery(s, t, rules);
}

// Finish connecting, then push the query out. Both halves live here because
// select reports either as "writable".
void WriteToUpstream(TcpSession& t) {
    if (t.connecting) {
        int error = 0;
        int errorLen = sizeof(error);
        if (getsockopt(t.upstream, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error),
                       &errorLen) == SOCKET_ERROR ||
            error != 0) {
            FailTcpForward(t);
            return;
        }
        t.connecting = false;
    }
    while (t.upSent < t.upOut.size()) {
        const int sent =
            send(t.upstream, reinterpret_cast<const char*>(t.upOut.data()) + t.upSent,
                 static_cast<int>(t.upOut.size() - t.upSent), 0);
        if (sent == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK) FailTcpForward(t);
            return;
        }
        t.upSent += static_cast<size_t>(sent);
    }
}

void ReadFromUpstream(TcpSession& t) {
    char buffer[4096];
    const int received = recv(t.upstream, buffer, sizeof(buffer), 0);
    if (received < 0) {
        if (WSAGetLastError() != WSAEWOULDBLOCK) FailTcpForward(t);
        return;
    }
    if (received == 0) {
        // Closed before a whole reply arrived; there is nothing to relay.
        FailTcpForward(t);
        return;
    }
    if (t.upIn.size() + static_cast<size_t>(received) > kMaxMessage + 2) {
        FailTcpForward(t);
        return;
    }
    t.upIn.insert(t.upIn.end(), buffer, buffer + received);

    if (t.upIn.size() < 2) return;
    const size_t len = static_cast<size_t>((t.upIn[0] << 8) | t.upIn[1]);
    if (t.upIn.size() < len + 2) return;

    // Relayed exactly as it came, truncation flag and all: the client asked over
    // TCP, so a reply that does not fit is the upstream's problem to have avoided.
    t.out.assign(t.upIn.begin(), t.upIn.begin() + static_cast<ptrdiff_t>(len) + 2);
    t.outSent = 0;
    CloseUpstream(t);
    t.deadline = Now() + kTcpIdleTimeoutMs;
}

void AcceptTcpClient(ResolverState& s) {
    sockaddr_storage from = {};
    int fromLen = sizeof(from);
    SOCKET client = accept(s.tcp, reinterpret_cast<sockaddr*>(&from), &fromLen);
    if (client == INVALID_SOCKET) return;
    if (s.sessions.size() >= kMaxTcpSessions) {
        closesocket(client);
        return;
    }
    SetNonBlocking(client);
    TcpSession session;
    session.client = client;
    session.deadline = Now() + kTcpIdleTimeoutMs;
    s.sessions.push_back(std::move(session));
}

// Everything one connection can do in a single pass. Returns false when it should
// be closed and dropped.
bool ServiceSession(ResolverState& s, TcpSession& t, fd_set& readable, fd_set& writable,
                    fd_set& failed, const RuleSet& rules) {
    if (t.upstream != INVALID_SOCKET) {
        // A refused connect is reported here rather than as writability.
        if (FD_ISSET(t.upstream, &failed)) {
            FailTcpForward(t);
        } else if (FD_ISSET(t.upstream, &writable)) {
            WriteToUpstream(t);
        } else if (FD_ISSET(t.upstream, &readable)) {
            ReadFromUpstream(t);
        }
    }
    if (!t.out.empty() && FD_ISSET(t.client, &writable)) {
        if (!WriteToClient(s, t, rules)) return false;
    } else if (t.out.empty() && FD_ISSET(t.client, &readable)) {
        if (!ReadFromClient(s, t, rules)) return false;
    }

    if (Now() < t.deadline) return true;
    // Out of time. A connection that is owed an answer gets one; an idle or stuck
    // one is simply dropped.
    if (t.busy && t.out.empty()) {
        FailTcpForward(t);
        return true;
    }
    return false;
}

void ExpirePendingUdp(ResolverState& s) {
    const uint64_t now = Now();
    for (auto it = s.pending.begin(); it != s.pending.end();) {
        if (now < it->deadline) {
            ++it;
            continue;
        }
        SendUdp(s,
                BuildStatusResponse(it->question.data(), it->question.size(), it->query,
                                    kRcodeServFail),
                it->client, it->clientLen);
        it = s.pending.erase(it);
    }
}

}  // namespace

// ---- LocalResolver -----------------------------------------------------------

LocalResolver::LocalResolver() : m_activeRules(std::make_shared<const RuleSet>()) {}

LocalResolver::~LocalResolver() {
    Stop();
}

void LocalResolver::Publish(std::shared_ptr<const RuleSet> rules) {
    std::lock_guard<std::mutex> lock(m_mx);
    m_activeRules = std::move(rules);
}

std::shared_ptr<const RuleSet> LocalResolver::ActiveRules() const {
    std::lock_guard<std::mutex> lock(m_mx);
    return m_activeRules;
}

bool LocalResolver::Start() {
    // A previous session may have ended on its own, leaving a joinable thread and
    // closed sockets behind. Tearing that down first means Start always begins from
    // a clean state and can never stack a second loop on the first.
    Stop();

    if (!EnsureWinsock()) {
        LOGE(L"Resolver: winsock could not be initialized.");
        return false;
    }

    // Held locally until everything has succeeded: on any failure the state object
    // goes out of scope and its destructor closes whatever was already opened.
    auto state = std::make_unique<ResolverState>();

    state->udp = BindListener(SOCK_DGRAM, IPPROTO_UDP);
    if (state->udp == INVALID_SOCKET) {
        LOGE(std::wstring(L"Resolver: cannot bind UDP ") + kResolverAddress + L":" +
             std::to_wstring(kResolverPort) + L" (err " + std::to_wstring(WSAGetLastError()) +
             L").");
        return false;
    }
    DisableUdpConnReset(state->udp);

    state->tcp = BindListener(SOCK_STREAM, IPPROTO_TCP);
    if (state->tcp == INVALID_SOCKET || listen(state->tcp, SOMAXCONN) == SOCKET_ERROR) {
        LOGE(std::wstring(L"Resolver: cannot listen on TCP ") + kResolverAddress + L":" +
             std::to_wstring(kResolverPort) + L" (err " + std::to_wstring(WSAGetLastError()) +
             L").");
        return false;
    }

    // Both families are opened up front; a machine with no IPv6 resolver simply
    // never uses the second one. Only losing both leaves nothing to forward with.
    state->upstream4 = MakeUpstreamSocket(AF_INET);
    state->upstream6 = MakeUpstreamSocket(AF_INET6);
    if (state->upstream4 == INVALID_SOCKET && state->upstream6 == INVALID_SOCKET) {
        LOGE(L"Resolver: cannot open a socket for forwarding (err " +
             std::to_wstring(WSAGetLastError()) + L").");
        return false;
    }

    state->scratch.resize(kMaxMessage);
    // Any seed will do as long as it is not zero, which xorshift cannot leave.
    state->idState = static_cast<uint32_t>(Now()) | 1u;

    m_state = std::move(state);
    m_running.store(true);
    m_thread = std::thread([this] { Loop(); });
    LOGI(std::wstring(L"Resolver: listening on ") + kResolverAddress + L":" +
         std::to_wstring(kResolverPort) + L".");
    return true;
}

void LocalResolver::Stop() {
    m_running.store(false);
    if (m_thread.joinable()) m_thread.join();
    m_state.reset();  // closes every socket
}

void LocalResolver::Loop() {
    ResolverState& s = *m_state;

    while (m_running.load()) {
        // One snapshot per pass, so every query answered in it sees the same rules
        // even if a hot-reload publishes a new set halfway through.
        const std::shared_ptr<const RuleSet> rules = ActiveRules();

        fd_set readable;
        fd_set writable;
        fd_set failed;
        FD_ZERO(&readable);
        FD_ZERO(&writable);
        FD_ZERO(&failed);

        FD_SET(s.udp, &readable);
        FD_SET(s.tcp, &readable);
        if (s.upstream4 != INVALID_SOCKET) FD_SET(s.upstream4, &readable);
        if (s.upstream6 != INVALID_SOCKET) FD_SET(s.upstream6, &readable);
        for (const TcpSession& session : s.sessions) {
            if (session.out.empty())
                FD_SET(session.client, &readable);
            else
                FD_SET(session.client, &writable);
            if (session.upstream != INVALID_SOCKET) {
                if (session.connecting || session.upSent < session.upOut.size()) {
                    FD_SET(session.upstream, &writable);
                    FD_SET(session.upstream, &failed);
                } else {
                    FD_SET(session.upstream, &readable);
                }
            }
        }

        timeval timeout = {0, kTickMs * 1000};
        const int ready = select(0, &readable, &writable, &failed, &timeout);
        if (ready == SOCKET_ERROR) {
            LOGE(L"Resolver: select failed (err " + std::to_wstring(WSAGetLastError()) +
                 L"); the local DNS server is stopping.");
            break;
        }

        if (ready > 0) {
            // Replies first: they retire pending entries, so a burst of forwards
            // cannot push one past its deadline while its answer sits unread.
            if (s.upstream4 != INVALID_SOCKET && FD_ISSET(s.upstream4, &readable))
                HandleUpstreamReply(s, s.upstream4);
            if (s.upstream6 != INVALID_SOCKET && FD_ISSET(s.upstream6, &readable))
                HandleUpstreamReply(s, s.upstream6);
            if (FD_ISSET(s.udp, &readable)) HandleUdpQuery(s, *rules);
            if (FD_ISSET(s.tcp, &readable)) AcceptTcpClient(s);
        }

        for (size_t i = 0; i < s.sessions.size();) {
            if (ServiceSession(s, s.sessions[i], readable, writable, failed, *rules)) {
                ++i;
                continue;
            }
            CloseSocket(s.sessions[i].client);
            CloseSocket(s.sessions[i].upstream);
            s.sessions.erase(s.sessions.begin() + static_cast<ptrdiff_t>(i));
        }

        ExpirePendingUdp(s);
    }

    // The loop can end without anyone asking — a failed select is the only way, but
    // it is a way. Clearing the flag here is what keeps "is the resolver running" an
    // honest answer rather than a memory of having started it.
    m_running.store(false);
}

}  // namespace Dns
