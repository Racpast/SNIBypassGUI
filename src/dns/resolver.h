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
// The DNS server the policy table points at.
//
// It answers for the names the rule set claims and forwards everything else to
// the machine's real DNS servers, because a policy-table namespace is routed here
// WHOLE: every query type for every name under it, not just the address lookups
// worth redirecting. A resolver that only knew how to answer would therefore turn
// a redirected domain's MX, TXT and SRV records into silence. Forwarding is what
// keeps the redirect confined to what it is meant to change.
//
// UDP and TCP are both served on port 53. TCP is not optional: a forwarded reply
// can come back truncated, and the client's only recourse then is to ask the same
// server again over TCP.
//
// One thread runs one event loop. DNS on loopback is a trickle, and forwarding is
// the only thing here that ever waits on the network — so it is done without
// waiting, by remembering the query and matching the reply when it arrives.
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>

#include "dns/rules.h"

namespace Dns {

// The loopback endpoint this server binds to and the policy table routes to.
//
// Deliberately not 127.0.0.1. All of 127.0.0.0/8 reaches loopback, and port 53 on
// 127.0.0.1 is the conventional home of every other local DNS server a machine
// might already run — Docker's, an ICS host's, a filtering proxy's. Taking an
// address nobody picks by convention means coexisting with them instead of
// fighting for a port.
inline constexpr wchar_t kResolverAddress[] = L"127.11.45.14";
inline constexpr uint16_t kResolverPort = 53;

// Sockets and in-flight state, defined in the implementation so that no consumer
// of this header has to see winsock.
struct ResolverState;

class LocalResolver {
public:
    LocalResolver();
    ~LocalResolver();
    LocalResolver(const LocalResolver&) = delete;
    LocalResolver& operator=(const LocalResolver&) = delete;

    // Publish the rules to answer from. The set is never mutated after publishing,
    // so the loop reads its snapshot without locking anything and a hot-reload only
    // changes which set the next query sees. Safe before or after Start().
    void Publish(std::shared_ptr<const RuleSet> rules);

    // Bind both listeners and run the event loop on a worker thread. Any previous
    // session is torn down first, so this always starts from a clean state.
    // Returns false — having bound nothing — if the endpoint is unavailable.
    bool Start();

    // Stop the loop and close every socket. Each step is driven by the resource it
    // releases rather than by a "running" flag, because the loop can end on its
    // own, and an early return on that flag would leave a joinable std::thread to
    // be destroyed, which terminates the process.
    void Stop();

    bool Running() const { return m_running.load(); }

private:
    void Loop();
    std::shared_ptr<const RuleSet> ActiveRules() const;

    mutable std::mutex m_mx;
    std::shared_ptr<const RuleSet> m_activeRules;
    std::unique_ptr<ResolverState> m_state;
    std::thread m_thread;
    std::atomic<bool> m_running{false};
};

}  // namespace Dns
