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
// DNS redirection, whole: the rules, the policy table that routes names here, and
// the server that answers them.
//
// The two mechanisms are one feature and are owned together, because they are only
// ever correct together. A policy rule pointing at a resolver that is not listening
// breaks every name it covers; a resolver holding rules the policy table has not
// been told about answers nothing. So they are brought up in the order that is safe
// to be interrupted in — resolver first, policy table second — taken down in the
// reverse one, and a hot-reload updates both from the same parse of the file.
//
// The rule set is owned here rather than by the resolver. The resolver needs
// something to match against; which names are redirected, and how many, is a question
// about the file this class read.
//
// Nothing is left behind by a clean stop. What an unclean one leaves is a single
// registry key with a fixed name, which the next start removes before it does
// anything else (see Services::EnforceCleanSlate).
//
// Being up is not a promise about the next second, and this class is what keeps
// watch over its own half of it. A guardian thread holds the invariant above for as
// long as the redirection is meant to be up, waiting — never polling — on the two
// events that can break it:
//
//   * the server's loop ending, which cannot be repaired in place and takes the
//     whole stack down with it;
//   * the policy rule being deleted or altered by something else, which CAN be
//     repaired exactly, because what the table should say is known here.
//
// The difference in treatment is the difference in what the two states cost. A rule
// that has gone missing sends the listed names back to their real addresses: those
// sites break the way they break when this program is not running, which is a
// recoverable, familiar failure. A server that has stopped answering while the rule
// still points at it is the other thing entirely — the queries are accepted by a
// socket nobody reads and never answered, so every listed name hangs until the
// client gives up. That one is not repaired, it is escaped.
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "dns/resolver.h"

namespace Dns {

class FileWatcher;

// Why redirection stopped, when it stopped on its own.
enum class RedirectFailure {
    None,            // it did not
    ServerStopped,   // the local DNS server's loop ended
    RuleUnholdable,  // something kept removing the policy rule faster than we could
                     // put it back
};

// How many times the policy rule may be repaired before the repairs are the
// problem.
//
// One deletion is an event: a network reset, a cleanup tool, an administrator with
// a script. Repairing it is right, and repairing it again an hour later is right
// too. What this bounds is the other case — something on the machine deleting the
// rule as fast as we write it — where every repair is immediately undone, DNS
// redirection is not working and will not start working, and continuing to write is
// spending the machine's time to hide that from the user. The honest end of that
// loop is to stop, say so, and take the stack down.
//
// A fixed window rather than a sliding one: the question is "is this a storm", and
// a count that resets on a quiet window answers it without keeping a history.
struct RepairBudget {
    // Generous enough that no plausible legitimate cause reaches it — Group Policy
    // refreshes on the order of minutes, a user running a cleanup tool twice — and
    // small enough that a real fight is over in under a second of writing.
    static constexpr unsigned kMaxRepairs = 5;
    static constexpr uint64_t kWindowMs = 60000;

    // Record one repair and say whether it was within budget. `nowMs` is a
    // monotonic millisecond clock; the caller supplies it so this is testable and
    // so the class holds no opinion about which clock.
    bool Allow(uint64_t nowMs);

    uint64_t windowStart = 0;
    unsigned used = 0;
    bool started = false;
};

class Redirector {
public:
    Redirector();
    ~Redirector();
    Redirector(const Redirector&) = delete;
    Redirector& operator=(const Redirector&) = delete;

    // Read `path` and hold the result as the rules to start with. Returns how many
    // rules were loaded; zero means the file was missing or said nothing.
    size_t LoadRules(const std::wstring& path);

    size_t RuleCount() const;

    // Start the local server, then route every namespace the rules name to it, then
    // begin watching both. Returns false having undone whatever it managed to do.
    //
    // A rule set that names nothing still starts the server. Nothing is routed to it,
    // so it sits idle, but a later edit to the rule file can then bring redirection up
    // through the hot-reload path rather than needing the stack restarted.
    bool Start();

    // Stop watching, stop names being sent here, then stop answering.
    void Stop();

    // Watch `path` and re-apply it when it changes, debounced to absorb editors
    // that write in chunks. A reload republishes the rules and rewrites the policy
    // table from the same parse. Safe to call before or after Start().
    void EnableHotReload(const std::wstring& path, unsigned debounceMs = 500);
    void DisableHotReload();

    // Is redirection actually in force?
    //
    // Both halves, because either one alone redirects nothing. The failure is folded
    // in rather than left for the teardown to reflect, so the moment the guardian
    // gives up this reads false — the tray does not have to wait for the stack to
    // finish coming down to stop claiming this works.
    bool Running() const {
        return m_resolver.Running() && m_failure.load() == RedirectFailure::None;
    }

    // Is there anything here for a Stop to undo?
    //
    // A different question from Running(), and deliberately a separate one. Running()
    // is about whether redirection works; this is about whether this object has
    // resources out in the world — a thread, a socket, a registry key — that someone
    // has to take back. A component that has failed answers no to the first and yes
    // to the second, and a teardown that asked the first question would walk past it
    // and leave the policy rule installed.
    bool Active() const {
        return m_resolver.Running() || m_failure.load() != RedirectFailure::None;
    }

    // Signalled when redirection has stopped in a way it cannot recover from, and
    // never by a stop that was asked for — Stop() ends the guardian before it touches
    // anything the guardian is watching.
    //
    // This is the whole of what the layer above needs to know. It waits on this
    // handle beside the child processes' handles, in one wait, and learns that DNS
    // redirection is down the same way and at the same instant it learns a child has
    // died. What broke, and whether it was worth trying to repair first, stays here.
    //
    // Typed as void* for the reason given in resolver.h; HANDLE is void*.
    void* failureHandle() const { return m_failed; }

    // What the last failure was, for the message the user is shown. Read it before
    // the Stop that reacts to it: a stop clears the failure, because after it there
    // is nothing left in a failed state to describe.
    RedirectFailure failure() const { return m_failure.load(); }

private:
    // Adopt `rules`: publish them to the resolver and, when running, bring the
    // policy table in line with them.
    void Apply(std::shared_ptr<const RuleSet> rules);

    std::shared_ptr<const RuleSet> Rules() const;

    // The guardian: one thread, waiting on cancellation, the server's loop and the
    // policy table. Started at the end of a successful Start, ended first by Stop.
    void StartGuardian();
    void StopGuardian();
    void Guard();
    void Fail(RedirectFailure cause, const wchar_t* detail);

    // What a look at the policy table concluded.
    enum class RuleGuard {
        Held,         // it says what it should, now
        Unwatchable,  // it cannot be kept in step, but redirection still works
        Lost,         // it cannot be held at all; Fail has already been called
    };
    RuleGuard RepairRuleIfNeeded();

    // Guards the rule pointer alone. A hot-reload replaces it from the watcher's
    // thread while a start or a status query reads it from another.
    mutable std::mutex m_mx;
    std::shared_ptr<const RuleSet> m_rules;

    // Serializes every touch of the policy table by this class against the
    // guardian's inspection of it.
    //
    // Installing a rule is several registry writes, and the change notification
    // fires on the first of them — so without this the guardian wakes in the middle
    // of an install, reads a key that is half written, concludes it has been
    // tampered with, and races the very write it is reacting to.
    //
    // Lock order where both are held: this one first, then m_mx. Apply() takes both
    // in that order and the guardian reaches m_mx through Rules(); nothing takes m_mx
    // and then reaches for this.
    std::mutex m_tableMx;

    LocalResolver m_resolver;
    std::unique_ptr<FileWatcher> m_watcher;
    std::wstring m_rulesPath;  // path being monitored

    // Both manual-reset. m_guardCancel says the guardian is no longer wanted;
    // m_failed is the one fact this class publishes outward.
    void* m_guardCancel = nullptr;
    void* m_failed = nullptr;
    std::thread m_guard;
    std::atomic<RedirectFailure> m_failure{RedirectFailure::None};

    // Reset by StartGuardian before the guardian thread exists; touched by nothing
    // but that thread afterwards.
    RepairBudget m_repairs;
};

}  // namespace Dns
