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
#include <cstddef>
#include <memory>
#include <string>

// High-level orchestration of the local proxy stack: DNS redirection plus the two
// loopback services (nginx, sni-gate) that redirected names resolve to.
namespace Services {

// Deterministic lifetime for everything the stack owns.
//
// The redirector owns a DNS server thread, a file watcher and a registry rule; each
// child owns a job object holding a live process. None of that may still exist
// once main() returns. A namespace-scope object with a non-trivial destructor does
// its teardown during static destruction, in an order the standard leaves
// unspecified across translation units — so it may log, resolve a path or read a
// setting after the module that owns those has already been destroyed. That is not
// a bug to be defended against one call at a time; it is a lifetime that was never
// stated.
//
// wWinMain creates exactly one Runtime on its stack. Constructing it publishes the
// state the functions below act on; destroying it stops the stack — threads joined,
// children terminated, handles closed, DNS restored — and unpublishes that state,
// all before main returns and before any static destructor runs.
//
// The state is held by shared_ptr rather than owned outright, and that is what makes
// the unpublish safe. The tray runs its commands on detached threads, and one of
// them (an update applying while the user picks Exit) can still be inside a function
// below when this destructor runs. Each such call holds its own reference for its
// duration, so the state cannot be destroyed under it; a call that arrives after the
// unpublish finds nothing and does nothing. On every ordinary path the destructor
// holds the last reference and the state is gone when it returns.
class Runtime {
public:
    // The state every function below acts on. Named in the header only so the
    // implementation file can refer to it; nothing outside constructs or touches one.
    struct State;

    Runtime();
    ~Runtime();
    Runtime(const Runtime&) = delete;
    Runtime& operator=(const Runtime&) = delete;

private:
    std::shared_ptr<State> m_state;
};

// Resolved executable and data locations. Every one comes from [Paths] in
// paths.ini, so the payload owns its own layout and can be restructured in a later
// release without rebuilding this executable. These need no Runtime.
std::wstring NginxExe();
std::wstring SniGateExe();
std::wstring SupportedSitesFile();

// ---- Status ----
//
// None of these is a remembered flag. DNS redirection is read from its server
// thread, and a child from its process handle, so a service that died on its own
// reports as stopped the first time anyone asks — there is no cached value that can
// drift away from what is actually running.
//
// A child also reports as running when a copy of its executable is alive that this
// program did not launch — someone opened it by hand in the data folder. It holds
// the same ports and does the same work, so calling it stopped would be false, and
// would offer to Start a stack whose ports are already taken. Stop terminates those
// copies as well, so the answer these give is always one a command can act on.
bool DnsRedirectRunning();
bool NginxRunning();
bool SniGateRunning();
bool AnyRunning();

// Start the whole stack, or nothing at all.
//
// Every step is verified before the next begins, and a failure at any point rolls
// back what already came up: a half-started stack cannot proxy anything, yet still
// holds the ports and reads as partly running. If a port is occupied by a foreign
// process, an interactive call prompts before freeing it; a non-interactive one
// (the logon start) never shows UI and reports through the log instead.
bool Start(bool interactive);

// Stop the whole stack and wait until the child ports are actually free again —
// "stopped" has to be a fact the next Start can rely on.
void Stop();

// Undo what a previous run could have left behind: leftover copies of our child
// binaries, and the DNS policy rule that outlives the process holding it. Called
// once at startup, when we own nothing yet, so anything answering to those names
// is either an orphan of a previous run or someone else's; a process whose image
// path cannot be read is left alone rather than guessed at.
void EnforceCleanSlate();

// ---- Ports ----
bool AnyPortOccupied();

// Attempt to free occupied ports by stopping HTTP.sys services and terminating
// non-critical holders. Returns true if all ports ended up free.
bool KillPortHolders();

// ---- Uninstall ----
// Stop everything, remove what the payload's [Uninstall] manifest declares as ours,
// drop the root certificates it names, and delete this executable.
void Uninstall();

// ---- Cache cleanup ----
struct CacheCleanResult {
    bool ok = false;     // the stack is back in the state it was found in
    size_t deleted = 0;  // items removed
};

// Stop the stack if it is running, delete everything matching [Cache] Clean from
// paths.ini, then bring it back up if it was up before.
CacheCleanResult CleanCache();

// ---- Directory management ----
// Ensure every directory in [Directories] Required exists. Returns how many were
// created. Needs no Runtime.
size_t EnsureRequiredDirectories();

// Bring the stack up without any prompting, for a logon launch.
void RunAutostartMode();

}  // namespace Services
