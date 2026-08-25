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
#include <windows.h>

#include <string>
#include <utility>
#include <vector>

// Process ownership and lifetime.
//
// The unit of identity here is the kernel handle, never the PID. A PID is an
// integer the kernel may hand to an unrelated process the moment its owner exits,
// so any code that drops a handle and later looks the process back up by PID has
// manufactured a race it then has to defend against. Launching therefore yields an
// owning object, and every later question — is it alive, what did it exit with,
// kill it — is answered through that object rather than through a number.
namespace Process {

// Upper bound on waiting for a terminated process to disappear.
//
// This is not a sleep. The wait is on a kernel object and returns the instant the
// process is gone, so on every normal path it costs microseconds; the bound only
// caps how long we tolerate a teardown that never completes (a wedged driver, a
// handle held open by something stuck).
constexpr DWORD kTerminateTimeoutMs = 5000;

// An owned process handle. Move-only: exactly one owner closes it.
class Handle {
public:
    Handle() = default;
    Handle(HANDLE process, DWORD pid) : handle_(process), pid_(pid) {}
    ~Handle() { Close(); }

    Handle(Handle&& other) noexcept : handle_(other.handle_), pid_(other.pid_) {
        other.handle_ = nullptr;
        other.pid_ = 0;
    }
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) {
            Close();
            handle_ = other.handle_;
            pid_ = other.pid_;
            other.handle_ = nullptr;
            other.pid_ = 0;
        }
        return *this;
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;

    explicit operator bool() const { return handle_ != nullptr; }
    DWORD pid() const { return pid_; }
    HANDLE get() const { return handle_; }

    // True once the process has exited. Answered by the kernel through the handle,
    // so it can never disagree with reality and can never be fooled by a PID that
    // has since been handed to someone else.
    bool Exited() const { return WaitForExit(0); }

    // Block until the process exits or `timeoutMs` elapses. True if it exited.
    bool WaitForExit(DWORD timeoutMs) const;

    // The process's exit code. Meaningful only once it has exited.
    bool ExitCode(DWORD& code) const;

    void Close();

private:
    HANDLE handle_ = nullptr;
    DWORD pid_ = 0;
};

// A child process this program is responsible for.
//
// Each child runs inside its own job object, which buys two things a bare handle
// cannot:
//
//   * Terminating the job kills the process AND every descendant in one kernel
//     operation. nginx forks workers; killing them through a process snapshot
//     means enumerating PIDs and racing their lifetimes, while the job knows its
//     own membership exactly.
//   * The job is configured to kill its members when its last handle closes.
//     Handles close when this program's process object is destroyed — including
//     when it is killed outright — so a crash cannot leave children behind holding
//     ports 80/443/22222. Orphan cleanup stops being an after-the-fact heuristic.
//
// If the OS refuses to contain the child (an outer job that forbids nesting), the
// child still runs and is still owned; only the two guarantees above are lost, and
// termination falls back to walking the process tree.
class Child {
public:
    Child() = default;
    Child(Handle&& process, HANDLE job) : process_(std::move(process)), job_(job) {}
    ~Child();

    Child(Child&& other) noexcept : process_(std::move(other.process_)), job_(other.job_) {
        other.job_ = nullptr;
    }
    Child& operator=(Child&& other) noexcept;
    Child(const Child&) = delete;
    Child& operator=(const Child&) = delete;

    explicit operator bool() const { return static_cast<bool>(process_); }
    DWORD pid() const { return process_.pid(); }

    // True while the process is still running. This is a kernel query, not a
    // remembered flag, so a child that died on its own is reported as stopped the
    // first time anyone asks.
    bool Running() const { return static_cast<bool>(process_) && !process_.Exited(); }

    bool WaitForExit(DWORD timeoutMs) const { return process_.WaitForExit(timeoutMs); }
    bool ExitCode(DWORD& code) const { return process_.ExitCode(code); }

    // Terminate the process and every descendant, then wait until the process is
    // actually gone. Returns true if that is confirmed. Calling it on an empty or
    // already-exited Child succeeds without doing anything.
    bool Terminate(DWORD timeoutMs = kTerminateTimeoutMs);

private:
    Handle process_;
    HANDLE job_ = nullptr;  // null when the OS declined to contain this child
};

// Launch a child under this program's supervision: hidden, no console, contained
// in its own job object. An empty Child means the launch failed (the reason,
// including the command line and working directory, is logged).
Child LaunchChild(const std::wstring& exePath, const std::wstring& args,
                  const std::wstring& workDir);

// Launch a process that must OUTLIVE this program — the uninstall and self-update
// helpers, which exist precisely to act after we are gone — so it gets no job.
// The returned handle is only for reporting success.
Handle LaunchDetached(const std::wstring& exePath, const std::wstring& args,
                      const std::wstring& workDir, bool hidden);

// The arguments this process was started with: its command line with the program
// path removed — the same string wWinMain receives as lpCmdLine, available in code
// that does not have that parameter to hand.
//
// The self-update helper needs it to relaunch this program the way it was invoked.
// Reading it back from the OS keeps that one caller from forcing every function in
// between to carry an argument none of them use.
std::wstring OwnCommandLineArgs();

// Full image path of `pid`. A false return means the process could not be
// interrogated: it has already exited, or its handle could not be opened
// (protected process, another user's session). That is "unknown", NOT "some other
// program" — treating the two as the same is how a program ends up killing
// processes it merely failed to identify.
bool TryImagePath(DWORD pid, std::wstring& out);

// PIDs of every process whose image basename matches, case-insensitively.
std::vector<DWORD> FindByName(const std::wstring& baseName);

// PIDs of every process running the executable at exactly `exePath`.
//
// A PID is not ownership and this does not pretend otherwise — it is a snapshot,
// used to answer "is this program running" about a copy we did not launch and hold
// no handle to. A process whose image path cannot be read is not included, so the
// answer is always "processes positively identified as that executable", never a
// guess. Our own children are tracked by handle instead; see Child.
std::vector<DWORD> FindByImagePath(const std::wstring& exePath);

// Terminate `pid` and its descendants, children first, and wait for them to be
// gone. True if every one is confirmed exited. This is for processes we do NOT own
// a handle to; our own children are stopped through Child::Terminate, which needs
// no PID and cannot race PID reuse.
bool KillTree(DWORD pid, DWORD timeoutMs = kTerminateTimeoutMs);

// Terminate every process running the executable at exactly `exePath`, and return
// how many were terminated. Matching on the full path rather than the basename is
// what keeps this from reaching a program that merely shares a common name:
// "nginx.exe" belonging to someone else lives somewhere else.
size_t TerminateByImagePath(const std::wstring& exePath);

}  // namespace Process
