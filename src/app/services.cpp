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

#include "app/services.h"

#include <windows.h>

#include <wincrypt.h>

#include <atomic>
#include <cwchar>
#include <mutex>
#include <utility>
#include <vector>

#include "app/filesystem.h"
#include "app/i18n.h"
#include "app/logging.h"
#include "app/paths.h"
#include "app/text.h"
#include "app/version.h"
#include "dns/nrpt.h"
#include "dns/redirector.h"
#include "platform/autostart.h"
#include "platform/command.h"
#include "platform/ports.h"
#include "platform/process.h"
#include "platform/shortcut.h"

namespace Services {

struct Runtime::State {
    // Set once the Runtime has begun tearing down.
    //
    // A detached tray worker can already be blocked on operationMutex when that
    // happens — the user clicking Start and then Exit is enough. Without this it
    // would acquire the mutex the moment teardown releases it and bring the whole
    // stack back up while the process is on its way out, leaving a local DNS
    // server and a policy rule alive with nothing left to own them.
    std::atomic<bool> shuttingDown{false};

    // Serializes Start/Stop/CleanCache so overlapping tray actions cannot interleave
    // process launches and DNS redirection state against each other.
    std::mutex operationMutex;

    // Guards the two child slots on their own, so the tray can ask what is running
    // without waiting behind a start that is still bringing the stack up.
    // Always taken after operationMutex when both are held.
    std::mutex childMutex;
    Process::Child nginx;
    Process::Child sniGate;

    // DNS redirection: a policy-table rule routes every listed namespace to a local
    // DNS server, which answers the redirected names with loopback and forwards
    // everything else to the machine's real resolvers.
    Dns::Redirector redirector;
};

namespace {

// ---- Payload-declared locations ---------------------------------------------

// The service-location interface lives at a fixed path next to the executable, so
// the layout it points at can change across releases without breaking startup.
std::wstring PathsConfigFile() {
    return ExeDir() + L"paths.ini";
}

std::wstring ResolvedPath(const wchar_t* key, const std::wstring& fallback) {
    wchar_t buf[MAX_PATH * 2] = {};
    GetPrivateProfileStringW(L"Paths", key, fallback.c_str(), buf,
                             static_cast<DWORD>(std::size(buf)), PathsConfigFile().c_str());
    std::wstring rel = TrimW(buf);
    if (rel.empty()) rel = fallback;
    return PathUnder(rel);
}

// Redirect-rule source: hosts-style "ACTION domain..." lines (see dns/rules.h).
std::wstring DnsRulesPath() {
    return ResolvedPath(L"Hosts", L"data\\dns_hosts.txt");
}

// Directory containing `exe`, with a trailing backslash.
std::wstring DirOf(const std::wstring& exe) {
    const size_t slash = exe.find_last_of(L"\\/");
    return (slash == std::wstring::npos) ? ExeDir() : exe.substr(0, slash + 1);
}

// ---- Child descriptions ------------------------------------------------------

// The port a child must be listening on before it counts as started.
//
// "The process is still alive" is not a postcondition worth having: a child that
// cannot read its configuration dies a few milliseconds later, and one that lives
// but never binds is just as useless to everything downstream. The listener is the
// fact the rest of the stack actually depends on, and it is directly observable.
struct ChildSpec {
    const wchar_t* name;
    int readyPort;
};

constexpr ChildSpec kNginx{L"nginx", 22222};
constexpr ChildSpec kSniGate{L"sni-gate", 443};

// Upper bound on how long a child may take to bind its port. This is a deadline,
// not a delay: a healthy start returns as soon as the listener appears, and a
// failed one the instant the process dies.
constexpr DWORD kStartupTimeoutMs = 10000;

// How often the TCP table is re-read while waiting. There is no kernel event for
// "a socket started listening", so this is the one place a poll cannot be avoided;
// the failure direction is still event-driven, through the process handle.
constexpr DWORD kListenPollMs = 50;

// How long to wait for a stopped service's port to disappear from the TCP table.
constexpr DWORD kPortReleaseTimeoutMs = 5000;

enum class Readiness { Listening, Exited, TimedOut };
enum class StartFailure { None, Launch, Exited, Timeout };

// Wait until `child` is listening on `port`, has exited, or the deadline passes.
//
// The wait on the process handle is what makes the failure path immediate: a child
// that dies after 5ms wakes us after 5ms. The port check between waits is what
// makes the success path meaningful.
Readiness AwaitListening(const Process::Child& child, int port, DWORD timeoutMs) {
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    for (;;) {
        if (Ports::IsOccupied(port)) return Readiness::Listening;
        if (child.WaitForExit(kListenPollMs)) {
            // Re-read the table once: the process could have bound the port in the
            // moment between our last check and its exit.
            return Ports::IsOccupied(port) ? Readiness::Listening : Readiness::Exited;
        }
        if (GetTickCount64() >= deadline) return Readiness::TimedOut;
    }
}

// Wait for our service ports to leave the TCP table.
//
// Terminating a process closes its sockets as part of teardown, and we already
// waited for that teardown to finish — but the update path stops the stack and
// starts it again straight away, so "stopped" has to mean the next bind will
// succeed, not merely that the process is gone.
void AwaitPortsReleased(DWORD timeoutMs) {
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    for (;;) {
        bool anyHeld = false;
        for (int port : Ports::kServicePorts)
            if (Ports::IsOccupied(port)) anyHeld = true;
        if (!anyHeld) return;
        if (GetTickCount64() >= deadline) {
            LOGW(L"A service port is still held after stopping; a restart may fail to bind.");
            return;
        }
        Sleep(kListenPollMs);
    }
}

// Drop the OS resolver cache. Synthesized answers carry a short TTL, so without
// this a start would be shadowed by cached real addresses, and a stop would keep
// sending traffic to a loopback that no longer listens until the TTL expired.
void FlushResolverCache() {
    Command::RunHidden(L"ipconfig /flushdns");
}

// The published state, and the lock that makes publishing it and taking a reference
// to it one step each.
//
// A tray command runs on a detached thread, so one of them — an update applying
// while the user picks Exit — can still be inside a public function below when the
// Runtime on wWinMain's stack is destroyed. Callers therefore get a shared_ptr, not
// a raw pointer: the state stays alive for exactly the duration of a call that is
// already under way, and is released as soon as the last such call returns. For a
// caller that arrives afterwards there is no state, which reads as "there is nothing
// running to act on" — exactly right.
//
// Neither global has a destructor that can run at exit. The lock is an SRWLOCK
// initialized by a constant, and the shared_ptr lives in a heap object that is
// deliberately never deleted: a detached worker can reach this slot after main() has
// returned, and a namespace-scope object would by then have been destroyed under it.
// What leaks is one empty shared_ptr — sixteen bytes holding nothing. The state it
// used to point at is destroyed properly, with every thread, process and handle it
// owns released in order.
SRWLOCK g_stateLock = SRWLOCK_INIT;

std::shared_ptr<Runtime::State>& StateSlot() {
    static auto* slot = new std::shared_ptr<Runtime::State>();
    return *slot;
}

std::shared_ptr<Runtime::State> Ctx() {
    AcquireSRWLockShared(&g_stateLock);
    std::shared_ptr<Runtime::State> state = StateSlot();
    ReleaseSRWLockShared(&g_stateLock);
    return state;
}

void PublishState(std::shared_ptr<Runtime::State> state) {
    AcquireSRWLockExclusive(&g_stateLock);
    StateSlot() = std::move(state);
    ReleaseSRWLockExclusive(&g_stateLock);
}

// Is this service running?
//
// Two different things both mean yes, and the tray has to report either one:
//   * the child this program launched is alive — answered through its handle, so it
//     cannot drift from reality and cannot be fooled by a reused PID;
//   * or a copy of the very same executable is alive that we did not launch, because
//     someone opened it by hand in the data folder.
//
// The second case used to report "Stopped" while that process sat there holding
// ports 80 and 22222. That is the one answer that is certainly wrong: the menu then
// offers to Start a stack whose ports are already taken, and the start walks into
// the port-conflict prompt for a program the user started themselves a moment ago.
bool ChildRunning(const std::shared_ptr<Runtime::State>& state,
                  Process::Child Runtime::State::* slot, const std::wstring& exe) {
    if (state) {
        std::lock_guard<std::mutex> lock(state->childMutex);
        if (((*state).*slot).Running()) return true;
    }
    return !Process::FindByImagePath(exe).empty();
}

// Whether any part of the stack this Runtime owns is still up. Only about what we
// launched: a copy started by hand is not something a teardown of this object is
// responsible for, and Stop reaches those separately.
bool AnythingRunning(Runtime::State& state) {
    if (state.redirector.Running()) return true;
    std::lock_guard<std::mutex> lock(state.childMutex);
    return static_cast<bool>(state.nginx) || static_cast<bool>(state.sniGate);
}

// ---- Start / stop, assuming operationMutex is held ---------------------------

StartFailure StartChild(Runtime::State& state, Process::Child Runtime::State::* slot,
                        const ChildSpec& spec, const std::wstring& exe) {
    LOGI(L"Starting " + std::wstring(spec.name) + L": " + exe);

    // nginx derives its prefix from its own module path with the wide API, and it
    // already lives in the directory that prefix has to be, so it needs no
    // arguments at all. It used to be given -p "<dir>", which travels through the
    // child's ANSI argv: on a non-ASCII install path those bytes do not survive the
    // round trip back to UTF-16, and nginx would exit before it could even open its
    // error log. The working directory carries the same information and is passed
    // as UTF-16 by the kernel.
    Process::Child child = Process::LaunchChild(exe, L"", DirOf(exe));
    if (!child) return StartFailure::Launch;

    switch (AwaitListening(child, spec.readyPort, kStartupTimeoutMs)) {
        case Readiness::Listening: break;
        case Readiness::Exited: {
            DWORD code = 0;
            const std::wstring detail =
                child.ExitCode(code) ? L" (exit code " + std::to_wstring(code) + L")" : L"";
            LOGE(std::wstring(spec.name) + L" exited immediately after starting" + detail +
                 L"; it never bound port " + std::to_wstring(spec.readyPort) + L".");
            return StartFailure::Exited;
        }
        case Readiness::TimedOut:
            LOGE(std::wstring(spec.name) + L" did not start listening on port " +
                 std::to_wstring(spec.readyPort) + L" within " +
                 std::to_wstring(kStartupTimeoutMs) + L" ms; stopping it again.");
            child.Terminate();
            return StartFailure::Timeout;
    }

    LOGI(std::wstring(spec.name) + L" started (pid " + std::to_wstring(child.pid()) +
         L"), listening on port " + std::to_wstring(spec.readyPort) + L".");
    std::lock_guard<std::mutex> lock(state.childMutex);
    state.*slot = std::move(child);
    return StartFailure::None;
}

void StopChildren(Runtime::State& state) {
    // Move the children out under the lock and terminate them outside it: the tray
    // must stay able to ask what is running while a stop is in progress.
    Process::Child nginx;
    Process::Child sniGate;
    {
        std::lock_guard<std::mutex> lock(state.childMutex);
        nginx = std::move(state.nginx);
        sniGate = std::move(state.sniGate);
    }
    if (nginx) {
        LOGI(L"Stopping nginx (pid " + std::to_wstring(nginx.pid()) + L")");
        nginx.Terminate();
    }
    if (sniGate) {
        LOGI(L"Stopping sni-gate (pid " + std::to_wstring(sniGate.pid()) + L")");
        sniGate.Terminate();
    }

    // A copy nobody here launched — opened by hand from the data folder — reports as
    // running and is therefore offered a Stop, so Stop has to be able to stop it.
    // Otherwise pressing it would leave the status exactly as it was, which is the
    // one thing a command must never do. Matching on the full path is what keeps this
    // to our own executables and away from a program that merely shares their name.
    Process::TerminateByImagePath(NginxExe());
    Process::TerminateByImagePath(SniGateExe());
}

void StopLocked(Runtime::State& state) {
    // Removing the policy rule is what returns DNS to normal; flushing afterwards
    // drops the loopback answers we synthesized, so names resolve for real again
    // straight away instead of after their TTL runs out.
    state.redirector.Stop();
    FlushResolverCache();

    StopChildren(state);
    AwaitPortsReleased(kPortReleaseTimeoutMs);
    LOGI(L"Services stopped.");
}

// Report a failed start. The logon path passes interactive == false and must never
// put a dialog in front of someone who is still signing in.
void ReportStartFailure(bool interactive, const wchar_t* what, const wchar_t* reasonKey) {
    if (!interactive) return;
    const std::wstring message =
        std::wstring(T(L"msg.startFail")) + L"\n\n" + what + L": " + T(reasonKey);
    MessageBoxW(nullptr, message.c_str(), APP_NAME, MB_ICONERROR);
}

const wchar_t* FailureKey(StartFailure failure) {
    switch (failure) {
        case StartFailure::Launch: return L"msg.startFailLaunch";
        case StartFailure::Exited: return L"msg.startFailExited";
        case StartFailure::Timeout: return L"msg.startFailTimeout";
        case StartFailure::None: break;
    }
    return L"msg.startFailLaunch";
}

// Refuse to start when the service that enforces the DNS policy table is down.
//
// Nothing is repaired here. Windows does not permit the service to be stopped, so
// the only way it is found down is that its start type was set to Disabled and the
// machine restarted — and undoing that needs another restart no matter which route
// is taken (see dns/nrpt.h for the two that were measured and rejected). Since the
// user has to restart either way, the useful thing to hand them is that
// instruction, delivered before a stack comes up that could not have worked.
bool EnsureDnsClientRunning(bool interactive) {
    const Dns::Nrpt::DnsClient state = Dns::Nrpt::QueryDnsClient();
    if (state == Dns::Nrpt::DnsClient::Running) return true;

    // Being unable to ask is not evidence of a problem. Blocking a start on a
    // question we could not put would be worse than proceeding and letting the
    // ordinary failure paths report whatever actually goes wrong.
    if (state == Dns::Nrpt::DnsClient::Unavailable) {
        LOGW(
            L"Could not determine whether the DNS Client service is running; "
            L"continuing anyway.");
        return true;
    }

    LOGE(state == Dns::Nrpt::DnsClient::Disabled
             ? L"The DNS Client service is disabled; DNS redirection cannot work. "
               L"Aborting start."
             : L"The DNS Client service is not running; DNS redirection cannot work. "
               L"Aborting start.");
    if (interactive) MessageBoxW(nullptr, T(L"msg.dnsClientOff"), APP_NAME, MB_ICONERROR);
    return false;
}

bool StartLocked(Runtime::State& state, bool interactive) {
    // Teardown has the last word: once it has started, nothing may bring the stack
    // back up behind it.
    if (state.shuttingDown.load(std::memory_order_acquire)) {
        LOGW(L"Start requested while shutting down; ignoring it.");
        return false;
    }

    // A start on a stack that is already up is not a second start.
    //
    // Two callers can ask independently — the logon thread brings the stack up while
    // the tray still shows "Start Services", because at the moment that menu was
    // built nothing was running yet. The mutex orders them but does not make the
    // second one a no-op, and without this it is not one: the ports are occupied by
    // then, so the second start would offer to free ports held by the services the
    // first one just launched, terminate them, and start them over.
    //
    // A remnant — one child gone on its own, or DNS redirection down with a child
    // still up — is not left to the port-conflict path either. This stack is
    // all-or-nothing by design, so the remnant is cleared and the start proceeds from
    // a known state rather than from whatever happened to survive.
    if (state.redirector.Running() && state.nginx.Running() && state.sniGate.Running()) {
        LOGI(L"Start requested while everything is already running; nothing to do.");
        return true;
    }
    if (state.redirector.Running() || state.nginx || state.sniGate) {
        LOGW(L"Start requested with part of the stack still up; stopping the remnant first.");
        StopLocked(state);
    }

    EnsureRequiredDirectories();

    // Checked before anything is launched, because it is the one precondition whose
    // absence fails silently: without the DNS Client service the policy rule is
    // inert, every listed name resolves the ordinary way, and the user sees a stack
    // that reports itself running while not one site works.
    if (!EnsureDnsClientRunning(interactive)) return false;

    if (AnyPortOccupied()) {
        bool shouldClean = true;
        if (interactive) {
            shouldClean = MessageBoxW(nullptr, T(L"msg.portsInUse"), APP_NAME,
                                      MB_ICONWARNING | MB_YESNO) == IDYES;
        }
        if (!shouldClean) {
            LOGW(L"User declined port cleanup; aborting start.");
            return false;
        }
        if (!KillPortHolders()) {
            LOGE(L"Cannot free ports held by system-critical processes; aborting start.");
            if (interactive)
                MessageBoxW(nullptr, T(L"msg.portsCritical"), APP_NAME, MB_ICONERROR);
            return false;
        }
        if (AnyPortOccupied()) {
            LOGE(L"Ports still occupied after cleanup; aborting start.");
            if (interactive)
                MessageBoxW(nullptr, T(L"msg.portsStillInUse"), APP_NAME, MB_ICONERROR);
            return false;
        }
    }

    // From here on the start is all-or-nothing. A stack with nginx up but the DNS
    // redirection down proxies nothing, yet holds the ports and reads as partly running;
    // rolling back leaves the machine exactly as it was found.
    const StartFailure nginxResult =
        StartChild(state, &Runtime::State::nginx, kNginx, NginxExe());
    if (nginxResult != StartFailure::None) {
        StopLocked(state);
        ReportStartFailure(interactive, kNginx.name, FailureKey(nginxResult));
        return false;
    }

    const StartFailure sniGateResult =
        StartChild(state, &Runtime::State::sniGate, kSniGate, SniGateExe());
    if (sniGateResult != StartFailure::None) {
        StopLocked(state);
        ReportStartFailure(interactive, kSniGate.name, FailureKey(sniGateResult));
        return false;
    }

    state.redirector.LoadRules(DnsRulesPath());
    if (!state.redirector.Start()) {
        LOGE(L"Failed to start DNS redirection.");
        StopLocked(state);
        if (interactive) MessageBoxW(nullptr, T(L"msg.dnsStartFail"), APP_NAME, MB_ICONERROR);
        return false;
    }

    // Reload rules automatically when the file changes.
    state.redirector.EnableHotReload(DnsRulesPath());

    // Evict any real addresses cached for redirected names so the redirect takes
    // effect immediately rather than after the cached TTL runs out.
    FlushResolverCache();

    LOGI(L"DNS redirection started with " + std::to_wstring(state.redirector.RuleCount()) +
         L" rules.");
    return true;
}

// ---- Uninstall helpers ------------------------------------------------------

// Split a '|'-separated list, trimming each item and dropping empties.
std::vector<std::wstring> SplitList(const std::wstring& s) {
    std::vector<std::wstring> out;
    size_t start = 0;
    for (;;) {
        const size_t bar = s.find(L'|', start);
        std::wstring token =
            TrimW(bar == std::wstring::npos ? s.substr(start) : s.substr(start, bar - start));
        if (!token.empty()) out.push_back(std::move(token));
        if (bar == std::wstring::npos) break;
        start = bar + 1;
    }
    return out;
}

// Read one '|'-separated value from a section in paths.ini.
std::vector<std::wstring> ReadPathsList(const wchar_t* section, const wchar_t* key) {
    std::vector<wchar_t> buf(32768, L'\0');
    GetPrivateProfileStringW(section, key, L"", buf.data(), static_cast<DWORD>(buf.size()),
                             PathsConfigFile().c_str());
    return SplitList(buf.data());
}

// Read a certificate's subject or issuer common name.
std::wstring CertName(PCCERT_CONTEXT ctx, DWORD which) {
    const DWORD n = CertGetNameStringW(
        ctx, CERT_NAME_ATTR_TYPE, which,
        const_cast<void*>(static_cast<const void*>(szOID_COMMON_NAME)), nullptr, 0);
    if (n <= 1) return L"";
    std::wstring name(n, L'\0');
    CertGetNameStringW(ctx, CERT_NAME_ATTR_TYPE, which,
                       const_cast<void*>(static_cast<const void*>(szOID_COMMON_NAME)),
                       name.data(), n);
    name.resize(std::wcslen(name.c_str()));
    return name;
}

// Remove every certificate whose subject OR issuer common name matches one of
// `names` from a Trusted Root store. sni-gate generates a local CA and installs it
// there to terminate TLS; leaving it behind after an uninstall would keep a trusted
// signer on the machine with no software left to justify it.
//
// Deleting invalidates the enumeration, so each pass restarts from the top and the
// loop repeats until a full sweep finds nothing to remove.
size_t RemoveRootCertificates(DWORD storeLocation, const std::vector<std::wstring>& names) {
    size_t removed = 0;
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                     storeLocation | CERT_STORE_OPEN_EXISTING_FLAG, L"ROOT");
    if (!store) return 0;

    for (bool again = true; again;) {
        again = false;
        PCCERT_CONTEXT ctx = nullptr;
        while ((ctx = CertEnumCertificatesInStore(store, ctx)) != nullptr) {
            const std::wstring subject = LowerW(CertName(ctx, 0));
            const std::wstring issuer = LowerW(CertName(ctx, CERT_NAME_ISSUER_FLAG));
            bool match = false;
            for (const std::wstring& want : names) {
                const std::wstring lowered = LowerW(want);
                if (subject == lowered || issuer == lowered) {
                    match = true;
                    break;
                }
            }
            if (!match) continue;

            // CertDeleteCertificateFromStore frees the context either way, so the
            // enumeration cannot continue from it — duplicate, delete, restart.
            PCCERT_CONTEXT dup = CertDuplicateCertificateContext(ctx);
            CertFreeCertificateContext(ctx);
            if (dup && CertDeleteCertificateFromStore(dup)) {
                ++removed;
            } else if (dup) {
                LOGW(L"Uninstall: failed to remove a root certificate (err " +
                     std::to_wstring(GetLastError()) + L").");
                CertFreeCertificateContext(dup);
            }
            again = true;
            break;  // restart the sweep
        }
    }
    CertCloseStore(store, 0);
    return removed;
}

// The executable cannot delete itself while running, so a detached script waits for
// this process to exit, removes it, and then tries a NON-recursive rmdir of the
// program directory. That call succeeds only if nothing else is left — if the user
// keeps unrelated files there, it fails harmlessly and their files remain.
void ScheduleSelfRemoval() {
    std::wstring dir = ExeDir();
    if (!dir.empty() && dir.back() == L'\\') dir.pop_back();

    std::wstring body;
    body += L"set \"SELF=" + ExePath() + L"\"\r\n";
    body += L"set \"DIR=" + dir + L"\"\r\n";
    body += L":wait\r\n";
    body += L"ping 127.0.0.1 -n 2 >nul\r\n";
    // Retrying the delete IS the wait condition: it succeeds as soon as this process
    // releases its own image. Watching the process name instead would hang on an
    // unrelated copy running elsewhere.
    body += L"del \"%SELF%\" >nul 2>&1\r\n";
    body += L"if exist \"%SELF%\" goto wait\r\n";
    // Non-recursive: removes the folder only when it is now empty.
    body += L"rmdir \"%DIR%\" >nul 2>&1\r\n";
    body += L"(goto) 2>nul & del \"%~f0\"\r\n";

    if (!Command::RunDetachedScript(L"snib_uninstall.bat", body))
        LOGE(
            L"Uninstall: the self-removal helper could not be started; "
            L"the executable will have to be deleted by hand.");
}

}  // namespace

// ---- Runtime ----------------------------------------------------------------

Runtime::Runtime() : m_state(std::make_shared<State>()) {
    PublishState(m_state);
}

Runtime::~Runtime() {
    // Unpublish first: from here on a new call from a detached worker finds no
    // runtime and does nothing, instead of racing this teardown.
    PublishState(nullptr);

    // Announce the teardown BEFORE waiting for the lock. A worker already blocked on
    // it will acquire it the instant we let go, and this is what stops that worker
    // from starting the stack again on the way out.
    m_state->shuttingDown.store(true, std::memory_order_release);

    {
        std::lock_guard<std::mutex> lock(m_state->operationMutex);
        if (AnythingRunning(*m_state)) StopLocked(*m_state);
    }

    // Everything the stack owns is now stopped, and releasing this reference destroys
    // the state itself — here, on the ordinary path, because a worker still inside a
    // call holds the only other reference and there is none once it returns.
}

// ---- Resolved locations ------------------------------------------------------

std::wstring NginxExe() {
    return ResolvedPath(L"Nginx", L"data\\nginx.exe");
}

std::wstring SniGateExe() {
    return ResolvedPath(L"SniGate", L"data\\sni-gate.exe");
}

std::wstring SupportedSitesFile() {
    return ResolvedPath(L"SupportedSites", L"data\\supported_sites.dat");
}

// ---- Status ------------------------------------------------------------------

bool DnsRedirectRunning() {
    const std::shared_ptr<Runtime::State> state = Ctx();
    return state && state->redirector.Running();
}

bool NginxRunning() {
    return ChildRunning(Ctx(), &Runtime::State::nginx, NginxExe());
}

bool SniGateRunning() {
    return ChildRunning(Ctx(), &Runtime::State::sniGate, SniGateExe());
}

bool AnyRunning() {
    return DnsRedirectRunning() || NginxRunning() || SniGateRunning();
}

// ---- Ports -------------------------------------------------------------------

bool AnyPortOccupied() {
    for (int port : Ports::kServicePorts)
        if (Ports::IsOccupied(port)) return true;
    return false;
}

bool KillPortHolders() {
    // http.sys (System, pid 4) commonly parks 80/443 via IIS/W3SVC/BranchCache.
    // Stopping the HTTP service releases those reservations.
    Command::RunHidden(L"net stop http /y", nullptr, 60000);
    Command::RunHidden(L"net stop w3svc /y", nullptr, 30000);
    Command::RunHidden(L"net stop was /y", nullptr, 30000);

    bool allFreed = true;
    for (int port : Ports::kServicePorts) {
        for (DWORD pid : Ports::ListenersOn(port)) {
            if (pid == 0) continue;

            std::wstring image;
            const bool identified = Process::TryImagePath(pid, image);

            if (Ports::IsSystemCritical(pid)) {
                LOGE(L"Port " + std::to_wstring(port) +
                     L" held by a system-critical process (pid " + std::to_wstring(pid) +
                     L": " + (identified ? image : std::wstring(L"<unknown>")) + L")");
                allFreed = false;
                continue;
            }

            LOGW(L"Freeing port " + std::to_wstring(port) + L": terminating pid " +
                 std::to_wstring(pid) + L" (" +
                 (identified ? image : std::wstring(L"<unknown>")) + L")");
            if (!Process::KillTree(pid)) allFreed = false;
        }
    }
    return allFreed;
}

// ---- Lifecycle ---------------------------------------------------------------

void EnforceCleanSlate() {
    // An orphan of a previous run is two things at once: one of OUR executables, and
    // still holding a port this stack needs. Both are required here, and each one
    // rules out a mistake the other would let through.
    //
    // Matching the image name alone would reach any nginx.exe on the machine — a
    // user's own web server, in their own folder, serving their own port — and
    // terminate it at startup without asking. Matching the port alone would terminate
    // whatever happens to hold port 80, which is not this program's call to make
    // silently. A foreign program holding one of our ports is not dealt with here at
    // all: that is a conflict the user is asked about, in KillPortHolders, on the way
    // into a start.
    //
    // A process whose image path cannot be read is left alone. Unidentified is not
    // the same as ours, and the whole point of this function is to act only on what
    // is certainly ours.
    const std::wstring ours[] = {LowerW(NginxExe()), LowerW(SniGateExe())};
    for (int port : Ports::kServicePorts) {
        for (DWORD pid : Ports::ListenersOn(port)) {
            std::wstring image;
            if (pid == 0 || !Process::TryImagePath(pid, image)) continue;
            image = LowerW(image);
            for (const std::wstring& mine : ours) {
                if (image != mine) continue;
                LOGW(L"Terminating a leftover " + image + L" (pid " + std::to_wstring(pid) +
                     L") still holding port " + std::to_wstring(port) + L".");
                Process::KillTree(pid);
                break;
            }
        }
    }

    // The policy rule is the one thing this program can leave behind that outlives
    // the process holding it: a machine killed mid-run keeps sending the redirected
    // names to a local server that is no longer listening. Removing it here is what
    // makes that recoverable by simply starting the program again. The rule has a
    // fixed key of our own, so this can never reach one the user installed.
    if (Dns::Nrpt::RemoveRule())
        LOGW(L"Removed a DNS policy rule left behind by a previous run.");
}

bool Start(bool interactive) {
    const std::shared_ptr<Runtime::State> state = Ctx();
    if (!state) return false;
    std::lock_guard<std::mutex> lock(state->operationMutex);
    return StartLocked(*state, interactive);
}

void Stop() {
    const std::shared_ptr<Runtime::State> state = Ctx();
    if (!state) return;
    std::lock_guard<std::mutex> lock(state->operationMutex);
    StopLocked(*state);
}

void RunAutostartMode() {
    Start(false);
}

// The program directory is NOT assumed to be ours alone. Users are told to extract
// the archive into a fixed folder, but nothing stops that folder from also holding
// unrelated files. So uninstall removes only what this program owns, and removes the
// directory itself ONLY if that left it empty.
//
// WHAT we own is declared by the payload ([Uninstall] in paths.ini), not baked into
// this executable — the same reason the service locations live there. A payload that
// grows a new folder ships an updated paths.ini through the ordinary signed update.
// This code is the executor of that declaration, never the author of it.
void Uninstall() {
    LOGI(L"Uninstalling.");
    Stop();
    Autostart::Disable();

    // Drop the desktop shortcut, if the one there is ours.
    Shortcut::RemoveIfOurs();

    // Pull sni-gate's locally generated CA out of the Trusted Root stores. Done
    // BEFORE the files go away, since the names come from paths.ini, which is itself
    // on the removal list. Both the machine store (where an elevated install lands)
    // and the current user's store are swept.
    const std::vector<std::wstring> certNames =
        ReadPathsList(L"Uninstall", L"RootCertificates");
    if (!certNames.empty()) {
        size_t n = RemoveRootCertificates(CERT_SYSTEM_STORE_LOCAL_MACHINE, certNames);
        n += RemoveRootCertificates(CERT_SYSTEM_STORE_CURRENT_USER, certNames);
        LOGI(L"Uninstall: removed " + std::to_wstring(n) + L" root certificate(s).");
    }

    // Remove exactly what the payload declares as ours; nothing else in the program
    // directory is touched.
    const std::vector<std::wstring> patterns = ReadPathsList(L"Uninstall", L"Remove");
    if (patterns.empty()) {
        LOGW(
            L"Uninstall: paths.ini declares no [Uninstall] Remove list; "
            L"only the executable will be removed.");
    } else {
        const size_t deleted = FileSystem::DeleteByPatterns(ExeDir(), patterns);
        LOGI(L"Uninstall: removed " + std::to_wstring(deleted) + L" item(s).");
    }

    ScheduleSelfRemoval();
}

CacheCleanResult CleanCache() {
    CacheCleanResult result;

    const std::shared_ptr<Runtime::State> state = Ctx();
    if (!state) return result;
    std::lock_guard<std::mutex> lock(state->operationMutex);

    LOGI(L"Cleaning cache.");
    const std::vector<std::wstring> patterns = ReadPathsList(L"Cache", L"Clean");
    if (patterns.empty()) {
        LOGW(L"Cache: paths.ini declares no [Cache] Clean patterns.");
        result.ok = true;
        return result;
    }

    // The stack is stopped and restarted as a whole, mirroring what Start and Stop
    // already guarantee, rather than tracking each service separately.
    const bool wasRunning = AnythingRunning(*state);
    if (wasRunning) {
        LOGI(L"Cache: stopping services before cleanup.");
        // No pause is needed before deleting: a process's file handles are closed by
        // the kernel as part of its teardown, and StopLocked does not return until
        // that teardown is confirmed complete.
        StopLocked(*state);
    }

    result.deleted = FileSystem::DeleteByPatterns(ExeDir(), patterns);
    LOGI(L"Cache: cleaned " + std::to_wstring(result.deleted) + L" item(s).");

    // Directories that were empty may have matched a pattern and gone with it.
    EnsureRequiredDirectories();

    result.ok = !wasRunning || StartLocked(*state, false);
    if (!result.ok) LOGE(L"Cache: the services did not come back up after cleanup.");
    return result;
}

size_t EnsureRequiredDirectories() {
    const std::vector<std::wstring> dirs = ReadPathsList(L"Directories", L"Required");
    if (dirs.empty()) return 0;

    std::vector<std::wstring> fullPaths;
    fullPaths.reserve(dirs.size());
    for (const std::wstring& rel : dirs) {
        if (!FileSystem::IsSafePath(rel)) {
            LOGW(L"Directories: rejecting unsafe path: " + rel);
            continue;
        }
        fullPaths.push_back(PathUnder(rel));
    }

    const size_t created = FileSystem::EnsureDirectories(fullPaths);
    if (created > 0) {
        LOGI(L"Directories: ensured " + std::to_wstring(created) + L" required director(ies).");
    }
    return created;
}

}  // namespace Services
