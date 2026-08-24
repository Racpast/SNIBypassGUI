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

#include <mutex>
#include <vector>

#include "app/filesystem.h"
#include "app/i18n.h"
#include "app/logging.h"
#include "app/paths.h"
#include "app/service_state.h"
#include "app/text.h"
#include "app/version.h"
#include "dns/interceptor.h"
#include "platform/command.h"
#include "platform/ports.h"
#include "platform/process.h"
#include "platform/shortcut.h"

namespace Services {
namespace {

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

// WinDivert.dll location, loaded by full path so the search order cannot be
// hijacked. Unset means the copy beside the executable. The DLL loads its own
// WinDivert64.sys from that directory, so the driver needs no key of its own.
std::wstring WinDivertDll() {
    return ResolvedPath(L"WinDivert", L"WinDivert.dll");
}

// Hijack-rule source: hosts-style "ACTION domain..." lines (see dns/interceptor.h).
std::wstring DnsRulesPath() {
    return ResolvedPath(L"Hosts", L"data\\dns_hosts.txt");
}

// Serializes Start/Stop/CleanCache so overlapping tray actions cannot interleave
// process launches and DNS-interceptor state against each other.
std::mutex g_operationMutex;

// In-process WinDivert interceptor: it intercepts outbound DNS queries (UDP/TCP
// port 53, MDNS 5353, LLMNR 5355) and answers matched names with loopback directly,
// touching no system setting. Closing its handle returns DNS to normal instantly —
// the "leave no trace" property.
Dns::Interceptor g_dnsInterceptor;

// Drop the OS resolver cache. Synthesized answers carry a short TTL, so without this
// a start would be shadowed by cached real addresses, and a stop would keep sending
// traffic to a loopback that no longer listens until the TTL expired.
void FlushResolverCache() {
    Command::RunHidden(L"ipconfig /flushdns");
}

// Directory containing `exe`, with a trailing backslash.
std::wstring DirOf(const std::wstring& exe) {
    const size_t slash = exe.find_last_of(L"\\/");
    return (slash == std::wstring::npos) ? ExeDir() : exe.substr(0, slash + 1);
}

std::wstring TaskQuery() {
    std::wstring out;
    Command::RunHidden(L"schtasks /Query /TN \"" + std::wstring(APP_TASK_NAME) + L"\" /XML",
                       &out, 15000);
    return out;
}

// Start a child process if it's not already running. Returns true if the process
// was started or is already running, false on launch failure.
bool StartChildProcess(ServiceState::Service service, const std::wstring& exe,
                       const std::wstring& args, const std::wstring& workDir) {
    using ServiceState::Service;

    // Check if already running by validating the recorded PID.
    const DWORD recordedPid = ServiceState::GetRecordedPid(service);
    const std::wstring expectedPath = ServiceState::GetExpectedPath(service);
    if (recordedPid != 0 && Process::ValidatePidPath(recordedPid, expectedPath)) {
        LOGI(L"Service already running: " + exe + L" (pid " + std::to_wstring(recordedPid) + L")");
        return true;
    }

    // Not running or PID invalid; check if another instance is at the expected path.
    const DWORD existingPid = Process::FindByExactPath(expectedPath);
    if (existingPid != 0) {
        LOGI(L"Found existing service at expected path: " + exe + L" (pid " +
             std::to_wstring(existingPid) + L")");
        ServiceState::RecordPid(service, existingPid);
        ServiceState::SetRunning(service, true);
        return true;
    }

    // Launch the service.
    const wchar_t* serviceName = (service == Service::Nginx) ? L"nginx" : L"sni-gate";
    LOGI(L"Starting " + std::wstring(serviceName) + L": " + exe);
    const DWORD pid = Process::Launch(exe, args, workDir, true);
    if (pid == 0) {
        LOGE(L"Failed to launch " + std::wstring(serviceName));
        return false;
    }

    ServiceState::RecordPid(service, pid);
    ServiceState::SetRunning(service, true);
    LOGI(L"Started " + std::wstring(serviceName) + L" (pid " + std::to_wstring(pid) + L")");
    return true;
}

void StartChildProcesses() {
    const std::wstring nginxExe = NginxExe();
    const std::wstring sniGateExe = SniGateExe();

    // nginx resolves its configuration relative to the current working directory,
    // so it MUST be launched with its own folder as the working directory and the
    // same folder passed as the -p prefix.
    const std::wstring nginxDir = DirOf(nginxExe);
    std::wstring nginxPrefix = nginxDir;
    if (!nginxPrefix.empty() && nginxPrefix.back() == L'\\') nginxPrefix.pop_back();

    StartChildProcess(ServiceState::Service::Nginx, nginxExe, L"-p \"" + nginxPrefix + L"\"",
                      nginxDir);
    StartChildProcess(ServiceState::Service::SniGate, sniGateExe, L"", DirOf(sniGateExe));
}

// Stop a child process by killing the recorded PID and any foreign copies.
void StopOurChild(ServiceState::Service service, const std::wstring& baseName) {
    using ServiceState::Service;

    const DWORD recordedPid = ServiceState::GetRecordedPid(service);
    const std::wstring expectedPath = ServiceState::GetExpectedPath(service);

    // Kill the recorded PID if it's still valid.
    if (recordedPid != 0 && Process::ValidatePidPath(recordedPid, expectedPath)) {
        LOGI(L"Stopping " + baseName + L" (pid " + std::to_wstring(recordedPid) + L")");
        Process::KillTree(recordedPid);
    }

    // Kill any other process at the expected path (in case of PID reuse or manual launch).
    Process::KillForeignByName(baseName, expectedPath);

    ServiceState::ClearPid(service);
    ServiceState::SetRunning(service, false);
}

// ---- Uninstall helpers ------------------------------------------------------

// Split a '|'-separated list, trimming each item and dropping empties.
std::vector<std::wstring> SplitList(const std::wstring& s) {
    std::vector<std::wstring> out;
    size_t start = 0;
    for (;;) {
        const size_t bar = s.find(L'|', start);
        std::wstring token = TrimW(bar == std::wstring::npos ? s.substr(start)
                                                            : s.substr(start, bar - start));
        if (!token.empty()) out.push_back(std::move(token));
        if (bar == std::wstring::npos) break;
        start = bar + 1;
    }
    return out;
}

// Read one '|'-separated value from a section in paths.ini.
std::vector<std::wstring> ReadPathsList(const wchar_t* section, const wchar_t* key) {
    std::vector<wchar_t> buf(32768, L'\0');
    GetPrivateProfileStringW(section, key, L"", buf.data(),
                             static_cast<DWORD>(buf.size()), PathsConfigFile().c_str());
    return SplitList(buf.data());
}

// Read a certificate's subject or issuer common name.
std::wstring CertName(PCCERT_CONTEXT ctx, DWORD which) {
    const DWORD n = CertGetNameStringW(ctx, CERT_NAME_ATTR_TYPE, which,
                                       const_cast<void*>(static_cast<const void*>(szOID_COMMON_NAME)),
                                       nullptr, 0);
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

    // Resolve the temp directory through the wide API; the ANSI environment would
    // mis-decode a non-ASCII path.
    wchar_t tempBuf[MAX_PATH + 1] = {};
    const DWORD tempLen = GetTempPathW(MAX_PATH + 1, tempBuf);
    std::wstring tempDir = (tempLen > 0 && tempLen <= MAX_PATH) ? std::wstring(tempBuf)
                                                                : L"C:\\Windows\\Temp\\";
    if (!tempDir.empty() && tempDir.back() != L'\\') tempDir.push_back(L'\\');

    const std::wstring script = tempDir + L"snib_uninstall.bat";
    HANDLE handle = CreateFileW(script.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return;

    std::wstring body;
    body += L"@echo off\r\n";
    body += L"chcp 65001 >nul\r\n";
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

    const std::string utf8 = WideToUtf8(body);
    DWORD written = 0;
    WriteFile(handle, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
    CloseHandle(handle);

    Process::Launch(L"C:\\Windows\\System32\\cmd.exe", L"/c \"" + script + L"\"", L"", true);
}

}  // namespace

std::wstring NginxExe() {
    return ResolvedPath(L"Nginx", L"data\\nginx.exe");
}

std::wstring SniGateExe() {
    return ResolvedPath(L"SniGate", L"data\\sni-gate.exe");
}

std::wstring SupportedSitesFile() {
    return ResolvedPath(L"SupportedSites", L"data\\supported_sites.dat");
}

bool DnsInterceptorRunning() {
    return ServiceState::IsRunning(ServiceState::Service::DnsInterceptor);
}

bool NginxRunning() {
    return ServiceState::IsRunning(ServiceState::Service::Nginx);
}

bool SniGateRunning() {
    return ServiceState::IsRunning(ServiceState::Service::SniGate);
}

bool AnyRunning() {
    return ServiceState::AnyRunning();
}

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

    // After stopping services, recheck ports immediately (minimize TOCTOU window).
    bool allFreed = true;
    for (int port : Ports::kServicePorts) {
        const std::vector<DWORD> pids = Ports::ListenersOn(port);
        for (DWORD pid : pids) {
            if (pid == 0) continue;

            // Never kill system-critical processes.
            if (Ports::IsSystemCritical(pid)) {
                LOGE(L"Port " + std::to_wstring(port) + L" held by system-critical process (pid " +
                     std::to_wstring(pid) + L": " + Ports::GetListenerImagePath(pid) + L")");
                allFreed = false;
                continue;
            }

            LOGW(L"Freeing port " + std::to_wstring(port) + L": killing pid " +
                 std::to_wstring(pid) + L" (" + Ports::GetListenerImagePath(pid) + L")");
            Process::KillTree(pid);
        }
    }

    return allFreed;
}

void EnforceCleanSlate() {
    const std::wstring nginxPath = NginxExe();
    const std::wstring sniGatePath = SniGateExe();

    Process::KillForeignByName(L"nginx.exe", nginxPath);
    Process::KillForeignByName(L"sni-gate.exe", sniGatePath);
}

bool Start(bool interactive) {
    std::lock_guard<std::mutex> lock(g_operationMutex);

    // Ensure required directories exist before starting services.
    EnsureRequiredDirectories();

    // Record expected paths for validation.
    ServiceState::SetExpectedPath(ServiceState::Service::Nginx, NginxExe());
    ServiceState::SetExpectedPath(ServiceState::Service::SniGate, SniGateExe());

    // Check port occupation atomically: check once, act immediately.
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

        // KillPortHolders returns false if system-critical processes hold ports.
        if (!KillPortHolders()) {
            LOGE(L"Cannot free ports held by system-critical processes; aborting start.");
            if (interactive) {
                MessageBoxW(nullptr, T(L"msg.portsCritical"), APP_NAME, MB_ICONERROR);
            }
            return false;
        }

        // Verify ports are actually free now.
        if (AnyPortOccupied()) {
            LOGE(L"Ports still occupied after cleanup; aborting start.");
            if (interactive) {
                MessageBoxW(nullptr, T(L"msg.portsStillInUse"), APP_NAME, MB_ICONERROR);
            }
            return false;
        }
    }

    // The loopback services that hijacked names redirect to.
    StartChildProcesses();

    // Start the interceptor. It intercepts outbound DNS queries and answers matched
    // names with loopback, so no adapter or service is reconfigured.
    g_dnsInterceptor.LoadRules(DnsRulesPath());
    if (!g_dnsInterceptor.Start(WinDivertDll())) {
        LOGE(L"Failed to start the DNS interceptor (WinDivert).");
        if (interactive)
            MessageBoxW(nullptr, T(L"msg.dnsStartFail"), APP_NAME, MB_ICONERROR);
        ServiceState::SetRunning(ServiceState::Service::DnsInterceptor, false);
        return false;
    }

    ServiceState::SetRunning(ServiceState::Service::DnsInterceptor, true);

    // Enable hot-reload: automatically reload rules when the file changes.
    g_dnsInterceptor.EnableHotReload(DnsRulesPath());

    // Evict any real addresses cached for hijacked names so the redirect takes effect
    // immediately rather than after the cached TTL runs out.
    FlushResolverCache();

    LOGI(L"DNS interceptor started with " + std::to_wstring(g_dnsInterceptor.RuleCount()) +
         L" rules.");
    return true;
}

void Stop() {
    std::lock_guard<std::mutex> lock(g_operationMutex);

    // Closing the WinDivert handle returns DNS to normal instantly. Flushing
    // afterwards drops the loopback answers we synthesized, so names resolve for real
    // again straight away.
    g_dnsInterceptor.Stop();
    ServiceState::SetRunning(ServiceState::Service::DnsInterceptor, false);
    FlushResolverCache();

    StopOurChild(ServiceState::Service::Nginx, L"nginx.exe");
    StopOurChild(ServiceState::Service::SniGate, L"sni-gate.exe");

    LOGI(L"Services stopped.");
}

bool IsAutostartEnabled() {
    const std::wstring xml = TaskQuery();
    if (xml.empty()) return false;
    // The task must reference THIS executable; schtasks XML holds <Command>path</Command>.
    return LowerW(xml).find(LowerW(ExePath())) != std::wstring::npos;
}

bool EnableAutostart() {
    // Validate that ExePath() does not contain characters that could break the command.
    const std::wstring exePath = ExePath();
    if (exePath.find(L'"') != std::wstring::npos || exePath.find(L'\n') != std::wstring::npos ||
        exePath.find(L'\r') != std::wstring::npos) {
        LOGE(L"ExePath contains invalid characters; refusing to create autostart task.");
        return false;
    }

    // Remove any stale task first, since it may point to a different path.
    Command::RunHidden(L"schtasks /Delete /TN \"" + std::wstring(APP_TASK_NAME) + L"\" /F",
                       nullptr, 15000);

    const std::wstring target = L"\\\"" + exePath + L"\\\" -autostart";
    const std::wstring cmd = L"schtasks /Create /TN \"" + std::wstring(APP_TASK_NAME) +
                             L"\" /TR \"" + target + L"\" /SC ONLOGON /RL HIGHEST /F";
    const int rc = Command::RunHidden(cmd, nullptr, 20000);
    if (rc != 0) {
        LOGE(L"Failed to create the autostart task (rc " + std::to_wstring(rc) + L").");
        return false;
    }
    LOGI(L"Autostart enabled.");
    return true;
}

bool DisableAutostart() {
    Command::RunHidden(L"schtasks /Delete /TN \"" + std::wstring(APP_TASK_NAME) + L"\" /F",
                       nullptr, 15000);
    LOGI(L"Autostart disabled.");
    return true;
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
    DisableAutostart();

    // Drop the desktop shortcut, if the one there is ours.
    Shortcut::RemoveIfOurs();

    // Pull sni-gate's locally generated CA out of the Trusted Root stores. Done
    // BEFORE the files go away, since the names come from paths.ini, which is itself
    // on the removal list. Both the machine store (where an elevated install lands)
    // and the current user's store are swept.
    const std::vector<std::wstring> certNames = ReadPathsList(L"Uninstall", L"RootCertificates");
    if (!certNames.empty()) {
        size_t n = RemoveRootCertificates(CERT_SYSTEM_STORE_LOCAL_MACHINE, certNames);
        n += RemoveRootCertificates(CERT_SYSTEM_STORE_CURRENT_USER, certNames);
        LOGI(L"Uninstall: removed " + std::to_wstring(n) + L" root certificate(s).");
    }

    // Remove exactly what the payload declares as ours; nothing else in the program
    // directory is touched. The new unified Remove list supports exact paths, wildcards,
    // and recursive patterns.
    const std::vector<std::wstring> patterns = ReadPathsList(L"Uninstall", L"Remove");
    if (patterns.empty()) {
        LOGW(L"Uninstall: paths.ini declares no [Uninstall] Remove list; "
             L"only the executable will be removed.");
    } else {
        const size_t deleted = FileSystem::DeleteByPatterns(ExeDir(), patterns);
        LOGI(L"Uninstall: removed " + std::to_wstring(deleted) + L" item(s).");
    }

    ScheduleSelfRemoval();
}

size_t CleanCache() {
    std::lock_guard<std::mutex> lock(g_operationMutex);

    LOGI(L"Cleaning cache.");
    const std::vector<std::wstring> patterns = ReadPathsList(L"Cache", L"Clean");
    if (patterns.empty()) {
        LOGW(L"Cache: paths.ini declares no [Cache] Clean patterns.");
        return 0;
    }

    // Remember if services were running before cleanup.
    const bool dnsWasRunning = ServiceState::IsRunning(ServiceState::Service::DnsInterceptor);
    const bool nginxWasRunning = ServiceState::IsRunning(ServiceState::Service::Nginx);
    const bool sniGateWasRunning = ServiceState::IsRunning(ServiceState::Service::SniGate);

    // Stop all services to release file locks (logs, temp files, etc.).
    if (dnsWasRunning || nginxWasRunning || sniGateWasRunning) {
        LOGI(L"Cache: stopping services before cleanup.");
        if (dnsWasRunning) {
            g_dnsInterceptor.Stop();
            ServiceState::SetRunning(ServiceState::Service::DnsInterceptor, false);
        }
        StopOurChild(ServiceState::Service::Nginx, L"nginx.exe");
        StopOurChild(ServiceState::Service::SniGate, L"sni-gate.exe");
        // Brief pause to ensure files are fully released.
        Sleep(500);
    }

    const size_t deleted = FileSystem::DeleteByPatterns(ExeDir(), patterns);
    LOGI(L"Cache: cleaned " + std::to_wstring(deleted) + L" item(s).");

    // After cache cleanup, ensure required directories still exist (they may have
    // been deleted if they were empty and matched a pattern).
    EnsureRequiredDirectories();

    // Restart services if they were running before, checking success.
    bool restartFailed = false;
    if (dnsWasRunning) {
        LOGI(L"Cache: restarting DNS interceptor.");
        g_dnsInterceptor.LoadRules(DnsRulesPath());
        if (!g_dnsInterceptor.Start(WinDivertDll())) {
            LOGE(L"Cache: FAILED to restart DNS interceptor after cleanup.");
            ServiceState::SetRunning(ServiceState::Service::DnsInterceptor, false);
            restartFailed = true;
        } else {
            ServiceState::SetRunning(ServiceState::Service::DnsInterceptor, true);
            g_dnsInterceptor.EnableHotReload(DnsRulesPath());
            FlushResolverCache();
        }
    }

    if (nginxWasRunning) {
        LOGI(L"Cache: restarting nginx.");
        const std::wstring nginxExe = NginxExe();
        const std::wstring dir = DirOf(nginxExe);
        std::wstring prefix = dir;
        if (!prefix.empty() && prefix.back() == L'\\') prefix.pop_back();
        if (!StartChildProcess(ServiceState::Service::Nginx, nginxExe, L"-p \"" + prefix + L"\"",
                               dir)) {
            LOGE(L"Cache: FAILED to restart nginx after cleanup.");
            restartFailed = true;
        }
    }

    if (sniGateWasRunning) {
        LOGI(L"Cache: restarting sni-gate.");
        const std::wstring sniGateExe = SniGateExe();
        if (!StartChildProcess(ServiceState::Service::SniGate, sniGateExe, L"", DirOf(sniGateExe))) {
            LOGE(L"Cache: FAILED to restart sni-gate after cleanup.");
            restartFailed = true;
        }
    }

    if (restartFailed) {
        LOGE(L"Cache cleanup completed but one or more services failed to restart.");
        return 0xFFFFFFFF;  // Signal failure
    }

    return deleted;
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

void RunAutostartMode() {
    Start(false);
}

}  // namespace Services
