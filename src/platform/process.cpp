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

#include "platform/process.h"

#include <tlhelp32.h>

#include <algorithm>
#include <utility>

#include "app/logging.h"
#include "app/text.h"

namespace Process {
namespace {

// "<code> (<system message>)" — a bare error number tells whoever reads the log
// nothing, and these are exactly the lines someone reaches for when a child will
// not start.
std::wstring DescribeError(DWORD code) {
    wchar_t* text = nullptr;
    const DWORD n =
        FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                           FORMAT_MESSAGE_IGNORE_INSERTS,
                       nullptr, code, 0, reinterpret_cast<LPWSTR>(&text), 0, nullptr);
    const std::wstring message = (n > 0 && text) ? TrimW(text) : std::wstring();
    if (text) LocalFree(text);
    return std::to_wstring(code) + (message.empty() ? L"" : L" (" + message + L")");
}

// Collect `root` and every descendant from a single snapshot, leaves first, so
// terminating in order never leaves a child reparented to something we then miss.
// A visited set guards against a cycle formed by PID reuse within the snapshot.
std::vector<DWORD> CollectTree(DWORD root) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return {root};

    std::vector<std::pair<DWORD, DWORD>> edges;  // (parent, child)
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID != entry.th32ParentProcessID)
                edges.emplace_back(entry.th32ParentProcessID, entry.th32ProcessID);
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);

    std::vector<DWORD> visited;
    std::vector<DWORD> stack = {root};
    while (!stack.empty()) {
        const DWORD current = stack.back();
        stack.pop_back();
        if (std::find(visited.begin(), visited.end(), current) != visited.end()) continue;
        visited.push_back(current);
        for (const auto& [parent, child] : edges)
            if (parent == current &&
                std::find(visited.begin(), visited.end(), child) == visited.end())
                stack.push_back(child);
    }
    // Discovery order is root-first, so reversing terminates children first.
    return std::vector<DWORD>(visited.rbegin(), visited.rend());
}

// Terminate every PID in `victims` and wait until each is actually gone.
//
// TerminateProcess is asynchronous — it marks the process for death and returns —
// so anything that looks at the process list straight afterwards sees a PID that
// has been terminated but not yet reaped, with no readable image path. Waiting on
// the handles is what turns "asked it to die" into "it is dead", and it is
// event-driven: each wait returns the moment its process disappears.
bool TerminateAndWait(const std::vector<DWORD>& victims, DWORD timeoutMs) {
    std::vector<HANDLE> pending;
    pending.reserve(victims.size());
    bool allGone = true;

    for (DWORD pid : victims) {
        if (pid == 0 || pid == 4) continue;  // never touch Idle/System
        HANDLE process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
        if (!process) {
            // An already-exited process is the outcome we wanted; anything else is
            // a process we are not allowed to stop, which the caller must know.
            const DWORD err = GetLastError();
            if (err != ERROR_INVALID_PARAMETER) {
                LOGW(L"Cannot terminate pid " + std::to_wstring(pid) + L": err " +
                     DescribeError(err));
                allGone = false;
            }
            continue;
        }
        TerminateProcess(process, 1);
        pending.push_back(process);
    }

    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    for (size_t i = 0; i < pending.size(); i += MAXIMUM_WAIT_OBJECTS) {
        const DWORD count =
            static_cast<DWORD>(std::min<size_t>(MAXIMUM_WAIT_OBJECTS, pending.size() - i));
        const ULONGLONG now = GetTickCount64();
        const DWORD remaining = (now >= deadline) ? 0 : static_cast<DWORD>(deadline - now);
        if (WaitForMultipleObjects(count, pending.data() + i, TRUE, remaining) != WAIT_OBJECT_0)
            allGone = false;
    }
    for (HANDLE process : pending) CloseHandle(process);
    return allGone;
}

// A job whose members are killed when its last handle closes. Our handles close
// when this process object is destroyed, however that happens, so children cannot
// outlive us.
HANDLE CreateContainingJob() {
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (!job) {
        LOGW(L"Could not create a job object (err " + DescribeError(GetLastError()) + L").");
        return nullptr;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits,
                                 sizeof(limits))) {
        LOGW(L"Could not configure the job object (err " + DescribeError(GetLastError()) +
             L").");
        CloseHandle(job);
        return nullptr;
    }
    return job;
}

struct Started {
    Handle process;
    HANDLE thread = nullptr;
};

Started StartProcess(const std::wstring& exePath, const std::wstring& args,
                     const std::wstring& workDir, bool hidden, DWORD extraFlags) {
    std::wstring cmd = L"\"" + exePath + L"\"";
    if (!args.empty()) cmd += L" " + args;
    std::vector<wchar_t> mutableCmd(cmd.begin(), cmd.end());
    mutableCmd.push_back(L'\0');

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    DWORD flags = extraFlags;
    if (hidden) {
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        flags |= CREATE_NO_WINDOW;
    }

    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(exePath.c_str(), mutableCmd.data(), nullptr, nullptr, FALSE, flags,
                        nullptr, workDir.empty() ? nullptr : workDir.c_str(), &si, &pi)) {
        LOGE(L"Launch failed: " + cmd + L" [working directory: " +
             (workDir.empty() ? std::wstring(L"<inherited>") : workDir) + L"] err " +
             DescribeError(GetLastError()));
        return {};
    }
    return {Handle(pi.hProcess, pi.dwProcessId), pi.hThread};
}

}  // namespace

// ---- Handle -----------------------------------------------------------------

bool Handle::WaitForExit(DWORD timeoutMs) const {
    if (!handle_) return true;  // nothing to wait for is indistinguishable from gone
    return WaitForSingleObject(handle_, timeoutMs) == WAIT_OBJECT_0;
}

bool Handle::ExitCode(DWORD& code) const {
    return handle_ && GetExitCodeProcess(handle_, &code) && code != STILL_ACTIVE;
}

void Handle::Close() {
    if (handle_) {
        CloseHandle(handle_);
        handle_ = nullptr;
    }
    pid_ = 0;
}

// ---- Child ------------------------------------------------------------------

Child& Child::operator=(Child&& other) noexcept {
    if (this != &other) {
        // Release what we currently hold exactly as the destructor would.
        Child discarded(std::move(*this));
        process_ = std::move(other.process_);
        job_ = other.job_;
        other.job_ = nullptr;
    }
    return *this;
}

Child::~Child() {
    // A contained child dies with its job as soon as the last handle closes, which
    // is the guarantee we launched it for. Without containment there is nothing to
    // inherit that guarantee, so take the tree down by hand rather than leave a
    // process holding a port after we are gone.
    if (!job_ && process_ && !process_.Exited()) KillTree(process_.pid());
    if (job_) CloseHandle(job_);
}

bool Child::Terminate(DWORD timeoutMs) {
    if (!process_ || process_.Exited()) return true;

    if (job_) {
        // One kernel call takes the whole tree — nginx's workers included — with no
        // snapshot to walk and no PID to race.
        TerminateJobObject(job_, 1);
        const bool gone = process_.WaitForExit(timeoutMs);
        if (!gone)
            LOGW(L"pid " + std::to_wstring(process_.pid()) +
                 L" did not exit within the termination timeout.");
        return gone;
    }
    return KillTree(process_.pid(), timeoutMs);
}

// ---- Free functions ---------------------------------------------------------

Child LaunchChild(const std::wstring& exePath, const std::wstring& args,
                  const std::wstring& workDir) {
    HANDLE job = CreateContainingJob();

    // Suspended, so containment is decided before a single instruction runs: a
    // child that started first could spawn a descendant outside the job.
    Started started = StartProcess(exePath, args, workDir, true, CREATE_SUSPENDED);
    if (!started.process) {
        if (job) CloseHandle(job);
        return {};
    }

    if (job && !AssignProcessToJobObject(job, started.process.get())) {
        LOGW(L"Could not contain " + exePath + L" in a job object (err " +
             DescribeError(GetLastError()) +
             L"); falling back to process-tree termination for it.");
        CloseHandle(job);
        job = nullptr;
    }

    if (ResumeThread(started.thread) == static_cast<DWORD>(-1)) {
        LOGE(L"Could not resume " + exePath + L" (err " + DescribeError(GetLastError()) +
             L").");
        TerminateProcess(started.process.get(), 1);
        CloseHandle(started.thread);
        if (job) CloseHandle(job);
        return {};
    }
    CloseHandle(started.thread);
    return Child(std::move(started.process), job);
}

Handle LaunchDetached(const std::wstring& exePath, const std::wstring& args,
                      const std::wstring& workDir, bool hidden) {
    Started started = StartProcess(exePath, args, workDir, hidden, 0);
    if (started.thread) CloseHandle(started.thread);
    return std::move(started.process);
}

std::wstring OwnCommandLineArgs() {
    const wchar_t* line = GetCommandLineW();
    if (!line) return {};

    // argv[0] is either quoted in full or runs to the first whitespace. Skipping
    // exactly that much is what leaves the arguments as the shell wrote them,
    // quoting intact, rather than a re-quoted approximation of them.
    const wchar_t* p = line;
    if (*p == L'"') {
        ++p;
        while (*p && *p != L'"') ++p;
        if (*p == L'"') ++p;
    } else {
        while (*p && *p != L' ' && *p != L'\t') ++p;
    }
    while (*p == L' ' || *p == L'\t') ++p;
    return p;
}

bool TryImagePath(DWORD pid, std::wstring& out) {
    out.clear();
    if (pid == 0) return false;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!process) return false;

    wchar_t buf[MAX_PATH * 2];
    DWORD size = static_cast<DWORD>(std::size(buf));
    const bool ok = QueryFullProcessImageNameW(process, 0, buf, &size) != 0;
    if (ok) out.assign(buf, size);
    CloseHandle(process);
    return ok && !out.empty();
}

std::vector<DWORD> FindByName(const std::wstring& baseName) {
    std::vector<DWORD> found;
    const std::wstring want = LowerW(baseName);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return found;
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (LowerW(entry.szExeFile) == want) found.push_back(entry.th32ProcessID);
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}

std::vector<DWORD> FindByImagePath(const std::wstring& exePath) {
    std::vector<DWORD> found;
    if (exePath.empty()) return found;

    // Narrow the snapshot scan by basename first, then confirm each candidate's full
    // path. Comparing paths for every process on the machine would open a handle to
    // each one for nothing.
    const size_t slash = exePath.find_last_of(L"\\/");
    const std::wstring baseName =
        (slash == std::wstring::npos) ? exePath : exePath.substr(slash + 1);
    const std::wstring want = LowerW(exePath);

    for (DWORD pid : FindByName(baseName)) {
        std::wstring image;
        if (TryImagePath(pid, image) && LowerW(image) == want) found.push_back(pid);
    }
    return found;
}

bool KillTree(DWORD pid, DWORD timeoutMs) {
    if (pid == 0 || pid == 4) return false;  // never touch Idle/System
    return TerminateAndWait(CollectTree(pid), timeoutMs);
}

size_t TerminateByImagePath(const std::wstring& exePath) {
    size_t terminated = 0;
    for (DWORD pid : FindByImagePath(exePath)) {
        LOGW(L"Terminating " + exePath + L" pid " + std::to_wstring(pid) +
             L", which this program did not launch.");
        if (KillTree(pid)) ++terminated;
    }
    return terminated;
}

}  // namespace Process
