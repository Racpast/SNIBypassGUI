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

// Collect a process and all its descendants, leaves first, from a single
// snapshot. A visited set guards against PID-reuse cycles.
void CollectTree(DWORD root, std::vector<DWORD>& ordered) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        ordered.push_back(root);
        return;
    }

    std::vector<std::pair<DWORD, DWORD>> edges;  // (parent, child)
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID != pe.th32ParentProcessID)
                edges.emplace_back(pe.th32ParentProcessID, pe.th32ProcessID);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    std::vector<DWORD> visited;
    std::vector<DWORD> stack = {root};
    while (!stack.empty()) {
        DWORD cur = stack.back();
        stack.pop_back();
        if (std::find(visited.begin(), visited.end(), cur) != visited.end()) continue;
        visited.push_back(cur);
        for (const auto& [parent, child] : edges)
            if (parent == cur && std::find(visited.begin(), visited.end(), child) == visited.end())
                stack.push_back(child);
    }
    // Discovery order is root-first, so reversing terminates children first.
    ordered.insert(ordered.end(), visited.rbegin(), visited.rend());
}

}  // namespace

std::wstring ImagePath(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) return L"";
    wchar_t buf[MAX_PATH * 2];
    DWORD size = static_cast<DWORD>(std::size(buf));
    std::wstring result;
    if (QueryFullProcessImageNameW(h, 0, buf, &size)) result.assign(buf, size);
    CloseHandle(h);
    return result;
}

std::vector<DWORD> FindByName(const std::wstring& baseName) {
    std::vector<DWORD> out;
    const std::wstring want = LowerW(baseName);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (LowerW(pe.szExeFile) == want) out.push_back(pe.th32ProcessID);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

void KillTree(DWORD pid) {
    if (pid == 0 || pid == 4) return;  // never touch Idle/System
    std::vector<DWORD> victims;
    CollectTree(pid, victims);
    for (DWORD victim : victims) {
        if (HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, victim)) {
            TerminateProcess(h, 1);
            CloseHandle(h);
        }
    }
}

DWORD Launch(const std::wstring& exePath, const std::wstring& args,
             const std::wstring& workDir, bool hidden) {
    std::wstring cmd = L"\"" + exePath + L"\"";
    if (!args.empty()) cmd += L" " + args;
    std::vector<wchar_t> mutableCmd(cmd.begin(), cmd.end());
    mutableCmd.push_back(L'\0');

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    if (hidden) {
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
    }
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(exePath.c_str(), mutableCmd.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr,
                        workDir.empty() ? nullptr : workDir.c_str(), &si, &pi)) {
        LOGE(L"Launch failed for " + exePath + L" (err " +
             std::to_wstring(GetLastError()) + L")");
        return 0;
    }
    const DWORD pid = pi.dwProcessId;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return pid;
}

bool ValidatePidPath(DWORD pid, const std::wstring& expectedPath) {
    if (pid == 0) return false;
    const std::wstring actual = ImagePath(pid);
    if (actual.empty()) return false;
    return LowerW(actual) == LowerW(expectedPath);
}

DWORD FindByExactPath(const std::wstring& expectedPath) {
    if (expectedPath.empty()) return 0;

    // Extract the basename to narrow the search.
    const size_t slash = expectedPath.find_last_of(L"\\/");
    const std::wstring baseName = (slash == std::wstring::npos)
                                    ? expectedPath
                                    : expectedPath.substr(slash + 1);

    const std::wstring wantPath = LowerW(expectedPath);
    for (DWORD pid : FindByName(baseName)) {
        const std::wstring actual = ImagePath(pid);
        if (!actual.empty() && LowerW(actual) == wantPath) {
            return pid;
        }
    }
    return 0;
}

void KillForeignByName(const std::wstring& baseName, const std::wstring& expectedPath) {
    const std::wstring wantPath = LowerW(expectedPath);
    for (DWORD pid : FindByName(baseName)) {
        const std::wstring img = ImagePath(pid);
        if (img.empty() || LowerW(img) != wantPath) {
            LOGW(L"Killing foreign " + baseName + L" pid " + std::to_wstring(pid) + L" (" +
                 img + L")");
            KillTree(pid);
        }
    }
}

}  // namespace Process
