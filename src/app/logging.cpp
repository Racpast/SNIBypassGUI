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

#include "app/logging.h"

#include <windows.h>

#include <shlobj.h>

#include <atomic>
#include <cstdio>
#include <cwchar>
#include <iterator>

#include "app/paths.h"
#include "app/settings.h"
#include "app/text.h"

namespace {

// None of these has a destructor, and that is the point.
//
// An SRWLOCK is initialized by a constant, a fixed array has no lifetime of its
// own, and std::atomic<bool> is trivially destructible. The previous version used
// a std::mutex and a std::wstring at namespace scope, and the order in which
// namespace-scope objects in different translation units are destroyed is
// unspecified: a log line written after main() returned could lock a destroyed
// mutex and hand CreateFileW a dangling pointer, which is exactly how a file whose
// name was heap garbage turned up in the working directory.
//
// The specific late log line that did it is gone now — the service stack is
// destroyed before main() returns — but a module whose correctness depends on
// nobody ever logging late is a trap for the next change. This one has no such
// requirement.
SRWLOCK g_lock = SRWLOCK_INIT;
wchar_t g_logPath[MAX_PATH * 2] = {};
std::atomic<bool> g_enabled{false};

void StoreLogPath(const std::wstring& path) {
    AcquireSRWLockExclusive(&g_lock);
    const size_t n =
        (path.size() < std::size(g_logPath) - 1) ? path.size() : std::size(g_logPath) - 1;
    std::wmemcpy(g_logPath, path.c_str(), n);
    g_logPath[n] = L'\0';
    ReleaseSRWLockExclusive(&g_lock);
}

HANDLE OpenForAppend() {
    return CreateFileW(g_logPath, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                       OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
}

// Open the log file, creating its directory only when that is what is missing.
//
// The directory is NOT created up front, and that is the whole point: a program the
// user has never asked to keep a log should not leave a folder behind to prove it.
// Creating one at startup made the choice for them, and made it before the setting
// had even been read.
//
// Nor is it created per line. The open succeeds on its own for every line but the
// one that follows a missing directory, so the cost of getting this right is a single
// failed CreateFileW in exactly the case that needs one.
//
// And that case is not only the first line of a run. Cache cleanup deletes this
// directory out from under a running program, so "it existed at startup" is not
// something a later write can rely on — which is why creating it here rather than in
// LogInit is what makes logging survive a cleanup instead of silently stopping until
// the next launch.
//
// Called with g_lock held, since it reads g_logPath.
HANDLE OpenLogFile() {
    HANDLE file = OpenForAppend();
    if (file != INVALID_HANDLE_VALUE) return file;

    // Only a missing directory is worth a second attempt. A denied open, a path that
    // is not a directory, a full disk — retrying those would fail identically.
    if (GetLastError() != ERROR_PATH_NOT_FOUND) return INVALID_HANDLE_VALUE;

    const std::wstring path(g_logPath);
    const size_t slash = path.find_last_of(L'\\');
    if (slash == std::wstring::npos) return INVALID_HANDLE_VALUE;
    SHCreateDirectoryExW(nullptr, path.substr(0, slash).c_str(), nullptr);

    return OpenForAppend();
}

}  // namespace

// Resolves where the log goes and reads whether anyone wants one. Nothing is created
// and nothing is opened: see OpenLogFile for why the directory is left until there is
// actually a line to put in it.
void LogInit() {
    StoreLogPath(ExeDir() + L"logs\\snibypassgui.log");
    g_enabled.store(LoggingEnabled(), std::memory_order_relaxed);
}

bool LogEnabled() {
    return g_enabled.load(std::memory_order_relaxed);
}

void LogSetEnabled(bool on) {
    SetLoggingEnabled(on);
    g_enabled.store(on, std::memory_order_relaxed);
}

void LogLine(const std::wstring& level, const std::wstring& msg) {
    if (!g_enabled.load(std::memory_order_relaxed)) return;

    SYSTEMTIME now;
    GetLocalTime(&now);
    wchar_t stamp[64];
    std::swprintf(stamp, std::size(stamp), L"%04d-%02d-%02d %02d:%02d:%02d", now.wYear,
                  now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond);

    const std::string line =
        WideToUtf8(L"[" + std::wstring(stamp) + L"] [" + level + L"] " + msg + L"\r\n");

    AcquireSRWLockExclusive(&g_lock);
    if (g_logPath[0] != L'\0') {
        HANDLE file = OpenLogFile();
        if (file != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(file, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
            CloseHandle(file);
        }
    }
    ReleaseSRWLockExclusive(&g_lock);
}
