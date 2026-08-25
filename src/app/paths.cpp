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

#include "app/paths.h"

#include <windows.h>

#include <cwchar>
#include <iterator>

namespace {

// Resolved once, from any thread, and never torn down.
//
// These are read from worker threads (the update check, the tray's command
// threads, the DNS server) as well as the UI thread, so the previous unguarded
// "assign on first use" was a data race. INIT_ONCE and plain arrays keep the
// storage free of both the race and a destructor, which matters because logging
// resolves paths and must stay safe for the whole life of the process.
INIT_ONCE g_once = INIT_ONCE_STATIC_INIT;
wchar_t g_exePath[MAX_PATH * 2] = {};
wchar_t g_exeDir[MAX_PATH * 2] = {};

BOOL CALLBACK ResolveOnce(PINIT_ONCE, PVOID, PVOID*) {
    const DWORD n =
        GetModuleFileNameW(nullptr, g_exePath, static_cast<DWORD>(std::size(g_exePath)));
    if (n == 0 || n >= std::size(g_exePath)) {
        g_exePath[0] = L'\0';
        return TRUE;
    }
    const wchar_t* lastSlash = nullptr;
    for (const wchar_t* p = g_exePath; *p; ++p)
        if (*p == L'\\' || *p == L'/') lastSlash = p;
    if (lastSlash) {
        const size_t keep = static_cast<size_t>(lastSlash - g_exePath) + 1;
        std::wmemcpy(g_exeDir, g_exePath, keep);
        g_exeDir[keep] = L'\0';
    }
    return TRUE;
}

void EnsureResolved() {
    InitOnceExecuteOnce(&g_once, ResolveOnce, nullptr, nullptr);
}

}  // namespace

std::wstring ExePath() {
    EnsureResolved();
    return g_exePath;
}

std::wstring ExeDir() {
    EnsureResolved();
    return g_exeDir;
}

std::wstring DataDir() {
    return ExeDir() + L"data\\";
}

std::wstring PathUnder(const std::wstring& rel) {
    std::wstring native = rel;
    for (wchar_t& c : native)
        if (c == L'/') c = L'\\';
    return ExeDir() + native;
}
