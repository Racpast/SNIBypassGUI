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

#include <cstdio>
#include <mutex>

#include "app/paths.h"
#include "app/settings.h"
#include "app/text.h"

namespace {

std::mutex   g_mutex;
std::wstring g_logPath;

}  // namespace

void LogInit() {
    std::wstring dir = ExeDir() + L"logs";
    SHCreateDirectoryExW(nullptr, dir.c_str(), nullptr);
    std::lock_guard<std::mutex> lock(g_mutex);
    g_logPath = dir + L"\\SNIBypassGUI.log";
}

void LogLine(const std::wstring& level, const std::wstring& msg) {
    if (!LoggingEnabled()) return;

    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_logPath.empty()) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t stamp[64];
    std::swprintf(stamp, std::size(stamp), L"%04d-%02d-%02d %02d:%02d:%02d", st.wYear,
                  st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    const std::string line =
        WideToUtf8(L"[" + std::wstring(stamp) + L"] [" + level + L"] " + msg + L"\r\n");

    HANDLE h = CreateFileW(g_logPath.c_str(), FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(h, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
    CloseHandle(h);
}
