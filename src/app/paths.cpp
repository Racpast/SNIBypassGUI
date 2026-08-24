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

namespace {

std::wstring g_exePath;
std::wstring g_exeDir;

void EnsureResolved() {
    if (!g_exePath.empty()) return;
    wchar_t buf[MAX_PATH * 2];
    DWORD n = GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(std::size(buf)));
    g_exePath.assign(buf, n);
    size_t slash = g_exePath.find_last_of(L"\\/");
    g_exeDir = (slash == std::wstring::npos) ? L"" : g_exePath.substr(0, slash + 1);
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
    std::wstring r = rel;
    for (wchar_t& c : r)
        if (c == L'/') c = L'\\';
    return ExeDir() + r;
}
