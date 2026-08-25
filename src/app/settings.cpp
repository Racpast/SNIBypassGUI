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

#include "app/settings.h"

#include <windows.h>

#include "app/paths.h"
#include "app/text.h"

namespace {

constexpr wchar_t kSection[] = L"General";

bool ReadFlag(const wchar_t* key) {
    return GetPrivateProfileIntW(kSection, key, 0, SettingsPath().c_str()) != 0;
}

void WriteFlag(const wchar_t* key, bool on) {
    WritePrivateProfileStringW(kSection, key, on ? L"1" : L"0", SettingsPath().c_str());
}

}  // namespace

std::wstring SettingsPath() {
    return ExeDir() + L"config.ini";
}

bool LoggingEnabled() {
    return ReadFlag(L"LoggingEnabled");
}
void SetLoggingEnabled(bool on) {
    WriteFlag(L"LoggingEnabled", on);
}
bool EulaAccepted() {
    return ReadFlag(L"EulaAccepted");
}
void SetEulaAccepted(bool ok) {
    WriteFlag(L"EulaAccepted", ok);
}
bool AutoUpdateEnabled() {
    return ReadFlag(L"AutoUpdate");
}
void SetAutoUpdateEnabled(bool on) {
    WriteFlag(L"AutoUpdate", on);
}

// Stored as a word rather than 0/1 because the preference is genuinely
// tri-state: an absent key ("never asked") must not read as "declined". An
// unknown value falls back to Unset, so a hand-edited config.ini degrades to
// asking again rather than to a silently assumed decision.
ShortcutPref GetShortcutPref() {
    wchar_t buf[32] = {};
    GetPrivateProfileStringW(kSection, L"DesktopShortcut", L"", buf,
                             static_cast<DWORD>(std::size(buf)), SettingsPath().c_str());
    std::wstring v = LowerW(TrimW(buf));
    if (v == L"wanted") return ShortcutPref::Wanted;
    if (v == L"declined") return ShortcutPref::Declined;
    return ShortcutPref::Unset;
}

void SetShortcutPref(ShortcutPref p) {
    const wchar_t* v = (p == ShortcutPref::Wanted)     ? L"wanted"
                       : (p == ShortcutPref::Declined) ? L"declined"
                                                       : L"";
    WritePrivateProfileStringW(kSection, L"DesktopShortcut", v, SettingsPath().c_str());
}
