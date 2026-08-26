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
#include <string>

// Appends to logs\snibypassgui.log beside the executable.
//
// Writing is off unless the user turns it on, so LogLine is safe to call
// unconditionally and costs an atomic load when it is off. Nothing on disk is touched
// until a line is actually written — a program nobody asked for a log from leaves no
// directory behind — and the directory is re-created if it goes missing while the
// program runs, which cache cleanup does. Every piece of state this module owns is
// trivially destructible on purpose: a log call must remain safe no matter when it
// happens, including after main() has returned, where a std::mutex or std::wstring
// owned by another translation unit may already have been destroyed.
void LogInit();
void LogLine(const std::wstring& level, const std::wstring& msg);

// The live switch. LogSetEnabled persists the choice as well, so it is the single
// call a caller needs; LogEnabled answers without touching the disk.
bool LogEnabled();
void LogSetEnabled(bool on);

#define LOGI(m) LogLine(L"INFO", (m))
#define LOGW(m) LogLine(L"WARN", (m))
#define LOGE(m) LogLine(L"ERROR", (m))
