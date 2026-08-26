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

// APP_VERSION_NUM is the strict dotted numeric version (a.b.c[.d]) used for:
//   - Update trigger comparisons (online vs local)
//   - min_upgradable_from boundary checks
//   - Native FILEVERSION resource
// Never carries a pre-release suffix, so numeric ordering is well-defined.
// Bump APP_VERSION_NUM to trigger an executable update.
//
// For display strings (tray tooltip, about dialog), use GetVersionDisplayStr()
// which pulls from i18n key "version.display" with fallback to APP_VERSION_NUM.
#define APP_VERSION_NUM L"5.1.1"

#include <string>
std::wstring GetVersionDisplayStr();

#define APP_NAME L"SNIBypassGUI"
#define APP_MUTEX_NAME L"Global\\SNIBypassGUI_SingleInstance_Mutex"
#define APP_HOMEPAGE L"https://github.com/racpast/SNIBypassGUI"

// Scheduled task used for autostart at logon.
#define APP_TASK_NAME L"SNIBypassGUI_Autostart"
