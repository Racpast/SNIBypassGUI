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

#include "app/version.h"
#include "app/i18n.h"
#include <cstring>

std::wstring GetVersionDisplayStr() {
    const wchar_t* display = T(L"version.display");
    // If the key is not found, T() returns the key itself ("version.display").
    // Check if it's still the key (fallback case) or an actual translation.
    if (std::wcscmp(display, L"version.display") == 0) {
        // No translation found, fallback to APP_VERSION_NUM
        return APP_VERSION_NUM;
    }
    return display;
}
