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

#include "platform/embedded_text.h"

#include <windows.h>

namespace EmbeddedText {

std::string Read(int resourceId) {
    HMODULE self = GetModuleHandleW(nullptr);
    HRSRC found = FindResourceW(self, MAKEINTRESOURCEW(resourceId), RT_RCDATA);
    if (!found) return {};
    HGLOBAL loaded = LoadResource(self, found);
    if (!loaded) return {};
    const auto* bytes = static_cast<const char*>(LockResource(loaded));
    const DWORD size = SizeofResource(self, found);
    if (!bytes || size == 0) return {};

    std::string text(bytes, size);
    if (text.size() >= 3 && static_cast<unsigned char>(text[0]) == 0xEF &&
        static_cast<unsigned char>(text[1]) == 0xBB &&
        static_cast<unsigned char>(text[2]) == 0xBF)
        text.erase(0, 3);
    return text;
}

}  // namespace EmbeddedText
