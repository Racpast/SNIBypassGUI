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

enum class Lang { English, Chinese };

// Resolved from [General] Language in config.ini, falling back to the OS UI language.
Lang GetLang();
void SetLang(Lang l);

// Translate a stable string key to the current language. An unknown key is
// returned verbatim, so a missing entry degrades to a visible identifier rather
// than to empty text.
const wchar_t* T(const wchar_t* key);
