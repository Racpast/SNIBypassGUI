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
#include <windows.h>

#include <string>
#include <vector>

namespace SupportedSites {

// Populate `menu` with the parsed supported-sites entries, creating nested submenus
// as needed. Each clickable link is assigned baseCmdId plus its index.
//
// Returns the URLs in command-id order: the link for command id C is at
// result[C - baseCmdId]. The caller must keep baseCmdId through
// baseCmdId + result.size() - 1 free of other menu command ids.
std::vector<std::wstring> PopulateMenu(HMENU menu, UINT baseCmdId);

}  // namespace SupportedSites
