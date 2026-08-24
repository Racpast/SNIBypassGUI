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

// The one desktop shortcut this program manages.
//
// Delivery is extract-and-run: no installer ever placed an entry anywhere, so a
// user who extracted the archive out of the way has no convenient route back to
// it.
namespace Shortcut {

// What currently sits on the desktop under our shortcut's name.
enum class State {
    Missing,  // not there — never created, or the user deleted it
    Ours,     // present and pointing at the running executable
    Foreign,  // present but pointing elsewhere (another copy, or unrelated)
};

// "<Desktop>\SNIBypassGUI.lnk", or empty if the desktop cannot be resolved.
std::wstring DesktopPath();

// True if the executable itself sits on the desktop, making a shortcut beside it
// pointless.
bool ExeIsOnDesktop();

State Inspect();

// Create or overwrite the shortcut so it points at the running executable.
bool Create();

// Delete the shortcut, but only when it points at the running executable.
void RemoveIfOurs();

}  // namespace Shortcut
