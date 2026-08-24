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

// The tray icon and its context menu — the program's entire user interface.
namespace Tray {

// Create the hidden message window and add the icon. Returns false if the window
// could not be created.
bool Create(HINSTANCE instance);

// Remove the icon and destroy the window.
void Destroy();

// Run the message loop until the user exits. Returns the exit code.
int RunMessageLoop();

// Start the opt-in silent update check. Safe to call when one is already running:
// the second call is ignored.
void StartSilentUpdateCheck();

}  // namespace Tray
