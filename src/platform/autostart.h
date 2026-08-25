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

// Start-at-logon, expressed through the Task Scheduler API rather than by driving
// schtasks.exe.
//
// The command-line route had to serialize a path into a quoted argument, spawn a
// process, and read its answer back out of a pipe — where the answer arrives in the
// console code page and a non-ASCII install path does not survive the round trip.
// Talking to the scheduler directly moves paths as UTF-16 the whole way, needs no
// quoting, and answers a query in a local call instead of a process launch, which
// matters because the tray menu asks on every open.
namespace Autostart {

// True if the logon task exists AND runs this exact executable. A task pointing at
// another copy reads as disabled, so the answer is always about this install.
bool IsEnabled();

// Register (or replace) the logon task for the current user. Requires the
// administrator rights this program already runs with.
bool Enable();

// Remove the logon task. Succeeds if it was already absent.
bool Disable();

}  // namespace Autostart
