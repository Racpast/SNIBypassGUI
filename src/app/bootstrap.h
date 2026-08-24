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

// First-run checks that must pass before the tray appears.
//
// The extract-and-run payload (paths.ini, data/, WinDivert.dll and .sys) is not
// embedded in the executable; it ships beside it in the archive and is
// delivered/updated through the signed manifest. So the executable must cope with
// the payload being absent in three distinct situations:
//
//   * the user extracted the whole archive       -> present, run offline
//   * the executable was run from inside an
//     archive viewer                             -> a helpful "extract first"
//                                                   refusal, never going online
//   * a real install with data/ deleted          -> re-fetch through the signed
//                                                   update channel, so there is no
//                                                   unsigned bootstrap path
namespace Bootstrap {

// True if the canonical payload is laid out beside the executable.
bool PayloadPresent();

// True if the executable is running from an archiver's scratch directory rather than
// a fixed install folder.
bool RunningFromArchiveTemp();

// Ensure the payload is available. Runs after elevation and, for the download path,
// after the agreement is accepted. Returns false if the program cannot proceed.
bool EnsurePayload();

// Reconcile the desktop shortcut with the stored preference, prompting on a first
// run that has never been asked.
void SyncDesktopShortcut();

}  // namespace Bootstrap
