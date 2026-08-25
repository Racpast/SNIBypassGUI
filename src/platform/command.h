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

namespace Command {

// Run a command line hidden and wait for it. Returns the child's exit code, -1
// if it could not be started, or -2 if it was killed on timeout. When `out` is
// given, stdout and stderr are captured into it.
int RunHidden(const std::wstring& cmdline, std::wstring* out = nullptr,
              DWORD timeoutMs = 30000);

// Write a batch script into the user's temp directory and launch it detached, to
// run after this program is gone.
//
// Three things here are load-bearing and easy to get wrong, which is why they live
// in one place rather than at each call site:
//
//   * The script is written as UTF-8 and its preamble — added here, so no caller can
//     omit it — runs `chcp 65001`. cmd.exe decodes a batch file with the code page
//     in force as it reads, so without that line an install path containing
//     non-ASCII characters is decoded in the machine's OEM code page and every path
//     the script then touches is a different, nonexistent one.
//   * The helper must OUTLIVE this program, since waiting for us to exit is its
//     entire job, so it is launched with no job object attached.
//   * Both the script and cmd's working directory are in the temp directory, never
//     under the program directory. A process's current directory cannot be deleted
//     while it exists, so a helper running from inside the install tree would pin
//     that folder for as long as it — or anything it starts, which inherits the
//     directory — is alive. The self-update helper starts the new executable, so
//     that inheritance lasts the whole next session.
//
// `scriptName` is a bare file name. `body` holds the commands; @echo off and the
// code-page line are supplied here. Returns false if the script could not be
// written or cmd.exe could not be started.
bool RunDetachedScript(const std::wstring& scriptName, const std::wstring& body);

}  // namespace Command
