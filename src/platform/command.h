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

}  // namespace Command
