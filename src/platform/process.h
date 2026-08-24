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

namespace Process {

// Kill a process and its whole tree, children first.
void KillTree(DWORD pid);

// PIDs of every process whose image basename matches, case-insensitively.
std::vector<DWORD> FindByName(const std::wstring& baseName);

// Full image path of a PID, empty on failure.
std::wstring ImagePath(DWORD pid);

// Launch a detached process. Returns its PID, or 0 on failure.
DWORD Launch(const std::wstring& exePath, const std::wstring& args,
             const std::wstring& workDir, bool hidden);

// Validate that a process with this PID is running from the exact expected path.
// Returns true if the process exists AND its full image path matches `expectedPath`
// (case-insensitive comparison). Used to verify that a recorded PID is still the
// service we launched, not a hijacker or reused PID.
bool ValidatePidPath(DWORD pid, const std::wstring& expectedPath);

// Find a process running from the exact expected path. Returns the PID if found,
// or 0 if no such process exists. This is stricter than the old IsOurProcessRunning:
// it requires the full path to match exactly, not just "somewhere under our directory".
DWORD FindByExactPath(const std::wstring& expectedPath);

// Kill processes with this basename that are NOT at the expected path, so the only
// copy left running is the one we control (if any).
void KillForeignByName(const std::wstring& baseName, const std::wstring& expectedPath);

}  // namespace Process
