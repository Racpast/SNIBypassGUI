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

// High-level orchestration of the local proxy stack: the DNS interceptor plus the
// two loopback services (nginx, sni-gate) that hijacked names resolve to.
namespace Services {

// Resolved executable and data locations. Every one comes from [Paths] in
// paths.ini, so the payload owns its own layout and can be restructured in a later
// release without rebuilding this executable.
std::wstring NginxExe();
std::wstring SniGateExe();
std::wstring SupportedSitesFile();

// ---- Status (thread-safe, read from centralized state) ----
bool DnsInterceptorRunning();
bool NginxRunning();
bool SniGateRunning();
bool AnyRunning();

// Start the whole stack. If a port is occupied by a foreign process, an interactive
// call prompts before freeing it; a non-interactive one refuses to proceed if a
// system-critical process holds the port (returns false with a logged reason).
// Returns true if the start sequence completed successfully.
bool Start(bool interactive);

// Stop the DNS interceptor and both child processes. Always succeeds.
void Stop();

// Kill foreign copies of our child binaries, so the only ones running are ours.
// Called during initialization to enforce a clean slate.
void EnforceCleanSlate();

// ---- Autostart (scheduled task, highest privileges) ----
bool IsAutostartEnabled();  // the task exists AND points at this executable
bool EnableAutostart();
bool DisableAutostart();

// ---- Ports ----
bool AnyPortOccupied();

// Attempt to free occupied ports by stopping HTTP.sys services and killing
// non-critical processes. Returns true if all ports were freed, false if
// system-critical processes still hold ports (caller should abort the start).
bool KillPortHolders();

// ---- Uninstall ----
// Stop everything, remove what the payload's [Uninstall] manifest declares as ours,
// drop the root certificates it names, and delete this executable.
void Uninstall();

// ---- Cache cleanup ----
// Delete temporary files and logs declared in [Cache] Clean patterns from paths.ini.
// Stops services if needed, cleans, then restarts them. Returns the count of items
// deleted, or 0xFFFFFFFF if the operation failed (with services potentially down).
size_t CleanCache();

// ---- Directory management ----
// Ensure all directories declared in [Directories] Required exist, creating them
// recursively as needed. Returns the count of directories created.
size_t EnsureRequiredDirectories();

// Bring the stack up without any prompting, for a logon launch.
void RunAutostartMode();

}  // namespace Services
