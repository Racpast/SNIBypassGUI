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

#include <vector>

namespace Ports {

// The ports the child services listen on.
constexpr int kServicePorts[] = {80, 443, 22222};

// PIDs holding a LISTEN on the given TCP port, across IPv4 and IPv6.
std::vector<DWORD> ListenersOn(int port);
bool IsOccupied(int port);

// Check if a PID is the System process (PID 4) or a critical system service
// that should never be killed. A process whose image path cannot be read counts
// as critical: without an identification there is no basis for terminating it.
bool IsSystemCritical(DWORD pid);

}  // namespace Ports
