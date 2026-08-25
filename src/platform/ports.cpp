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

#include "platform/ports.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <iphlpapi.h>

#include <algorithm>

#include "app/text.h"
#include "platform/process.h"

namespace Ports {
namespace {

// TCP table ports are big-endian on the wire.
int HostPort(DWORD tablePort) {
    return static_cast<int>(((tablePort & 0xFF) << 8) | ((tablePort >> 8) & 0xFF));
}

template <typename Table>
void CollectListeners(ULONG family, int port, std::vector<DWORD>& pids) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, family, TCP_TABLE_OWNER_PID_LISTENER, 0);
    if (size == 0) return;
    std::vector<BYTE> buf(size);
    if (GetExtendedTcpTable(buf.data(), &size, FALSE, family, TCP_TABLE_OWNER_PID_LISTENER,
                            0) != NO_ERROR)
        return;
    const auto* table = reinterpret_cast<const Table*>(buf.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        if (row.dwState == MIB_TCP_STATE_LISTEN && HostPort(row.dwLocalPort) == port)
            pids.push_back(row.dwOwningPid);
    }
}

}  // namespace

std::vector<DWORD> ListenersOn(int port) {
    std::vector<DWORD> pids;
    CollectListeners<MIB_TCPTABLE_OWNER_PID>(AF_INET, port, pids);
    CollectListeners<MIB_TCP6TABLE_OWNER_PID>(AF_INET6, port, pids);
    std::sort(pids.begin(), pids.end());
    pids.erase(std::unique(pids.begin(), pids.end()), pids.end());
    return pids;
}

bool IsOccupied(int port) {
    return !ListenersOn(port).empty();
}

bool IsSystemCritical(DWORD pid) {
    if (pid == 0 || pid == 4) return true;  // Idle and System

    // The System process (PID 4) hosts kernel-mode drivers including http.sys,
    // which parks 80/443 for IIS/BranchCache. We handle http.sys by stopping the
    // services (net stop http), never by killing PID 4.
    std::wstring image;
    if (!Process::TryImagePath(pid, image)) return true;  // unidentified: assume critical
    image = LowerW(image);

    // System-protected paths: anything under System32 that's not our service.
    if (image.find(L"\\system32\\") != std::wstring::npos ||
        image.find(L"\\syswow64\\") != std::wstring::npos) {
        return true;
    }

    // Common system services that legitimately hold ports.
    return image.find(L"\\svchost.exe") != std::wstring::npos ||
           image.find(L"\\services.exe") != std::wstring::npos ||
           image.find(L"\\lsass.exe") != std::wstring::npos ||
           image.find(L"\\wininit.exe") != std::wstring::npos ||
           image.find(L"\\csrss.exe") != std::wstring::npos;
}

}  // namespace Ports
