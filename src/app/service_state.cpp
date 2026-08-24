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

#include "app/service_state.h"

#include <windows.h>

#include <array>
#include <mutex>
#include <string>

#include "app/text.h"

namespace ServiceState {
namespace {

struct State {
    bool running = false;
    DWORD pid = 0;
    std::wstring expectedPath;
};

std::mutex g_stateMutex;
std::array<State, 3> g_states;  // DnsInterceptor, Nginx, SniGate

size_t Index(Service service) {
    return static_cast<size_t>(service);
}

}  // namespace

bool IsRunning(Service service) {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    return g_states[Index(service)].running;
}

bool AnyRunning() {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    for (const State& s : g_states) {
        if (s.running) return true;
    }
    return false;
}

void SetRunning(Service service, bool running) {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_states[Index(service)].running = running;
}

void SetAllStopped() {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    for (State& s : g_states) {
        s.running = false;
        s.pid = 0;
    }
}

void RecordPid(Service service, DWORD pid) {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_states[Index(service)].pid = pid;
}

DWORD GetRecordedPid(Service service) {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    return g_states[Index(service)].pid;
}

void ClearPid(Service service) {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_states[Index(service)].pid = 0;
}

void SetExpectedPath(Service service, const std::wstring& path) {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    g_states[Index(service)].expectedPath = LowerW(path);
}

std::wstring GetExpectedPath(Service service) {
    std::lock_guard<std::mutex> lock(g_stateMutex);
    return g_states[Index(service)].expectedPath;
}

}  // namespace ServiceState
