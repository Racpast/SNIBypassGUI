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
// Centralized service state management with proper locking to prevent race
// conditions between Start/Stop operations and status queries.
//
// All service state (DNS interceptor, nginx, sni-gate) is tracked here with
// a single mutex protecting both the state flags and the operations that
// change them. This eliminates TOCTOU races where one thread checks a status
// while another is modifying it.

#include <windows.h>

#include <atomic>
#include <mutex>
#include <string>

namespace ServiceState {

// Service identifiers for tracking.
enum class Service { DnsInterceptor, Nginx, SniGate };

// State query (thread-safe, read-only).
bool IsRunning(Service service);
bool AnyRunning();

// State update (called by Services::Start/Stop under g_operationMutex).
// These are NOT thread-safe on their own; the caller must hold the operation lock.
void SetRunning(Service service, bool running);
void SetAllStopped();

// Process tracking for validation: record PIDs when services start so we can
// verify that the running process is the exact one we launched, not a hijacker.
void RecordPid(Service service, DWORD pid);
DWORD GetRecordedPid(Service service);
void ClearPid(Service service);

// Path validation: record the canonical executable paths from paths.ini at
// startup so we can verify that any running process claiming to be ours is
// actually at the expected location.
void SetExpectedPath(Service service, const std::wstring& path);
std::wstring GetExpectedPath(Service service);

}  // namespace ServiceState
