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

#include "dns/file_watcher.h"

#include <windows.h>

#include "app/logging.h"

namespace Dns {

FileWatcher::FileWatcher(const std::wstring& path, std::function<void()> callback,
                         unsigned debounceMs)
    : m_path(path), m_callback(std::move(callback)), m_debounceMs(debounceMs) {
    // Extract directory and filename for filtering.
    const size_t slash = m_path.find_last_of(L"\\/");
    if (slash != std::wstring::npos) {
        m_fileName = m_path.substr(slash + 1);
    } else {
        m_fileName = m_path;
    }
}

FileWatcher::~FileWatcher() {
    Stop();
}

void FileWatcher::Start() {
    if (m_running.load()) return;

    // Extract the directory to watch.
    std::wstring dir = m_path;
    const size_t slash = dir.find_last_of(L"\\/");
    if (slash != std::wstring::npos) {
        dir = dir.substr(0, slash);
    } else {
        dir = L".";
    }

    // Open the directory for change notification.
    m_dirHandle = CreateFileW(dir.c_str(), FILE_LIST_DIRECTORY,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
    if (m_dirHandle == INVALID_HANDLE_VALUE) {
        LOGE(L"FileWatcher: cannot open directory for monitoring: " + dir);
        m_dirHandle = nullptr;
        return;
    }

    m_stopRequested.store(false);
    m_running.store(true);
    m_thread = std::thread([this] { Loop(); });
    LOGI(L"FileWatcher: started monitoring " + m_path);
}

void FileWatcher::Stop() {
    if (!m_running.load()) return;

    m_stopRequested.store(true);

    // Cancel any pending I/O to wake up the thread.
    if (m_dirHandle) CancelIoEx(m_dirHandle, nullptr);

    if (m_thread.joinable()) m_thread.join();

    if (m_dirHandle) {
        CloseHandle(m_dirHandle);
        m_dirHandle = nullptr;
    }

    m_running.store(false);
    LOGI(L"FileWatcher: stopped monitoring " + m_path);
}

void FileWatcher::Loop() {
    // Buffer for ReadDirectoryChangesW results.
    constexpr DWORD kBufferSize = 4096;
    alignas(DWORD) uint8_t buffer[kBufferSize];

    OVERLAPPED overlapped = {};
    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!overlapped.hEvent) {
        LOGE(L"FileWatcher: cannot create event object.");
        m_running.store(false);
        return;
    }

    bool pendingReload = false;

    while (!m_stopRequested.load()) {
        // Start an async read.
        DWORD bytesReturned = 0;
        ResetEvent(overlapped.hEvent);
        const BOOL ok = ReadDirectoryChangesW(
            m_dirHandle, buffer, kBufferSize, FALSE,
            FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME, &bytesReturned,
            &overlapped, nullptr);

        if (!ok && GetLastError() != ERROR_IO_PENDING) {
            if (!m_stopRequested.load())
                LOGE(L"FileWatcher: ReadDirectoryChangesW failed.");
            break;
        }

        // Wait for the read to complete or stop signal.
        const DWORD timeout = pendingReload ? m_debounceMs : INFINITE;
        const DWORD waitResult = WaitForSingleObject(overlapped.hEvent, timeout);

        if (m_stopRequested.load()) break;

        if (waitResult == WAIT_TIMEOUT) {
            // Debounce timer expired with no new changes; fire the callback.
            if (pendingReload) {
                LOGI(L"FileWatcher: file settled, triggering reload.");
                m_callback();
                pendingReload = false;
            }
            continue;
        }

        if (waitResult != WAIT_OBJECT_0) continue;

        // Read completed; check if our file was modified.
        if (!GetOverlappedResult(m_dirHandle, &overlapped, &bytesReturned, FALSE)) continue;
        if (bytesReturned == 0) continue;

        // Parse the FILE_NOTIFY_INFORMATION entries.
        bool ourFileChanged = false;
        size_t offset = 0;
        while (offset < bytesReturned) {
            const auto* info =
                reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(buffer + offset);

            // Extract the filename from the notification.
            const std::wstring name(info->FileName, info->FileNameLength / sizeof(wchar_t));

            // Check if this is the file we're watching.
            if (_wcsicmp(name.c_str(), m_fileName.c_str()) == 0) {
                const DWORD action = info->Action;
                if (action == FILE_ACTION_MODIFIED || action == FILE_ACTION_ADDED ||
                    action == FILE_ACTION_RENAMED_NEW_NAME) {
                    ourFileChanged = true;
                }
            }

            if (info->NextEntryOffset == 0) break;
            offset += info->NextEntryOffset;
        }

        // If our file changed, reset the debounce timer.
        if (ourFileChanged) {
            pendingReload = true;
            LOGI(L"FileWatcher: detected change in " + m_fileName + L", starting debounce.");
        }
    }

    CloseHandle(overlapped.hEvent);
    m_running.store(false);
}

}  // namespace Dns
