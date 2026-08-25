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

#include <cstdint>
#include <utility>

#include "app/logging.h"

namespace Dns {
namespace {

constexpr DWORD kNotifyBufferSize = 4096;

}  // namespace

FileWatcher::FileWatcher(const std::wstring& path, std::function<void()> callback,
                         unsigned debounceMs)
    : m_path(path), m_callback(std::move(callback)), m_debounceMs(debounceMs) {
    const size_t slash = m_path.find_last_of(L"\\/");
    m_fileName = (slash == std::wstring::npos) ? m_path : m_path.substr(slash + 1);
}

FileWatcher::~FileWatcher() {
    Stop();
}

void FileWatcher::Start() {
    if (m_thread.joinable()) return;

    std::wstring dir = m_path;
    const size_t slash = dir.find_last_of(L"\\/");
    dir = (slash == std::wstring::npos) ? L"." : dir.substr(0, slash);

    m_dirHandle =
        CreateFileW(dir.c_str(), FILE_LIST_DIRECTORY,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
    if (m_dirHandle == INVALID_HANDLE_VALUE) {
        LOGE(L"FileWatcher: cannot open directory for monitoring: " + dir);
        m_dirHandle = nullptr;
        return;
    }

    m_stopRequested.store(false);
    m_thread = std::thread([this] { Loop(); });
    LOGI(L"FileWatcher: started monitoring " + m_path);
}

void FileWatcher::Stop() {
    m_stopRequested.store(true);

    // Wake a thread parked in its wait. CancelIoEx makes the pending read complete
    // with ERROR_OPERATION_ABORTED instead of waiting for a change that may never
    // come.
    if (m_dirHandle) CancelIoEx(m_dirHandle, nullptr);

    const bool joined = m_thread.joinable();
    if (joined) m_thread.join();

    if (m_dirHandle) {
        CloseHandle(m_dirHandle);
        m_dirHandle = nullptr;
    }
    if (joined) LOGI(L"FileWatcher: stopped monitoring " + m_path);
}

void FileWatcher::Loop() {
    alignas(DWORD) uint8_t buffer[kNotifyBufferSize];

    OVERLAPPED overlapped = {};
    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!overlapped.hEvent) {
        LOGE(L"FileWatcher: cannot create event object.");
        return;
    }

    // One read is outstanding at a time, and a new one is issued only after the
    // previous has completed. Reissuing while a read is still pending would have
    // two operations sharing this OVERLAPPED and this buffer, and would reset the
    // event the pending one is about to signal.
    const auto issueRead = [&]() -> bool {
        ResetEvent(overlapped.hEvent);
        DWORD ignored = 0;
        if (ReadDirectoryChangesW(m_dirHandle, buffer, kNotifyBufferSize, FALSE,
                                  FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME,
                                  &ignored, &overlapped, nullptr))
            return true;
        return GetLastError() == ERROR_IO_PENDING;
    };

    bool pendingReload = false;
    bool watching = issueRead();
    if (!watching) LOGE(L"FileWatcher: ReadDirectoryChangesW failed.");

    while (watching && !m_stopRequested.load()) {
        // With a change already seen, the wait doubles as the debounce timer: it
        // expires only if nothing else arrives in the meantime.
        const DWORD waited =
            WaitForSingleObject(overlapped.hEvent, pendingReload ? m_debounceMs : INFINITE);
        if (m_stopRequested.load()) break;

        if (waited == WAIT_TIMEOUT) {
            LOGI(L"FileWatcher: file settled, triggering reload.");
            m_callback();
            pendingReload = false;
            continue;  // the read from before is still outstanding
        }
        if (waited != WAIT_OBJECT_0) break;

        DWORD bytes = 0;
        if (!GetOverlappedResult(m_dirHandle, &overlapped, &bytes, FALSE)) {
            if (!m_stopRequested.load())
                LOGE(L"FileWatcher: change notification failed; stopping the watch.");
            break;
        }

        // A zero-length result means the kernel's change buffer overflowed and the
        // individual events were lost. Something in the directory changed, we just
        // cannot tell what, so assume it was ours rather than miss an edit.
        bool ourFileChanged = (bytes == 0);
        for (size_t offset = 0; offset < bytes;) {
            const auto* info =
                reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(buffer + offset);
            const std::wstring name(info->FileName, info->FileNameLength / sizeof(wchar_t));
            if (_wcsicmp(name.c_str(), m_fileName.c_str()) == 0 &&
                (info->Action == FILE_ACTION_MODIFIED || info->Action == FILE_ACTION_ADDED ||
                 info->Action == FILE_ACTION_RENAMED_NEW_NAME))
                ourFileChanged = true;

            if (info->NextEntryOffset == 0) break;
            offset += info->NextEntryOffset;
        }

        if (ourFileChanged) {
            pendingReload = true;
            LOGI(L"FileWatcher: detected change in " + m_fileName + L", starting debounce.");
        }
        watching = issueRead();
        if (!watching) LOGE(L"FileWatcher: ReadDirectoryChangesW failed.");
    }

    // A read may still be outstanding, and it completes into `overlapped` and
    // `buffer` — both of which live on this stack frame. Cancel it and wait for the
    // cancellation to land before either goes away.
    CancelIoEx(m_dirHandle, &overlapped);
    DWORD discarded = 0;
    GetOverlappedResult(m_dirHandle, &overlapped, &discarded, TRUE);
    CloseHandle(overlapped.hEvent);
}

}  // namespace Dns
