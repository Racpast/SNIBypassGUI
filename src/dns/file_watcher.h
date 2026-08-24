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
// File monitoring with debouncing for DNS rules hot-reload.
//
// Watches a single file for changes and invokes a callback after the file has settled
// (no writes for a configurable period). This handles editors that write in chunks,
// save-as-rename patterns, and other noisy modification sequences.
//
// Usage:
//   FileWatcher watcher(L"path\\to\\dns_rules.txt", []() {
//       // Reload rules here
//   }, 500);  // 500ms debounce
//   watcher.Start();
//   // ... later ...
//   watcher.Stop();
//
// Thread-safe: the callback runs on a dedicated worker thread, NOT the thread that
// called Start(). The callback must be thread-safe with respect to whatever it does.

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

namespace Dns {

class FileWatcher {
public:
    // `path` is the file to watch. `callback` is invoked after `debounceMs` milliseconds
    // of no further changes. `debounceMs` defaults to 500ms, which handles most editors.
    FileWatcher(const std::wstring& path, std::function<void()> callback,
                unsigned debounceMs = 500);
    ~FileWatcher();
    FileWatcher(const FileWatcher&) = delete;
    FileWatcher& operator=(const FileWatcher&) = delete;

    // Start monitoring. Returns immediately; changes are handled on a worker thread.
    void Start();

    // Stop monitoring and wait for the worker thread to exit. Safe to call even if
    // never started or already stopped.
    void Stop();

    bool Running() const { return m_running.load(); }

private:
    void Loop();

    std::wstring             m_path;
    std::function<void()>    m_callback;
    unsigned                 m_debounceMs;
    void*                    m_dirHandle = nullptr;  // directory handle for ReadDirectoryChangesW
    std::wstring             m_fileName;             // bare filename to filter events
    std::thread              m_thread;
    std::atomic<bool>        m_running{false};
    std::atomic<bool>        m_stopRequested{false};
};

}  // namespace Dns
