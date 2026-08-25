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
// Watches a single file and invokes a callback once it has settled (no further
// change for a configurable period), which absorbs editors that write in chunks,
// save-as-rename patterns and other noisy sequences.
//
// Usage:
//   FileWatcher watcher(L"path\\to\\dns_hosts.txt", [] { /* reload */ }, 500);
//   watcher.Start();
//   ...
//   watcher.Stop();
//
// The callback runs on the watcher's own worker thread, never on the thread that
// called Start(), so it must be safe to run concurrently with whatever else the
// owner is doing.

#include <atomic>
#include <functional>
#include <string>
#include <thread>

namespace Dns {

class FileWatcher {
public:
    // `callback` fires after `debounceMs` with no further change.
    FileWatcher(const std::wstring& path, std::function<void()> callback,
                unsigned debounceMs = 500);
    ~FileWatcher();
    FileWatcher(const FileWatcher&) = delete;
    FileWatcher& operator=(const FileWatcher&) = delete;

    // Start monitoring. Returns immediately; a second call while already watching
    // does nothing.
    void Start();

    // Stop monitoring and wait for the worker thread to exit.
    //
    // Every step is guarded by the resource it releases, not by a "running" flag:
    // the thread is joined if it is joinable, the handle closed if it is open. A
    // flag cannot express this, because the worker clears it when it exits on its
    // own — and an early return on that flag would skip the join and leave a
    // joinable std::thread to be destroyed, which terminates the process.
    void Stop();

private:
    void Loop();

    std::wstring m_path;
    std::function<void()> m_callback;
    unsigned m_debounceMs;
    void* m_dirHandle = nullptr;  // directory being watched
    std::wstring m_fileName;      // bare name, to filter events
    std::thread m_thread;
    std::atomic<bool> m_stopRequested{false};
};

}  // namespace Dns
