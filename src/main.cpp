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

#include <windows.h>

#include <string>
#include <thread>

#include "app/bootstrap.h"
#include "app/i18n.h"
#include "app/logging.h"
#include "app/services.h"
#include "app/settings.h"
#include "app/text.h"
#include "app/version.h"
#include "platform/elevation.h"
#include "platform/process.h"
#include "ui/eula.h"
#include "ui/tray.h"

namespace {

bool HasFlag(const std::wstring& cmdline, const std::wstring& flag) {
    return LowerW(cmdline).find(LowerW(flag)) != std::wstring::npos;
}

// Keep THIS process and kill every other copy, regardless of where it runs from.
void EnforceSingleInstance() {
    const DWORD self = GetCurrentProcessId();
    for (DWORD pid : Process::FindByName(L"SNIBypassGUI.exe")) {
        if (pid == self) continue;
        LOGW(L"Killing another SNIBypassGUI instance, pid " + std::to_wstring(pid));
        Process::KillTree(pid);
    }
}

// Owns the single-instance mutex for the lifetime of the run.
class InstanceMutex {
public:
    InstanceMutex() : handle_(CreateMutexW(nullptr, TRUE, APP_MUTEX_NAME)) {}
    ~InstanceMutex() {
        if (handle_) {
            ReleaseMutex(handle_);
            CloseHandle(handle_);
        }
    }
    InstanceMutex(const InstanceMutex&) = delete;
    InstanceMutex& operator=(const InstanceMutex&) = delete;

private:
    HANDLE handle_;
};

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR lpCmdLine, int) {
    const std::wstring cmdline = lpCmdLine ? lpCmdLine : L"";

    LogInit();
    LOGI(L"=== SNIBypassGUI " + GetVersionDisplayStr() + L" (" + APP_VERSION_NUM
         + L") starting (args: " + cmdline + L") ===");

    // 1. Require administrator, elevating if necessary.
    if (!IsRunningAsAdmin()) {
        if (!RelaunchElevated(cmdline))
            MessageBoxW(nullptr, T(L"msg.needAdmin"), APP_NAME, MB_ICONERROR);
        return 0;
    }

    // 2. Run-location sanity check. A missing payload while running from an archiver's
    //    scratch directory means the archive was never extracted; refuse early, before
    //    any prompt or network access. A fixed install with a missing payload is
    //    handled after the agreement, through the signed download path.
    if (!Bootstrap::PayloadPresent() && Bootstrap::RunningFromArchiveTemp()) {
        LOGE(L"Running from an archive temp dir without payload; refusing to continue.");
        MessageBoxW(nullptr, T(L"msg.extractFirst"), APP_NAME, MB_ICONERROR | MB_OK);
        return 0;
    }

    // 3. Single instance: kill any other copy, keep this one. The named mutex closes
    //    the race where two copies start simultaneously.
    EnforceSingleInstance();
    const InstanceMutex instanceMutex;

    // 4. Only our own child binaries may be running.
    Services::EnforceCleanSlate();

    const bool autostartMode = HasFlag(cmdline, L"-autostart") || HasFlag(cmdline, L"/autostart");

    // 5. Every launch needs an accepted agreement before the tray appears. Declining
    //    exits without starting anything.
    if (!Eula::EnsureAccepted(instance)) {
        LOGI(L"User declined the agreement; exiting.");
        return 0;
    }

    // 6. Ensure the payload is present. When it is missing on a fixed install, this
    //    fetches it through the signed update channel — only reached after the
    //    agreement, so there is no network access before it.
    if (!Bootstrap::EnsurePayload()) {
        LOGE(L"Payload unavailable; exiting.");
        return 0;
    }

    if (!Tray::Create(instance)) return 1;

    // Reconcile the desktop shortcut. Skipped in autostart mode: a logon launch must
    // not put a dialog in front of the user, and the shortcut should follow the copy
    // the user launched by hand, not one the scheduler started for them.
    if (!autostartMode) Bootstrap::SyncDesktopShortcut();

    // Bring the stack up on a worker thread so the tray appears immediately.
    if (autostartMode) std::thread([] { Services::RunAutostartMode(); }).detach();

    // The silent check is self-threaded and never shows an error dialog, so it cannot
    // delay or disrupt the tray coming up.
    if (AutoUpdateEnabled()) {
        LOGI(L"AutoUpdate is on; running a silent startup update check.");
        Tray::StartSilentUpdateCheck();
    }

    const int exitCode = Tray::RunMessageLoop();

    if (Services::AnyRunning()) Services::Stop();
    Tray::Destroy();
    LOGI(L"Exited.");
    return exitCode;
}
