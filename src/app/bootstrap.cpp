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

#include "app/bootstrap.h"

#include <windows.h>

#include <string>

#include "app/i18n.h"
#include "app/logging.h"
#include "app/paths.h"
#include "app/settings.h"
#include "app/text.h"
#include "app/version.h"
#include "platform/shortcut.h"
#include "update/client.h"

namespace Bootstrap {
namespace {

// Fetch the signed manifest and land every payload file that is missing or differs
// from it. This reuses the ordinary update path: on a fresh install every asset is
// "missing" so all of them download, while the executable version matches and is
// skipped. Shows a retry/cancel loop so a transient network error is recoverable.
bool DownloadPayloadWithRetry() {
    for (;;) {
        LOGI(L"First run: payload missing; fetching it via the signed update channel.");
        const Update::Info info = Update::FetchManifest();
        if (info.ok) {
            // PerformUpdate returns true only when it schedules an executable swap; a
            // payload-only bootstrap returns false but still lands the assets, so
            // success is judged by the payload being present afterwards.
            Update::PerformUpdate(info);
            if (PayloadPresent()) {
                LOGI(L"First run: payload downloaded and in place.");
                return true;
            }
        }
        const std::wstring why = (!info.ok && !info.error.empty())
                                     ? info.error
                                     : std::wstring(T(L"msg.bootstrapFail"));
        if (MessageBoxW(nullptr, why.c_str(), APP_NAME, MB_ICONERROR | MB_RETRYCANCEL) !=
            IDRETRY) {
            LOGE(L"First run: user cancelled the payload download; cannot continue.");
            return false;
        }
    }
}

}  // namespace

// paths.ini (the stable interface) and data/ are the anchors; if both exist we assume
// a complete extract and run offline, deferring any repair to the update check.
bool PayloadPresent() {
    const bool haveIni =
        GetFileAttributesW((ExeDir() + L"paths.ini").c_str()) != INVALID_FILE_ATTRIBUTES;
    const DWORD dataAttr = GetFileAttributesW(DataDir().c_str());
    const bool haveData =
        dataAttr != INVALID_FILE_ATTRIBUTES && (dataAttr & FILE_ATTRIBUTE_DIRECTORY);
    return haveIni && haveData;
}

// Archivers "open" an executable by extracting only it to a scratch directory under
// %TEMP% and launching it there, leaving the sibling payload inside the archive. We
// detect that location so a missing payload in this state means "you did not extract
// the whole archive" rather than "your install is broken" — and so we do NOT go
// online, which would look like a hang to an offline user.
bool RunningFromArchiveTemp() {
    const std::wstring exeDir = LowerW(ExeDir());

    // Well-known archiver scratch markers (Rar$EXa0.123\, 7zO1A2B\).
    if (exeDir.find(L"\\rar$ex") != std::wstring::npos) return true;
    if (exeDir.find(L"\\7zo") != std::wstring::npos) return true;

    const auto underTempVar = [&exeDir](const wchar_t* variable) {
        wchar_t buf[MAX_PATH * 2] = {};
        const DWORD n = GetEnvironmentVariableW(variable, buf, static_cast<DWORD>(std::size(buf)));
        if (n == 0 || n >= std::size(buf)) return false;
        std::wstring temp = LowerW(buf);
        if (!temp.empty() && temp.back() != L'\\') temp.push_back(L'\\');
        return exeDir.compare(0, temp.size(), temp) == 0;
    };
    return underTempVar(L"TEMP") || underTempVar(L"TMP");
}

bool EnsurePayload() {
    if (PayloadPresent()) return true;

    // Running from an archiver's scratch directory: the user launched the executable
    // without extracting the whole archive. Refuse clearly and never touch the network.
    if (RunningFromArchiveTemp()) {
        LOGE(L"Running from an archive temp dir without payload; refusing to continue.");
        MessageBoxW(nullptr, T(L"msg.extractFirst"), APP_NAME, MB_ICONERROR | MB_OK);
        return false;
    }

    // A fixed install whose payload is gone: re-fetch it.
    return DownloadPayloadWithRetry();
}

// Extract-and-run means no installer ever put this program anywhere findable: a user
// who extracted it into a nested folder has nothing to click next time. So we offer a
// desktop shortcut, and thereafter keep it honest.
//
// Two facts shape the rules. First, each copy carries its own config.ini, so the
// stored preference is per-copy while the desktop is shared: running a second copy
// repoints the one shortcut at itself. Second, the two ways a shortcut can stop being
// ours are NOT equivalent:
//
//   Foreign (present, pointing elsewhere) — another copy took the name. The user asked
//       THIS copy for a shortcut and no longer has one, so repointing it restores what
//       they asked for. Whichever copy ran last owns the desktop, which matches the
//       copy the user is actually using.
//   Missing (not there at all) — the user deleted it. Recreating that would overrule
//       them on every launch, so a delete is taken as a change of mind and the
//       preference is reset to declined.
//
// A decline is therefore permanent until the user acts again, and we never fight the
// user over a file they removed on purpose. Only the never-asked state prompts.
void SyncDesktopShortcut() {
    // The executable already sits on the desktop: a shortcut beside it is pointless.
    if (Shortcut::ExeIsOnDesktop()) return;

    const ShortcutPref pref = GetShortcutPref();
    if (pref == ShortcutPref::Declined) return;

    const Shortcut::State state = Shortcut::Inspect();

    if (pref == ShortcutPref::Wanted) {
        switch (state) {
            case Shortcut::State::Ours:
                // Already correct. Create() is cheap and idempotent, so refresh
                // unconditionally — the stored description does not follow a language
                // change on its own.
                Shortcut::Create();
                return;
            case Shortcut::State::Foreign:
                LOGI(L"Shortcut: desktop link points at another copy; repointing it here.");
                Shortcut::Create();
                return;
            case Shortcut::State::Missing:
                LOGI(L"Shortcut: desktop link was removed by the user; not recreating it.");
                SetShortcutPref(ShortcutPref::Declined);
                return;
        }
        return;
    }

    // Never asked. If a shortcut for this executable somehow already exists, adopt it
    // rather than asking about something the user evidently already has.
    if (state == Shortcut::State::Ours) {
        SetShortcutPref(ShortcutPref::Wanted);
        return;
    }

    if (MessageBoxW(nullptr, T(L"msg.shortcutAsk"), APP_NAME, MB_ICONQUESTION | MB_YESNO) !=
        IDYES) {
        // Any non-Yes outcome (No, Esc, the close button) is a decline, recorded so the
        // question never comes back on its own.
        SetShortcutPref(ShortcutPref::Declined);
        return;
    }
    if (Shortcut::Create()) {
        SetShortcutPref(ShortcutPref::Wanted);
    } else {
        // Do not record a preference we failed to honour: leaving it unset lets the
        // next launch try again rather than silently giving up forever.
        MessageBoxW(nullptr, T(L"msg.shortcutFail"), APP_NAME, MB_ICONWARNING);
    }
}

}  // namespace Bootstrap
