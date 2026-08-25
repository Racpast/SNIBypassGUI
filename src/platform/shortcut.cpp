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

#include "platform/shortcut.h"

#include <windows.h>

#include <objbase.h>
#include <shlguid.h>
#include <shlobj.h>

#include "app/i18n.h"
#include "app/logging.h"
#include "app/paths.h"
#include "app/text.h"
#include "app/version.h"
#include "platform/com.h"

namespace Shortcut {
namespace {

// Named after the app, so it reads as "SNIBypassGUI" on the desktop regardless of
// what the executable file happens to be called.
const wchar_t kLinkName[] = APP_NAME L".lnk";

// The current user's desktop folder with a trailing backslash, empty on failure.
// Resolved through the shell rather than USERPROFILE so a redirected (OneDrive /
// roaming) desktop is handled correctly.
std::wstring DesktopDir() {
    wchar_t buf[MAX_PATH] = {};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_DESKTOPDIRECTORY, nullptr, SHGFP_TYPE_CURRENT,
                                buf)))
        return L"";
    std::wstring dir = buf;
    if (dir.empty()) return L"";
    if (dir.back() != L'\\') dir.push_back(L'\\');
    return dir;
}

std::wstring ReadLinkTarget(const std::wstring& lnk) {
    const Com::Scope com;
    Com::Ptr<IShellLinkW> link;
    if (FAILED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW,
                                link.PutVoid())))
        return L"";

    Com::Ptr<IPersistFile> file;
    if (FAILED(link->QueryInterface(IID_IPersistFile, file.PutVoid()))) return L"";
    if (FAILED(file->Load(lnk.c_str(), STGM_READ))) return L"";

    wchar_t buf[MAX_PATH * 2] = {};
    // SLGP_RAWPATH reads the stored path as-is, without letting the shell "resolve"
    // a stale link by searching the disk for a moved target — that search is slow
    // and could silently match the wrong file.
    if (FAILED(link->GetPath(buf, static_cast<int>(std::size(buf)), nullptr, SLGP_RAWPATH)))
        return L"";
    return buf;
}

bool SamePath(const std::wstring& a, const std::wstring& b) {
    return !a.empty() && !b.empty() && LowerW(a) == LowerW(b);
}

}  // namespace

std::wstring DesktopPath() {
    const std::wstring dir = DesktopDir();
    return dir.empty() ? L"" : dir + kLinkName;
}

bool ExeIsOnDesktop() {
    const std::wstring desktop = DesktopDir();
    return !desktop.empty() && SamePath(ExeDir(), desktop);
}

State Inspect() {
    const std::wstring lnk = DesktopPath();
    // With no resolvable desktop there is nothing to act on; report Missing so
    // callers treat it as "nothing of ours is there" and take no action.
    if (lnk.empty()) return State::Missing;
    if (GetFileAttributesW(lnk.c_str()) == INVALID_FILE_ATTRIBUTES) return State::Missing;
    return SamePath(ReadLinkTarget(lnk), ExePath()) ? State::Ours : State::Foreign;
}

bool Create() {
    const std::wstring lnk = DesktopPath();
    if (lnk.empty()) {
        LOGW(L"Shortcut: could not resolve the desktop folder.");
        return false;
    }

    const Com::Scope com;
    Com::Ptr<IShellLinkW> link;
    if (FAILED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW,
                                link.PutVoid()))) {
        LOGE(L"Shortcut: CoCreateInstance(ShellLink) failed.");
        return false;
    }

    std::wstring workDir = ExeDir();
    if (!workDir.empty() && workDir.back() == L'\\') workDir.pop_back();
    link->SetPath(ExePath().c_str());
    link->SetWorkingDirectory(workDir.c_str());
    // A .lnk stores its description literally, so this is a snapshot of the
    // current language rather than something that follows the UI on its own; a
    // language change re-runs Create() to refresh it.
    link->SetDescription(T(L"shortcut.description"));
    link->SetIconLocation(ExePath().c_str(), 0);

    Com::Ptr<IPersistFile> file;
    if (FAILED(link->QueryInterface(IID_IPersistFile, file.PutVoid()))) {
        LOGE(L"Shortcut: the shell link does not support IPersistFile.");
        return false;
    }
    const bool ok = SUCCEEDED(file->Save(lnk.c_str(), TRUE));

    if (ok)
        LOGI(L"Shortcut: created " + lnk);
    else
        LOGE(L"Shortcut: failed to save " + lnk);
    return ok;
}

void RemoveIfOurs() {
    const std::wstring lnk = DesktopPath();
    if (lnk.empty()) return;
    if (GetFileAttributesW(lnk.c_str()) == INVALID_FILE_ATTRIBUTES) return;
    // Only remove a shortcut that actually points at this executable, so one the
    // user created for something else that happens to share the name survives.
    if (!SamePath(ReadLinkTarget(lnk), ExePath())) {
        LOGW(L"Shortcut: desktop link does not point at this exe; leaving it alone.");
        return;
    }
    if (DeleteFileW(lnk.c_str())) LOGI(L"Shortcut: removed " + lnk);
}

}  // namespace Shortcut
