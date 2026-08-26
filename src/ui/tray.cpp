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

#include "ui/tray.h"

#include <shellapi.h>

#include <atomic>
#include <cwchar>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

#include "app/i18n.h"
#include "app/logging.h"
#include "app/paths.h"
#include "app/services.h"
#include "app/settings.h"
#include "app/text.h"
#include "app/version.h"
#include "platform/autostart.h"
#include "platform/process.h"
#include "platform/shell.h"
#include "platform/shortcut.h"
#include "ui/eula.h"
#include "ui/supported_sites.h"
#include "update/client.h"

namespace Tray {
namespace {

constexpr UINT kTrayMessage = WM_APP + 1;
constexpr UINT kTrayIconId = 1;
constexpr wchar_t kWindowClass[] = L"SNIBypassGUI_TrayWnd";

enum MenuId : UINT {
    kIdStatusDns = 2000,
    kIdStatusNginx,
    kIdStatusRoute,
    kIdVersion,
    kIdStart,
    kIdStop,
    kIdToggleAutostart,
    kIdCheckUpdate,
    kIdToggleAutoUpdate,
    kIdEditHosts,
    kIdCleanCache,
    kIdToggleLog,
    kIdLangEnglish,
    kIdLangChinese,
    kIdExit,
    kIdUninstall,
    kIdAboutApp,
    kIdAboutCopyright,
    kIdAboutQq1,
    kIdAboutQq2,
    kIdAboutTelegram,
    kIdAboutEmail,
    kIdAboutStar,
    kIdAboutSponsor,
    kIdViewEula,
    kIdSupportedSitesFirst = 5000,
};

// About-panel destinations.
constexpr wchar_t kUrlApp[] = L"https://snib.racpast.com";
constexpr wchar_t kUrlCopyright[] = L"https://github.com/racpast";
constexpr wchar_t kUrlQq1[] =
    L"https://qm.qq.com/cgi-bin/qm/qr?k=IXuDK0pmAcqFxgF_dUExYaU6oWFRReiT&jump_from=webapi&"
    L"authKey=WC2UM5ybN9Ez1FIWZdhOaa+K/A4aheJzgEm9GIeRmGHctOiRnpG1hRvb79vMQEaC";
constexpr wchar_t kUrlQq2[] =
    L"https://qm.qq.com/cgi-bin/qm/qr?k=kJXlDDpMHOThp2FIlsVxBf3V-Ad7vWV6&jump_from=webapi&"
    L"authKey=LFzTy1SORNq/kfexzzecmejNKPrP3D+/xYd1UzfPc3y1ZoKWijCNvBsTBcb+qFeV";
constexpr wchar_t kUrlTelegram[] = L"https://t.me/snibypassgui";
constexpr wchar_t kUrlSponsor[] = L"https://ifdian.net/a/racpast";
constexpr wchar_t kEmail[] = L"snibypassgui@gmail.com";
constexpr wchar_t kHostsFile[] = L"C:\\Windows\\System32\\drivers\\etc\\hosts";

HWND g_window = nullptr;
HICON g_icon = nullptr;
UINT g_taskbarCreated = 0;
std::vector<std::wstring> g_supportedSiteLinks;

// Set for the whole lifetime of an update check (fetch, confirm, download, apply).
// While it is set the tray disables "Check for Updates" and Start/Stop, so a second
// check cannot be launched and — critically — the user cannot start the services back
// up in the window where PerformUpdate has stopped them to replace a locked binary.
std::atomic<bool> g_updateBusy{false};

// Set during cache cleanup to prevent Start/Stop operations that would interfere.
std::atomic<bool> g_cleanupBusy{false};

// Clears g_updateBusy when the worker thread unwinds, on every path.
struct BusyGuard {
    ~BusyGuard() { g_updateBusy.store(false); }
};

// Clears g_cleanupBusy when the worker thread unwinds, on every path.
struct CleanupBusyGuard {
    ~CleanupBusyGuard() { g_cleanupBusy.store(false); }
};

std::wstring BuildTrayTooltip() {
    return std::wstring(APP_NAME) + L" " + GetVersionDisplayStr();
}

void CopyBounded(wchar_t* dst, size_t capacity, const std::wstring& text) {
    const size_t n = (text.size() < capacity - 1) ? text.size() : capacity - 1;
    std::wmemcpy(dst, text.c_str(), n);
    dst[n] = L'\0';
}

// Just enough of the structure to name our icon.
//
// Every notify-icon call builds its own copy rather than sharing one: tooltips and
// balloons are updated from the worker threads behind Start, Stop, cache cleanup
// and the update check, while the UI thread re-adds the icon when Explorer
// restarts. One shared NOTIFYICONDATAW would have those threads writing the same
// flags and buffers at the same time.
NOTIFYICONDATAW IconIdentity() {
    NOTIFYICONDATAW data = {};
    data.cbSize = sizeof(data);
    data.hWnd = g_window;
    data.uID = kTrayIconId;
    return data;
}

void SetTip(const std::wstring& tip) {
    NOTIFYICONDATAW data = IconIdentity();
    data.uFlags = NIF_TIP;
    CopyBounded(data.szTip, std::size(data.szTip), tip);
    Shell_NotifyIconW(NIM_MODIFY, &data);
}

void ResetTip() {
    SetTip(BuildTrayTooltip());
}

void ShowBalloon(const std::wstring& title, const std::wstring& text) {
    NOTIFYICONDATAW data = IconIdentity();
    data.uFlags = NIF_INFO;
    CopyBounded(data.szInfoTitle, std::size(data.szInfoTitle), title);
    CopyBounded(data.szInfo, std::size(data.szInfo), text);
    data.dwInfoFlags = NIIF_INFO;
    Shell_NotifyIconW(NIM_MODIFY, &data);
}

void AddIcon() {
    NOTIFYICONDATAW data = IconIdentity();
    data.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    data.uCallbackMessage = kTrayMessage;
    data.hIcon = g_icon;
    CopyBounded(data.szTip, std::size(data.szTip), BuildTrayTooltip());
    Shell_NotifyIconW(NIM_ADD, &data);
}

std::wstring StatusLabel(const wchar_t* nameKey, bool running) {
    return std::wstring(T(nameKey)) + T(L"punct.colon") +
           (running ? std::wstring(L"● ") + T(L"status.running")
                    : std::wstring(L"○ ") + T(L"status.stopped"));
}

HMENU BuildAboutMenu() {
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, kIdAboutApp, APP_NAME);
    AppendMenuW(menu, MF_STRING | MF_GRAYED, kIdVersion,
                (std::wstring(T(L"menu.version")) + L" " + GetVersionDisplayStr()).c_str());
    AppendMenuW(menu, MF_STRING, kIdAboutCopyright, T(L"about.copyright"));
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kIdViewEula, T(L"menu.viewEula"));
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, T(L"about.qqGroups"));
    AppendMenuW(menu, MF_STRING, kIdAboutQq1, L"① 946813204");
    AppendMenuW(menu, MF_STRING, kIdAboutQq2, L"② 1055626367");
    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, T(L"about.telegram"));
    AppendMenuW(menu, MF_STRING, kIdAboutTelegram, L"@snibypassgui");
    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, T(L"about.email"));
    AppendMenuW(menu, MF_STRING, kIdAboutEmail, kEmail);
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, T(L"about.star"));
    AppendMenuW(menu, MF_STRING, kIdAboutStar, T(L"about.github"));
    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, T(L"about.sponsor"));
    AppendMenuW(menu, MF_STRING, kIdAboutSponsor, T(L"about.afdian"));
    return menu;
}

void ShowContextMenu() {
    const bool dns = Services::DnsRedirectRunning();
    const bool nginx = Services::NginxRunning();
    const bool sniGate = Services::SniGateRunning();
    // An update or cleanup in flight owns the service state, so disable the items that would
    // race it (Start/Stop) or launch a second update/cleanup.
    const bool updateBusy = g_updateBusy.load();
    const bool cleanupBusy = g_cleanupBusy.load();
    const bool busy = updateBusy || cleanupBusy;

    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING | MF_GRAYED, kIdStatusDns,
                StatusLabel(L"status.dns", dns).c_str());
    AppendMenuW(menu, MF_STRING | MF_GRAYED, kIdStatusNginx,
                StatusLabel(L"status.nginx", nginx).c_str());
    AppendMenuW(menu, MF_STRING | MF_GRAYED, kIdStatusRoute,
                StatusLabel(L"status.route", sniGate).c_str());
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    // Offer only one of Start/Stop: if anything is running, only "Stop" — which
    // prevents clicking "Start" when the ports are already held by our own services.
    const UINT startStopFlags = MF_STRING | (busy ? MF_GRAYED : 0);
    if (dns || nginx || sniGate)
        AppendMenuW(menu, startStopFlags, kIdStop, T(L"menu.stop"));
    else
        AppendMenuW(menu, startStopFlags, kIdStart, T(L"menu.start"));

    const bool autostart = Autostart::IsEnabled();
    AppendMenuW(menu, MF_STRING, kIdToggleAutostart,
                autostart ? T(L"menu.disableAuto") : T(L"menu.enableAuto"));
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    HMENU sitesMenu = CreatePopupMenu();
    g_supportedSiteLinks = SupportedSites::PopulateMenu(sitesMenu, kIdSupportedSitesFirst);
    UINT sitesFlags = MF_POPUP;
    if (GetMenuItemCount(sitesMenu) == 0) sitesFlags |= MF_GRAYED;
    AppendMenuW(menu, sitesFlags, reinterpret_cast<UINT_PTR>(sitesMenu),
                T(L"menu.supportedSites"));
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    // While busy the item becomes a grayed indicator; the live step is carried by the
    // tray tooltip, which can repaint while the menu is held open.
    if (updateBusy)
        AppendMenuW(menu, MF_STRING | MF_GRAYED, kIdCheckUpdate, T(L"menu.updating"));
    else
        AppendMenuW(menu, MF_STRING, kIdCheckUpdate, T(L"menu.checkUpdate"));
    AppendMenuW(menu, MF_STRING | (AutoUpdateEnabled() ? MF_CHECKED : 0), kIdToggleAutoUpdate,
                T(L"menu.autoUpdate"));

    // Each language entry shows its own name, with the active one checked.
    const Lang lang = GetLang();
    HMENU langMenu = CreatePopupMenu();
    AppendMenuW(langMenu, MF_STRING | (lang == Lang::English ? MF_CHECKED : 0), kIdLangEnglish,
                T(L"lang.en"));
    AppendMenuW(langMenu, MF_STRING | (lang == Lang::Chinese ? MF_CHECKED : 0), kIdLangChinese,
                T(L"lang.zh"));
    AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(langMenu), T(L"menu.language"));

    HMENU miscMenu = CreatePopupMenu();
    AppendMenuW(miscMenu, MF_STRING | (LogEnabled() ? MF_CHECKED : 0), kIdToggleLog,
                T(L"menu.logging"));
    AppendMenuW(miscMenu, MF_STRING, kIdEditHosts, T(L"menu.editHosts"));
    // Show "Cleaning..." when cleanup is in progress.
    if (cleanupBusy)
        AppendMenuW(miscMenu, MF_STRING | MF_GRAYED, kIdCleanCache, T(L"msg.cleaningCache"));
    else
        AppendMenuW(miscMenu, MF_STRING, kIdCleanCache, T(L"menu.cleanCache"));
    // Grayed while an update or a cleanup is in flight, for the same reason Start and
    // Stop are: an uninstall would delete the tree out from under it. Showing it
    // enabled and then doing nothing on click would look like a broken menu item.
    AppendMenuW(miscMenu, MF_STRING | (busy ? MF_GRAYED : 0), kIdUninstall,
                T(L"menu.uninstall"));
    AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(miscMenu), T(L"menu.misc"));

    AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(BuildAboutMenu()), T(L"menu.about"));
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kIdExit, T(L"menu.exit"));

    POINT cursor;
    GetCursorPos(&cursor);
    SetForegroundWindow(g_window);  // so the menu dismisses correctly
    TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, cursor.x, cursor.y, 0, g_window,
                   nullptr);
    DestroyMenu(menu);
}

// ---- Command handlers (heavy work runs off the UI thread) -------------------

void DoStart() {
    if (g_updateBusy.load() || g_cleanupBusy.load())
        return;  // an update or cleanup owns the service state
    std::thread([] {
        if (Services::Start(true)) ShowBalloon(APP_NAME, T(L"msg.started"));
    }).detach();
}

void DoStop() {
    if (g_updateBusy.load() || g_cleanupBusy.load()) return;
    std::thread([] {
        Services::Stop();
        ShowBalloon(APP_NAME, T(L"msg.stopped"));
    }).detach();
}

void DoToggleAutostart() {
    std::thread([] {
        if (Autostart::IsEnabled()) {
            if (Autostart::Disable())
                ShowBalloon(APP_NAME, T(L"msg.autoOff"));
            else
                MessageBoxW(nullptr, T(L"msg.autoFail"), APP_NAME, MB_ICONERROR);
        } else if (Autostart::Enable()) {
            ShowBalloon(APP_NAME, T(L"msg.autoOn"));
        } else {
            MessageBoxW(nullptr, T(L"msg.autoFail"), APP_NAME, MB_ICONERROR);
        }
    }).detach();
}

void DoSetLang(Lang lang) {
    if (GetLang() == lang) return;
    SetLang(lang);
    // Update the tray icon tooltip to reflect the new language.
    ResetTip();
    // A .lnk stores its description as a literal string, so the shortcut we own would
    // otherwise keep the previous language's text forever. Rewrite it.
    if (GetShortcutPref() == ShortcutPref::Wanted &&
        Shortcut::Inspect() == Shortcut::State::Ours)
        Shortcut::Create();
    ShowBalloon(APP_NAME, T(L"msg.langChanged"));
}

// Prompt for and apply an already-fetched update. Assumes info.ok and that an update
// is available; runs on a worker thread. Shared by the manual check and the silent
// startup one.
void PromptAndApply(const Update::Info& info, const std::wstring& summary) {
    const int cmp = Update::CompareVersions(info.version, APP_VERSION_NUM);
    const bool exeChanges = (cmp != 0);
    const bool isDowngrade = (cmp < 0);

    // Pick the right message based on what's changing.
    const wchar_t* titleKey =
        exeChanges ? (isDowngrade ? L"msg.updDowngrade" : L"msg.updAvail") : L"msg.updDataOnly";
    const wchar_t* confirmKey =
        exeChanges ? (isDowngrade ? L"msg.updConfirmDowngrade" : L"msg.updConfirm")
                   : L"msg.updConfirmData";

    std::wstring message = std::wstring(T(titleKey)) + L" (" + info.version + L")" +
                           T(L"punct.colonEol") + L"\n\n" + summary;
    if (!info.notes.empty())
        message += std::wstring(L"\n") + T(L"msg.updNotes") + L"\n" + info.notes + L"\n";
    message += std::wstring(L"\n") + T(confirmKey);
    if (MessageBoxW(nullptr, message.c_str(), APP_NAME, MB_ICONQUESTION | MB_YESNO) != IDYES)
        return;

    const bool wasRunning = Services::AnyRunning();

    // The download does not touch the live install, so the services stay up for its
    // whole duration and are stopped only in onBeforeApply, right before the apply. If
    // the download fails, onBeforeApply never fires and the services are undisturbed.
    Update::Progress progress;
    progress.onFile = [](size_t done, size_t total, const std::wstring&) {
        SetTip(std::wstring(APP_NAME) + T(L"punct.colon") + T(L"msg.updDownloading") + L" (" +
               std::to_wstring(done) + L"/" + std::to_wstring(total) + L")");
    };
    progress.onBeforeApply = [wasRunning] {
        SetTip(std::wstring(APP_NAME) + T(L"punct.colon") + T(L"msg.updApplying"));
        if (wasRunning) Services::Stop();
    };

    if (Update::PerformUpdate(info, progress)) {
        // An executable swap was scheduled, so exit and let the helper replace us.
        PostMessageW(g_window, WM_CLOSE, 0, 0);
        return;
    }

    ResetTip();
    ShowBalloon(APP_NAME, T(L"msg.updDone"));
    // Restart only if we were running AND the apply actually stopped us: a download
    // that failed before onBeforeApply leaves the services up, and starting an
    // already-running stack would double-start it.
    if (wasRunning && !Services::AnyRunning()) {
        if (!Services::Start(false)) {
            LOGE(L"Update: FAILED to restart services after data-only update.");
            MessageBoxW(nullptr, T(L"msg.restartFailed"), APP_NAME, MB_ICONERROR);
        }
    }
}

void DoCheckUpdate() {
    // Refuse a second check while one is running. Setting the flag here, before the
    // thread starts, closes the double-click race.
    bool expected = false;
    if (!g_updateBusy.compare_exchange_strong(expected, true)) return;
    std::thread([] {
        BusyGuard guard;
        const Update::Info info = Update::FetchManifest();
        if (!info.ok) {
            // FetchManifest sets a specific reason (signature, schema, policy,
            // network); show that rather than a generic failure.
            const std::wstring why =
                info.error.empty() ? std::wstring(T(L"msg.updFail")) : info.error;
            MessageBoxW(nullptr, why.c_str(), APP_NAME,
                        info.reinstallRequired ? MB_ICONWARNING : MB_ICONERROR);
            return;
        }
        std::wstring summary;
        if (!Update::UpdateAvailable(info, summary)) {
            MessageBoxW(nullptr, T(L"msg.upToDate"), APP_NAME, MB_ICONINFORMATION);
            return;
        }
        PromptAndApply(info, summary);
    }).detach();
}

void DoUninstall() {
    // The confirmation stays on the UI thread — it is a modal question and nothing
    // else may happen until it is answered. An uninstall that lands while an update
    // is applying, or a cleanup is mid-restart, would delete the tree out from under
    // it, so the same flags that gate Start and Stop gate this too.
    if (g_updateBusy.load() || g_cleanupBusy.load()) return;
    if (MessageBoxW(nullptr, T(L"msg.uninstallConfirm"), APP_NAME, MB_ICONWARNING | MB_YESNO) !=
        IDYES)
        return;

    // The work itself runs off the UI thread. It stops the stack, which waits on the
    // same lock every tray command uses, and a Start already under way holds that
    // lock for as long as a child takes to bind its port — up to ten seconds of a
    // frozen tray if this ran here.
    std::thread([] {
        Services::Uninstall();
        // WM_CLOSE, not PostQuitMessage: the quit message has to be posted by the
        // thread that owns the message loop, and this is not it. The window's own
        // handler takes it from here, and wWinMain tears the tray icon down.
        PostMessageW(g_window, WM_CLOSE, 0, 0);
    }).detach();
}

void DoCleanCache() {
    // Refuse a second cleanup while one is running.
    bool expected = false;
    if (!g_cleanupBusy.compare_exchange_strong(expected, true)) return;

    std::thread([] {
        CleanupBusyGuard guard;
        SetTip(std::wstring(APP_NAME) + T(L"punct.colon") + T(L"msg.cleaningCache"));
        const Services::CacheCleanResult result = Services::CleanCache();
        ResetTip();
        if (!result.ok) {
            MessageBoxW(nullptr, T(L"msg.restartFailed"), APP_NAME, MB_ICONERROR);
            return;
        }
        std::wstring message = T(L"msg.cacheClean");
        message += L"\n" + std::to_wstring(result.deleted) + L" " + T(L"msg.itemsDeleted");
        ShowBalloon(APP_NAME, message);
    }).detach();
}

void HandleCommand(int id) {
    if (id >= static_cast<int>(kIdSupportedSitesFirst) &&
        id < static_cast<int>(kIdSupportedSitesFirst) +
                 static_cast<int>(g_supportedSiteLinks.size())) {
        Shell::OpenUrl(g_supportedSiteLinks[id - kIdSupportedSitesFirst].c_str());
        return;
    }

    switch (id) {
        case kIdStart: DoStart(); break;
        case kIdStop: DoStop(); break;
        case kIdToggleAutostart: DoToggleAutostart(); break;
        case kIdCheckUpdate: DoCheckUpdate(); break;
        case kIdToggleAutoUpdate: SetAutoUpdateEnabled(!AutoUpdateEnabled()); break;
        case kIdToggleLog: LogSetEnabled(!LogEnabled()); break;
        case kIdCleanCache: DoCleanCache(); break;
        case kIdLangEnglish: DoSetLang(Lang::English); break;
        case kIdLangChinese: DoSetLang(Lang::Chinese); break;
        case kIdAboutApp: Shell::OpenUrl(kUrlApp); break;
        case kIdAboutCopyright: Shell::OpenUrl(kUrlCopyright); break;
        case kIdAboutQq1: Shell::OpenUrl(kUrlQq1); break;
        case kIdAboutQq2: Shell::OpenUrl(kUrlQq2); break;
        case kIdAboutTelegram: Shell::OpenUrl(kUrlTelegram); break;
        case kIdAboutStar: Shell::OpenUrl(APP_HOMEPAGE); break;
        case kIdAboutSponsor: Shell::OpenUrl(kUrlSponsor); break;
        case kIdViewEula: Eula::ShowForReading(GetModuleHandleW(nullptr)); break;
        case kIdUninstall: DoUninstall(); break;
        case kIdAboutEmail:
            Shell::CopyToClipboard(kEmail);
            ShowBalloon(APP_NAME, T(L"msg.copied"));
            break;
        case kIdEditHosts:
            // We already run elevated, so notepad inherits that. It is launched
            // detached on purpose: an editor the user is typing in must not be
            // taken down when the tray exits.
            Process::LaunchDetached(L"C:\\Windows\\System32\\notepad.exe",
                                    std::wstring(L"\"") + kHostsFile + L"\"", L"", false);
            break;
        case kIdExit: PostMessageW(g_window, WM_CLOSE, 0, 0); break;
        default: break;
    }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    // Explorer re-registers this message when it restarts, so re-add the icon.
    if (msg == g_taskbarCreated) {
        AddIcon();
        return 0;
    }

    switch (msg) {
        case kTrayMessage:
            if (LOWORD(lp) == WM_RBUTTONUP || LOWORD(lp) == WM_CONTEXTMENU ||
                LOWORD(lp) == WM_LBUTTONUP)
                ShowContextMenu();
            return 0;

        case WM_COMMAND: HandleCommand(LOWORD(wp)); return 0;

        case WM_CLOSE: DestroyWindow(hwnd); return 0;

        case WM_DESTROY: PostQuitMessage(0); return 0;

        default: return DefWindowProcW(hwnd, msg, wp, lp);
    }
}

}  // namespace

bool Create(HINSTANCE instance) {
    g_taskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = instance;
    wc.lpszClassName = kWindowClass;
    RegisterClassExW(&wc);

    // WS_EX_TOOLWINDOW keeps it off the taskbar, and it is never shown.
    g_window = CreateWindowExW(WS_EX_TOOLWINDOW, kWindowClass, APP_NAME, WS_POPUP, 0, 0, 0, 0,
                               nullptr, nullptr, instance, nullptr);
    if (!g_window) {
        LOGE(L"Could not create the tray window.");
        return false;
    }

    g_icon = static_cast<HICON>(
        LoadImageW(instance, MAKEINTRESOURCEW(1), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE));
    if (!g_icon) g_icon = LoadIconW(nullptr, IDI_APPLICATION);

    AddIcon();
    return true;
}

void Destroy() {
    NOTIFYICONDATAW data = IconIdentity();
    Shell_NotifyIconW(NIM_DELETE, &data);
}

int RunMessageLoop() {
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}

// Any failure — network, signature, policy — is swallowed to a log line: an automatic
// check must never nag with an error dialog. If an update is available, the same
// prompt/confirm/apply path as the manual check is reused.
void StartSilentUpdateCheck() {
    bool expected = false;
    if (!g_updateBusy.compare_exchange_strong(expected, true)) return;
    std::thread([] {
        BusyGuard guard;
        const Update::Info info = Update::FetchManifest();
        if (!info.ok) {
            LOGW(L"Auto-update check failed: " +
                 (info.error.empty() ? std::wstring(L"unknown error") : info.error));
            return;
        }
        std::wstring summary;
        if (!Update::UpdateAvailable(info, summary)) {
            LOGI(L"Auto-update check: already up to date (" + info.version + L").");
            return;
        }
        PromptAndApply(info, summary);
    }).detach();
}

}  // namespace Tray
