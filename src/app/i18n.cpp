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

#include "app/i18n.h"

#include <windows.h>

#include <atomic>
#include <iterator>
#include <map>

#include "app/settings.h"
#include "app/text.h"

// Keys are stable identifiers; every value carries both languages side by side so
// a new string cannot be added to one language and forgotten in the other.

namespace {

// -1 until the language has been resolved; afterwards the Lang value.
std::atomic<int> g_lang{-1};

Lang DetectOsLang() {
    return PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_CHINESE ? Lang::Chinese
                                                                     : Lang::English;
}

struct Pair {
    const wchar_t* en;
    const wchar_t* zh;
};

const std::map<std::wstring, Pair>& Table() {
    // clang-format off
    // The one table in this program that is data rather than code, and the only
    // place formatting is held by hand. Keys in one column and the two languages
    // in the next is what makes a missing translation visible at a glance and
    // makes a translation diff show the sentence that changed rather than a
    // re-wrapped block. Automatic formatting packs every entry to the left, which
    // costs exactly that.
    static const std::map<std::wstring, Pair> t = {
        {L"version.display",  {L"V5.1.1", L"V5.1.1"}},

        {L"status.dns",       {L"DNS Redirection", L"DNS 重定向"}},
        {L"status.nginx",     {L"Nginx", L"Nginx"}},
        {L"status.route",     {L"Route Service", L"路由服务"}},
        {L"status.running",   {L"Running", L"运行中"}},
        {L"status.stopped",   {L"Stopped", L"已停止"}},

        {L"menu.version",     {L"Version", L"版本"}},
        {L"menu.start",       {L"Start Services", L"启动服务"}},
        {L"menu.stop",        {L"Stop Services", L"停止服务"}},
        {L"menu.enableAuto",  {L"Start on Sign-in", L"开机自动启动"}},
        {L"menu.disableAuto", {L"Don't Start on Sign-in", L"取消开机自动启动"}},
        {L"menu.checkUpdate", {L"Check for Updates", L"检查更新"}},
        {L"menu.updating",    {L"Updating…", L"正在更新…"}},
        {L"menu.autoUpdate",  {L"Check for Updates on Startup", L"启动时检查更新"}},
        {L"menu.editHosts",   {L"Edit System Hosts File", L"编辑系统 Hosts 文件"}},
        {L"menu.cleanCache",  {L"Clean Cache", L"清理缓存"}},
        {L"menu.logging",     {L"Write Log File", L"记录日志"}},
        {L"menu.language",    {L"Language", L"语言"}},
        {L"menu.misc",        {L"More", L"更多"}},
        {L"menu.about",       {L"About", L"关于"}},
        {L"menu.exit",        {L"Exit", L"退出"}},
        {L"menu.uninstall",   {L"Uninstall", L"卸载"}},
        {L"menu.viewEula",    {L"View User Agreement", L"查看用户协议"}},
        {L"menu.supportedSites", {L"Supported Sites", L"支持的网站"}},

        {L"about.copyright",  {L"Copyright (c) Racpast. All rights reserved.",
                               L"Copyright (c) Racpast. All rights reserved."}},
        {L"about.qqGroups",   {L"QQ Group:", L"QQ 交流群："}},
        {L"about.telegram",   {L"Telegram:", L"Telegram："}},
        {L"about.email",      {L"Email:", L"邮箱："}},
        {L"about.star",       {L"If this project helps you, please give me a star:",
                               L"如果这个项目对您有帮助，请您给我点一个 star："}},
        {L"about.sponsor",    {L"If you'd like to support my work, please sponsor me:",
                               L"如果您愿意支持我继续创作，请您赞助我："}},
        {L"about.github",     {L"GitHub", L"GitHub"}},
        {L"about.afdian",     {L"Afdian", L"爱发电"}},

        // Language names are always shown in their own language, so both columns
        // deliberately match.
        {L"lang.en",          {L"English", L"English"}},
        {L"lang.zh",          {L"简体中文", L"简体中文"}},

        {L"msg.needAdmin",    {L"SNIBypassGUI needs to run as administrator.",
                               L"SNIBypassGUI 需要以管理员身份运行。"}},
        {L"msg.portsInUse",   {L"Port 80, 443 or 22222 is being used by another program.\n"
                               L"Free these ports now? The programs holding them will be terminated.",
                               L"端口 80、443 或 22222 已被其他程序占用。\n"
                               L"是否立即释放这些端口？占用端口的程序将被强制结束。"}},
        {L"msg.portsCritical", {L"Port 80, 443 or 22222 is held by a Windows system process, which "
                               L"cannot be terminated safely.\nSNIBypassGUI did not start.",
                               L"端口 80、443 或 22222 被 Windows 系统进程占用，无法安全结束该进程。\n"
                               L"SNIBypassGUI 未能启动。"}},
        {L"msg.portsStillInUse", {L"The required ports are still in use after the cleanup attempt.\n"
                               L"SNIBypassGUI did not start.",
                               L"所需端口在尝试清理后仍被占用。\nSNIBypassGUI 未能启动。"}},
        {L"msg.restartFailed", {L"The services could not be started again.\n"
                               L"Use \"Start Services\" from the tray menu to retry.",
                               L"服务未能重新启动。\n请从托盘菜单中选择“启动服务”重试。"}},

        // Shown when one service of the stack fails to come up. The start is rolled
        // back, so the machine is left as it was found.
        {L"msg.startFail",    {L"A required service could not be started, so SNIBypassGUI has "
                               L"stopped everything it had started.",
                               L"必要的服务未能启动，SNIBypassGUI 已停止本次已启动的全部组件。"}},
        {L"msg.startFailLaunch", {L"could not be launched.",
                               L"无法启动。"}},
        {L"msg.startFailExited", {L"exited immediately after being launched. Its configuration "
                               L"may be invalid, a file it needs may be missing, or security "
                               L"software may have blocked it.",
                               L"启动后立即退出。可能是其配置有误、所需文件缺失，"
                               L"或被安全软件拦截。"}},
        {L"msg.dnsStartFail", {L"Could not start DNS redirection.\n"
                               L"Another program may already be using 127.11.45.14:53, or the "
                               L"DNS Client service may be disabled.",
                               L"无法启动 DNS 重定向。\n"
                               L"可能是 127.11.45.14:53 已被其他程序占用，或 DNS Client 服务被禁用。"}},
        {L"msg.dnsClientOff", {L"Windows' \"DNS Client\" service is not running, and SNIBypassGUI "
                               L"cannot redirect any domain without it — no supported site would "
                               L"work, so it did not start.\n\n"
                               L"Press Win+R, run services.msc, set \"DNS Client\" to Automatic, "
                               L"then restart Windows and try again.\n\n"
                               L"Some \"system tuning\" guides may recommend disabling this "
                               L"service, but Windows relies on it to work correctly.",
                               L"Windows 的 “DNS Client” 服务未在运行。没有它，SNIBypassGUI "
                               L"无法重定向任何域名，所有受支持的网站都不会生效，因此未启动。\n\n"
                               L"请按 Win+R 运行 services.msc，将 “DNS Client” 的启动类型设为"
                               L"“自动”，然后重启 Windows 后重试。\n\n"
                               L"部分“系统优化”教程可能会建议禁用此服务，但 Windows 的正常运行依赖于该服务。"}},
        {L"msg.started",      {L"Services are running.", L"服务已启动。"}},
        {L"msg.stopped",      {L"Services have stopped.", L"服务已停止。"}},
        {L"msg.autoOn",       {L"SNIBypassGUI will start automatically when you sign in.",
                               L"已设置为开机自动启动。"}},
        {L"msg.autoOff",      {L"SNIBypassGUI will no longer start automatically.",
                               L"已取消开机自动启动。"}},
        {L"msg.autoFail",     {L"Could not set up automatic startup.", L"设置开机自动启动失败。"}},

        {L"msg.updFail",      {L"Could not check for updates. Please check your network connection "
                               L"and try again.",
                               L"检查更新失败。请检查网络连接后重试。"}},
        {L"msg.upToDate",     {L"You're on the latest version.", L"当前已是最新版本。"}},
        {L"msg.updAvail",     {L"A new version is available", L"发现新版本"}},
        {L"msg.updDowngrade", {L"A version rollback is available", L"检测到版本回滚"}},
        {L"msg.updDataOnly",  {L"Resource updates are available", L"发现资源更新"}},
        {L"msg.updConfirm",   {L"Download and install it now?", L"是否立即下载并安装？"}},
        {L"msg.updConfirmDowngrade", {L"Apply this rollback now?", L"是否立即应用此回滚？"}},
        {L"msg.updConfirmData", {L"Download and apply them now?", L"是否立即下载并应用？"}},
        {L"msg.updDone",      {L"Update installed.", L"更新已完成。"}},
        {L"msg.updDownloading", {L"Downloading update", L"正在下载更新"}},
        {L"msg.updApplying",  {L"Installing update…", L"正在安装更新…"}},
        {L"msg.updSigFail",   {L"The update could not be verified and was rejected. The download may "
                               L"have been tampered with. Nothing on your computer was changed.",
                               L"更新内容未通过签名验证，已拒绝安装。\n"
                               L"下载的内容可能已被篡改。本次操作未对您的计算机作出任何更改。"}},
        {L"msg.updParseFail", {L"The update information is malformed and was rejected.",
                               L"更新信息格式无效，已拒绝安装。"}},
        {L"msg.updSchema",    {L"This version is too old to understand the update server's format. "
                               L"Please download the latest version manually.",
                               L"当前版本过旧，无法识别更新服务器的数据格式。请手动下载最新版本。"}},
        {L"msg.updBadPath",   {L"The update information contains an unsafe file path and was rejected.",
                               L"更新信息包含不安全的文件路径，已拒绝安装。"}},
        {L"msg.updReinstall", {L"This installation is too old to be updated in place. "
                               L"Please download and install the latest version manually.",
                               L"当前安装的版本过旧，无法直接升级。请手动下载并安装最新版本。"}},
        {L"msg.updChunkDlFail", {L"Could not download part of the update for:", L"更新分片下载失败："}},
        {L"msg.updChunkHash", {L"Part of the update failed verification for:", L"更新分片校验失败："}},
        {L"msg.updFileHash",  {L"A downloaded file failed verification:", L"下载的文件校验失败："}},
        {L"msg.updWriteFail", {L"Could not write the update to disk. Check that there is enough free "
                               L"space and that the program folder is writable.",
                               L"无法将更新写入磁盘。请确认磁盘剩余空间充足，且程序目录可写入。"}},
        {L"msg.updHashFail",  {L"Could not start verifying the update.", L"无法初始化更新校验。"}},
        {L"msg.updApplyFail", {L"Could not install the update. The previous version has been restored.",
                               L"更新安装失败，已还原到先前的版本。"}},
        {L"msg.updNotes",     {L"What's new:", L"更新内容："}},

        {L"msg.extractFirst", {L"SNIBypassGUI is running from a temporary folder and cannot find its "
                               L"data files.\n\nPlease extract the whole archive to a folder of your "
                               L"choice first, then run SNIBypassGUI.exe from there.",
                               L"SNIBypassGUI 正在从临时文件夹运行，找不到所需的数据文件。\n\n"
                               L"请先将整个压缩包解压到一个固定的文件夹，再从该文件夹运行 SNIBypassGUI.exe。"}},
        {L"msg.bootstrapFail", {L"Could not download the required data files. Please check your network "
                               L"connection and try again.",
                               L"所需的数据文件下载失败。请检查网络连接后重试。"}},
        {L"msg.uninstallConfirm", {L"Uninstall SNIBypassGUI? This will stop the services, "
                               L"remove its certificate and delete its program files.",
                               L"确定卸载 SNIBypassGUI？将停止服务、移除证书并删除程序文件。"}},
        {L"msg.cleaningCache", {L"Cleaning cache…", L"正在清理缓存…"}},
        {L"msg.cacheClean",   {L"Cache cleaned.", L"缓存已清理。"}},
        {L"msg.itemsDeleted", {L"items deleted", L"个项目已删除"}},
        {L"msg.langChanged",  {L"Language changed.", L"语言已切换。"}},
        {L"msg.copied",       {L"Copied to clipboard.", L"已复制到剪贴板。"}},
        {L"msg.shortcutAsk",  {L"Create a SNIBypassGUI shortcut on your desktop?",
                               L"是否在桌面创建 SNIBypassGUI 的快捷方式？"}},
        {L"msg.shortcutFail", {L"Could not create the desktop shortcut.", L"创建桌面快捷方式失败。"}},

        // Stored verbatim inside the .lnk as its tooltip.
        {L"shortcut.description", {L"SNIBypassGUI — A tool for improving access to certain websites",
                               L"SNIBypassGUI — 一个用于改善特定网站访问的工具"}},

        {L"eula.title",       {L"User Agreement", L"用户协议"}},
        {L"eula.intro",       {L"Please read the following agreement carefully. You must accept it "
                               L"before using SNIBypassGUI.",
                               L"请仔细阅读以下协议。您需要同意本协议后方可使用 SNIBypassGUI。"}},
        {L"eula.introView",   {L"The SNIBypassGUI user agreement, which you have already accepted.",
                               L"SNIBypassGUI 用户协议，您此前已同意本协议。"}},
        {L"eula.agree",       {L"Accept", L"同意"}},
        {L"eula.disagree",    {L"Decline", L"拒绝"}},
        {L"eula.close",       {L"Close", L"关闭"}},
        {L"eula.loadFail",    {L"Could not load the user agreement.", L"加载用户协议失败。"}},
    };
    // clang-format on
    return t;
}

}  // namespace

// Resolved once and then remembered.
//
// T() is called for every item each time the tray menu is built, and every one of
// those calls used to re-read config.ini to find out which language to answer in.
// The stored value is the only thing that can change it, and SetLang owns that.
Lang GetLang() {
    const int cached = g_lang.load(std::memory_order_relaxed);
    if (cached >= 0) return static_cast<Lang>(cached);

    wchar_t buf[16] = {};
    GetPrivateProfileStringW(L"General", L"Language", L"", buf,
                             static_cast<DWORD>(std::size(buf)), SettingsPath().c_str());
    const std::wstring value = LowerW(TrimW(buf));
    Lang resolved;
    if (value == L"zh" || value == L"cn" || value == L"chinese")
        resolved = Lang::Chinese;
    else if (value == L"en" || value == L"english")
        resolved = Lang::English;
    else
        resolved = DetectOsLang();

    g_lang.store(static_cast<int>(resolved), std::memory_order_relaxed);
    return resolved;
}

void SetLang(Lang l) {
    WritePrivateProfileStringW(L"General", L"Language", l == Lang::Chinese ? L"zh" : L"en",
                               SettingsPath().c_str());
    g_lang.store(static_cast<int>(l), std::memory_order_relaxed);
}

const wchar_t* T(const wchar_t* key) {
    const auto& t = Table();
    auto it = t.find(key);
    if (it == t.end()) return key;
    return GetLang() == Lang::Chinese ? it->second.zh : it->second.en;
}
