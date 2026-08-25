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

#include "platform/autostart.h"

#include <windows.h>

#include <sddl.h>
#include <taskschd.h>

#include <cstdio>
#include <string>
#include <vector>

#include "app/i18n.h"
#include "app/logging.h"
#include "app/paths.h"
#include "app/text.h"
#include "app/version.h"
#include "platform/com.h"

namespace Autostart {
namespace {

// The scheduler stores a task's action path verbatim, but a task written by hand
// may have quoted it. Strip one layer so the comparison is about the path.
std::wstring Unquote(std::wstring s) {
    s = TrimW(s);
    if (s.size() >= 2 && s.front() == L'"' && s.back() == L'"') s = s.substr(1, s.size() - 2);
    return s;
}

std::wstring HexHresult(HRESULT hr) {
    wchar_t buf[16];
    std::swprintf(buf, std::size(buf), L"0x%08lX", static_cast<unsigned long>(hr));
    return buf;
}

// The current user's SID, in string form.
//
// The logon trigger is scoped to a specific user, and a SID says which one without
// depending on a display name that varies with locale, domain form and renames.
std::wstring CurrentUserSid() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return L"";

    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::wstring sid;
    if (size > 0) {
        std::vector<BYTE> buffer(size);
        if (GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) {
            wchar_t* text = nullptr;
            const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
            if (ConvertSidToStringSidW(user->User.Sid, &text)) {
                sid = text;
                LocalFree(text);
            }
        }
    }
    CloseHandle(token);
    return sid;
}

// Connect to the local scheduler and open the root folder.
bool OpenRootFolder(Com::Ptr<ITaskService>& service, Com::Ptr<ITaskFolder>& folder) {
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_ITaskService, service.PutVoid());
    if (FAILED(hr)) {
        LOGE(L"Autostart: cannot create the Task Scheduler client (" + HexHresult(hr) + L").");
        return false;
    }
    Com::Variant empty;
    hr = service->Connect(empty.Get(), empty.Get(), empty.Get(), empty.Get());
    if (FAILED(hr)) {
        LOGE(L"Autostart: cannot connect to the Task Scheduler service (" + HexHresult(hr) +
             L").");
        return false;
    }
    const Com::Bstr root(L"\\");
    hr = service->GetFolder(root.Get(), folder.Put());
    if (FAILED(hr)) {
        LOGE(L"Autostart: cannot open the root task folder (" + HexHresult(hr) + L").");
        return false;
    }
    return true;
}

// The executable an existing task launches, empty if it has no exec action.
std::wstring RegisteredExecutable(IRegisteredTask* task) {
    Com::Ptr<ITaskDefinition> definition;
    if (FAILED(task->get_Definition(definition.Put()))) return L"";

    Com::Ptr<IActionCollection> actions;
    if (FAILED(definition->get_Actions(actions.Put()))) return L"";

    Com::Ptr<IAction> action;
    if (FAILED(actions->get_Item(1, action.Put()))) return L"";  // collections are 1-based

    Com::Ptr<IExecAction> exec;
    if (FAILED(action->QueryInterface(IID_IExecAction, exec.PutVoid()))) return L"";

    Com::Bstr path;
    if (FAILED(exec->get_Path(path.Put()))) return L"";
    return Unquote(path.Str());
}

// Build the task definition for a logon start of this executable.
bool BuildDefinition(ITaskService* service, Com::Ptr<ITaskDefinition>& definition) {
    HRESULT hr = service->NewTask(0, definition.Put());
    if (FAILED(hr)) {
        LOGE(L"Autostart: cannot create a task definition (" + HexHresult(hr) + L").");
        return false;
    }

    {
        Com::Ptr<IRegistrationInfo> info;
        if (SUCCEEDED(definition->get_RegistrationInfo(info.Put()))) {
            const Com::Bstr author(L"Racpast");
            const Com::Bstr description(T(L"shortcut.description"));
            info->put_Author(author.Get());
            info->put_Description(description.Get());
        }
    }

    {
        // Highest privileges, because the program needs administrator rights and a
        // logon start must not stop to ask for them.
        Com::Ptr<IPrincipal> principal;
        if (SUCCEEDED(definition->get_Principal(principal.Put()))) {
            principal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
            principal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
        }
    }

    {
        // The scheduler's defaults are written for maintenance jobs: they refuse to
        // start on battery, stop the task when the machine unplugs, and kill it after
        // three days. All three are wrong for something the user expects to sit in
        // their tray for as long as they are signed in.
        Com::Ptr<ITaskSettings> settings;
        if (SUCCEEDED(definition->get_Settings(settings.Put()))) {
            settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
            settings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
            settings->put_MultipleInstances(TASK_INSTANCES_IGNORE_NEW);
            const Com::Bstr noLimit(L"PT0S");
            settings->put_ExecutionTimeLimit(noLimit.Get());
        }
    }

    {
        Com::Ptr<ITriggerCollection> triggers;
        if (FAILED(definition->get_Triggers(triggers.Put()))) return false;
        Com::Ptr<ITrigger> trigger;
        if (FAILED(triggers->Create(TASK_TRIGGER_LOGON, trigger.Put()))) return false;
        Com::Ptr<ILogonTrigger> logon;
        if (SUCCEEDED(trigger->QueryInterface(IID_ILogonTrigger, logon.PutVoid()))) {
            const Com::Bstr id(L"SNIBypassGUI_Logon");
            logon->put_Id(id.Get());
            const std::wstring sid = CurrentUserSid();
            if (!sid.empty()) {
                const Com::Bstr user(sid);
                logon->put_UserId(user.Get());
            }
        }
    }

    {
        Com::Ptr<IActionCollection> actions;
        if (FAILED(definition->get_Actions(actions.Put()))) return false;
        Com::Ptr<IAction> action;
        if (FAILED(actions->Create(TASK_ACTION_EXEC, action.Put()))) return false;
        Com::Ptr<IExecAction> exec;
        if (FAILED(action->QueryInterface(IID_IExecAction, exec.PutVoid()))) return false;

        // Every one of these travels as UTF-16 from here to the scheduler's own
        // store: there is no code page anywhere on the path, so an install folder
        // with non-ASCII characters is not a special case.
        std::wstring workDir = ExeDir();
        if (!workDir.empty() && workDir.back() == L'\\') workDir.pop_back();
        const Com::Bstr path(ExePath());
        const Com::Bstr args(L"-autostart");
        const Com::Bstr dir(workDir);
        exec->put_Path(path.Get());
        exec->put_Arguments(args.Get());
        exec->put_WorkingDirectory(dir.Get());
    }
    return true;
}

}  // namespace

bool IsEnabled() {
    const Com::Scope com;
    Com::Ptr<ITaskService> service;
    Com::Ptr<ITaskFolder> folder;
    if (!OpenRootFolder(service, folder)) return false;

    const Com::Bstr name(APP_TASK_NAME);
    Com::Ptr<IRegisteredTask> task;
    if (FAILED(folder->GetTask(name.Get(), task.Put()))) return false;  // absent

    return LowerW(RegisteredExecutable(task.Get())) == LowerW(ExePath());
}

bool Enable() {
    const Com::Scope com;
    Com::Ptr<ITaskService> service;
    Com::Ptr<ITaskFolder> folder;
    if (!OpenRootFolder(service, folder)) return false;

    Com::Ptr<ITaskDefinition> definition;
    if (!BuildDefinition(service.Get(), definition)) return false;

    const Com::Bstr name(APP_TASK_NAME);
    Com::Variant userId;
    Com::Variant password;
    Com::Variant sddl;
    Com::Ptr<IRegisteredTask> registered;
    const HRESULT hr = folder->RegisterTaskDefinition(
        name.Get(), definition.Get(), TASK_CREATE_OR_UPDATE, userId.Get(), password.Get(),
        TASK_LOGON_INTERACTIVE_TOKEN, sddl.Get(), registered.Put());
    if (FAILED(hr)) {
        LOGE(L"Autostart: cannot register the logon task (" + HexHresult(hr) + L").");
        return false;
    }
    LOGI(L"Autostart enabled for " + ExePath());
    return true;
}

bool Disable() {
    const Com::Scope com;
    Com::Ptr<ITaskService> service;
    Com::Ptr<ITaskFolder> folder;
    if (!OpenRootFolder(service, folder)) return false;

    const Com::Bstr name(APP_TASK_NAME);
    const HRESULT hr = folder->DeleteTask(name.Get(), 0);
    // A task that is not there is the state we were asked to produce.
    if (FAILED(hr) && hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
        LOGE(L"Autostart: cannot delete the logon task (" + HexHresult(hr) + L").");
        return false;
    }
    LOGI(L"Autostart disabled.");
    return true;
}

}  // namespace Autostart
