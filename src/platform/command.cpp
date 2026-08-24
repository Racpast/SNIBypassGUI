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

#include "platform/command.h"

#include <string>
#include <thread>
#include <vector>

#include "app/logging.h"
#include "app/text.h"
#include "platform/process.h"

namespace Command {

int RunHidden(const std::wstring& cmdline, std::wstring* out, DWORD timeoutMs) {
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE readEnd = nullptr;
    HANDLE writeEnd = nullptr;
    if (out) {
        if (!CreatePipe(&readEnd, &writeEnd, &sa, 0))
            out = nullptr;
        else
            SetHandleInformation(readEnd, HANDLE_FLAG_INHERIT, 0);
    }

    std::vector<wchar_t> mutableCmd(cmdline.begin(), cmdline.end());
    mutableCmd.push_back(L'\0');

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    if (out) {
        si.dwFlags |= STARTF_USESTDHANDLES;
        si.hStdOutput = writeEnd;
        si.hStdError = writeEnd;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    }

    PROCESS_INFORMATION pi = {};
    const BOOL started =
        CreateProcessW(nullptr, mutableCmd.data(), nullptr, nullptr, out ? TRUE : FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (writeEnd) CloseHandle(writeEnd);
    if (!started) {
        if (readEnd) CloseHandle(readEnd);
        return -1;
    }

    // Drain the child's output on a background thread so a chatty child cannot
    // fill the pipe and deadlock against our own timeout wait. The thread ends
    // when the write end closes, i.e. once the child exits or is terminated.
    std::string captured;
    std::thread reader;
    if (out && readEnd) {
        reader = std::thread([readEnd, &captured] {
            char buf[4096];
            DWORD n = 0;
            while (ReadFile(readEnd, buf, sizeof(buf), &n, nullptr) && n > 0)
                captured.append(buf, n);
        });
    }

    const DWORD waitResult = WaitForSingleObject(pi.hProcess, timeoutMs);
    if (waitResult == WAIT_TIMEOUT) {
        LOGW(L"Command timed out; terminating: " + cmdline);
        Process::KillTree(pi.dwProcessId);
        WaitForSingleObject(pi.hProcess, 5000);
    }

    if (reader.joinable()) reader.join();
    if (readEnd) CloseHandle(readEnd);

    if (out) {
        // Console output is usually UTF-8; fall back to the active code page when
        // it decodes to nothing.
        *out = Utf8ToWide(captured);
        if (out->empty() && !captured.empty()) {
            const int n = MultiByteToWideChar(CP_ACP, 0, captured.c_str(),
                                              static_cast<int>(captured.size()), nullptr, 0);
            std::wstring wide(static_cast<size_t>(n), L'\0');
            MultiByteToWideChar(CP_ACP, 0, captured.c_str(),
                                static_cast<int>(captured.size()), wide.data(), n);
            *out = std::move(wide);
        }
    }

    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (waitResult == WAIT_TIMEOUT) ? -2 : static_cast<int>(code);
}

}  // namespace Command
