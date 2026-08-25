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
namespace {

// Decode captured console output.
//
// UTF-8 is tried strictly: without MB_ERR_INVALID_CHARS, MultiByteToWideChar
// happily turns arbitrary bytes into U+FFFD and reports success, so a console that
// answered in the machine's ANSI code page would decode to a non-empty string of
// replacement characters and the fallback below would never run. Strict decoding is
// what makes "is this actually UTF-8?" a question with an answer.
std::wstring DecodeConsoleOutput(const std::string& bytes) {
    if (bytes.empty()) return {};

    const int size = static_cast<int>(bytes.size());
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), size, nullptr, 0);
    if (n > 0) {
        std::wstring wide(static_cast<size_t>(n), L'\0');
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), size, wide.data(), n);
        return wide;
    }

    n = MultiByteToWideChar(CP_ACP, 0, bytes.data(), size, nullptr, 0);
    if (n <= 0) return {};
    std::wstring wide(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_ACP, 0, bytes.data(), size, wide.data(), n);
    return wide;
}

// The user's temp directory, with a trailing backslash.
//
// Resolved through the wide API: the ANSI environment would mis-decode a non-ASCII
// profile path, and the scripts written here carry install paths that have to
// survive verbatim.
std::wstring TempDir() {
    wchar_t buf[MAX_PATH + 1] = {};
    const DWORD n = GetTempPathW(MAX_PATH + 1, buf);
    std::wstring dir = (n > 0 && n <= MAX_PATH) ? std::wstring(buf) : L"C:\\Windows\\Temp\\";
    if (!dir.empty() && dir.back() != L'\\') dir.push_back(L'\\');
    return dir;
}

}  // namespace

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

    if (out) *out = DecodeConsoleOutput(captured);

    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (waitResult == WAIT_TIMEOUT) ? -2 : static_cast<int>(code);
}

bool RunDetachedScript(const std::wstring& scriptName, const std::wstring& body) {
    std::wstring script;
    script += L"@echo off\r\n";
    script += L"chcp 65001 >nul\r\n";
    script += body;

    const std::wstring dir = TempDir();
    const std::wstring scriptPath = dir + scriptName;

    HANDLE file = CreateFileW(scriptPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        LOGE(L"Cannot write the helper script " + scriptPath + L" (err " +
             std::to_wstring(GetLastError()) + L").");
        return false;
    }
    const std::string utf8 = WideToUtf8(script);
    DWORD written = 0;
    const bool wrote =
        WriteFile(file, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr) &&
        written == utf8.size();
    CloseHandle(file);
    if (!wrote) {
        LOGE(L"Incomplete write of the helper script " + scriptPath + L".");
        return false;
    }

    // No job object: this helper exists to act after we are gone, so tying its
    // lifetime to ours would defeat it. It runs from the temp directory, so neither
    // it nor anything it starts holds a folder inside the install tree open.
    return static_cast<bool>(Process::LaunchDetached(L"C:\\Windows\\System32\\cmd.exe",
                                                     L"/c \"" + scriptPath + L"\"", dir, true));
}

}  // namespace Command
