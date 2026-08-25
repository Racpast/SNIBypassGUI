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

#include "update/http.h"

#include <windows.h>

#include <wininet.h>

#include "app/version.h"

namespace Http {

bool Get(const std::wstring& url, std::string& out) {
    out.clear();

    HINTERNET session = InternetOpenW(APP_NAME L"/" APP_VERSION_NUM,
                                      INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!session) return false;

    const DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE |
                        INTERNET_FLAG_SECURE | INTERNET_FLAG_PRAGMA_NOCACHE;
    HINTERNET request = InternetOpenUrlW(session, url.c_str(), nullptr, 0, flags, 0);
    if (!request) {
        InternetCloseHandle(session);
        return false;
    }

    DWORD status = 0;
    DWORD statusLen = sizeof(status);
    const bool gotStatus =
        HttpQueryInfoW(request, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &status,
                       &statusLen, nullptr) == TRUE;
    // Accept only an explicit 2xx. If the status could not be read at all (e.g. a
    // non-HTTP handler), fall back to trusting the body, but never treat an
    // unknown or zero status as success on its own.
    const bool statusOk = gotStatus ? (status >= 200 && status < 300) : true;

    bool readOk = true;
    if (statusOk) {
        char buf[16384];
        DWORD n = 0;
        for (;;) {
            if (!InternetReadFile(request, buf, sizeof(buf), &n)) {
                readOk = false;
                break;
            }
            if (n == 0) break;  // clean end of stream
            out.append(buf, n);
        }
    }

    InternetCloseHandle(request);
    InternetCloseHandle(session);
    return statusOk && readOk;
}

}  // namespace Http
