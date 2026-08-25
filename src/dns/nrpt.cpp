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

#include "dns/nrpt.h"

#include <windows.h>

#include <cstdint>
#include <vector>

#include "app/logging.h"
#include "app/text.h"

namespace Dns {
namespace Nrpt {
namespace {

// The DNS Client service's local policy table. This is the one the PowerShell
// cmdlets write; the Group Policy table lives elsewhere and belongs to the
// administrator, so it is never touched.
constexpr wchar_t kPolicyKey[] =
    L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig";

// Our single rule, under a fixed key name so that removing it needs no search.
// The name is a GUID because every other producer of these rules uses one and the
// service has never been asked to accept anything else; it is arbitrary, constant,
// and ours. `Comment` is what identifies the rule to a human reading the registry
// or the output of Get-DnsClientNrptRule.
constexpr wchar_t kRuleKey[] = L"{7A9C4E31-2D6B-4F58-A1E0-8C3D5B04F926}";
constexpr wchar_t kComment[] =
    L"SNIBypassGUI - removed automatically when it stops; safe to delete";

// Rule schema version. Version 2 is what current Windows writes and reads.
constexpr DWORD kRuleVersion = 2;

// ConfigOptions is a bitmask of which optional parts of the rule are present.
// Bit 3 declares the GenericDNSServers field, which is the only part used here:
// no DNSSEC requirement, no IPsec restriction, no DirectAccess.
constexpr DWORD kConfigGenericDnsServers = 0x8;

// The DNS Client service, which owns the policy table and applies it.
constexpr wchar_t kServiceName[] = L"Dnscache";

std::wstring FullRulePath() {
    return std::wstring(kPolicyKey) + L"\\" + kRuleKey;
}

// The service's configured start type, or SERVICE_AUTO_START if it cannot be read
// — the benign assumption, since it only ever decides whether to report the
// service as merely stopped or as barred from starting.
DWORD StartType(SC_HANDLE service) {
    DWORD needed = 0;
    QueryServiceConfigW(service, nullptr, 0, &needed);
    if (needed == 0) return SERVICE_AUTO_START;
    std::vector<uint8_t> buffer(needed);
    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
    if (!QueryServiceConfigW(service, config, needed, &needed)) return SERVICE_AUTO_START;
    return config->dwStartType;
}

// Tell the DNS Client service to re-read its parameters.
//
// The table is picked up on its own within about a second either way; this makes
// the change effective at once, so the first query after a start is not answered
// from the world as it was before the rule existed.
void NotifyDnsCache() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        LOGW(L"NRPT: cannot reach the service manager (err " + std::to_wstring(GetLastError()) +
             L"); the rule will apply shortly anyway.");
        return;
    }
    // SERVICE_CONTROL_PARAMCHANGE is dispatched under the pause/continue right.
    SC_HANDLE dnscache = OpenServiceW(scm, kServiceName, SERVICE_PAUSE_CONTINUE);
    if (dnscache) {
        SERVICE_STATUS status = {};
        if (!ControlService(dnscache, SERVICE_CONTROL_PARAMCHANGE, &status))
            LOGW(L"NRPT: Dnscache did not accept PARAMCHANGE (err " +
                 std::to_wstring(GetLastError()) + L").");
        CloseServiceHandle(dnscache);
    } else {
        LOGW(L"NRPT: cannot open the Dnscache service (err " + std::to_wstring(GetLastError()) +
             L").");
    }
    CloseServiceHandle(scm);
}

// Pack UTF-8 namespaces into the double-null-terminated block REG_MULTI_SZ wants:
// each item followed by its own null, then one more to close the block. The result
// is the complete on-disk representation, terminator included, so its size() is
// exactly what gets written.
std::wstring PackMultiSz(const std::vector<std::string>& items) {
    std::wstring packed;
    for (const std::string& item : items) {
        packed += Utf8ToWide(item);
        packed.push_back(L'\0');
    }
    packed.push_back(L'\0');  // the terminator for the block itself
    return packed;
}

// A REG_SZ value: the characters plus the one terminating null the type implies.
bool SetSz(HKEY key, const wchar_t* name, const std::wstring& value) {
    const DWORD bytes = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
    return RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()),
                          bytes) == ERROR_SUCCESS;
}

// A REG_MULTI_SZ value. The length is the block's own size and nothing more:
// PackMultiSz has already appended both terminators, so adding another character's
// worth — as a helper shared with REG_SZ did — stores a third null past the end of
// the list. Harmless to most readers, but it is not what the type says.
bool SetMultiSz(HKEY key, const wchar_t* name, const std::wstring& block) {
    const DWORD bytes = static_cast<DWORD>(block.size() * sizeof(wchar_t));
    return RegSetValueExW(key, name, 0, REG_MULTI_SZ,
                          reinterpret_cast<const BYTE*>(block.data()), bytes) == ERROR_SUCCESS;
}

bool SetDword(HKEY key, const wchar_t* name, DWORD value) {
    return RegSetValueExW(key, name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value),
                          sizeof(value)) == ERROR_SUCCESS;
}

}  // namespace

bool InstallRule(const std::vector<std::string>& namespaces, const std::wstring& dnsServer) {
    if (namespaces.empty()) {
        LOGW(L"NRPT: no namespaces to route; not installing a rule.");
        RemoveRule();
        return true;
    }

    // Written into a key that is created fresh, so a rule left by an older run
    // cannot contribute a stale namespace list or a stale server to this one.
    RemoveRule();

    HKEY key = nullptr;
    LSTATUS status =
        RegCreateKeyExW(HKEY_LOCAL_MACHINE, FullRulePath().c_str(), 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &key, nullptr);
    if (status != ERROR_SUCCESS) {
        LOGE(L"NRPT: cannot create the rule key (err " + std::to_wstring(status) + L").");
        return false;
    }

    const bool ok = SetDword(key, L"Version", kRuleVersion) &&
                    SetMultiSz(key, L"Name", PackMultiSz(namespaces)) &&
                    SetSz(key, L"GenericDNSServers", dnsServer) &&
                    SetDword(key, L"ConfigOptions", kConfigGenericDnsServers) &&
                    SetSz(key, L"Comment", kComment);
    RegCloseKey(key);

    if (!ok) {
        // A partially written rule is worse than none: the service could route
        // names to a server field that was never stored. Take it back out.
        LOGE(L"NRPT: cannot write the rule's values (err " + std::to_wstring(GetLastError()) +
             L").");
        RemoveRule();
        return false;
    }

    NotifyDnsCache();
    LOGI(L"NRPT: routing " + std::to_wstring(namespaces.size()) + L" namespace(s) to " +
         dnsServer + L".");
    return true;
}

bool RemoveRule() {
    const LSTATUS status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, FullRulePath().c_str());
    if (status == ERROR_FILE_NOT_FOUND) return false;  // nothing was there
    if (status != ERROR_SUCCESS) {
        LOGE(L"NRPT: cannot remove the rule (err " + std::to_wstring(status) +
             L"); redirected domains may keep resolving to the local server.");
        return false;
    }
    NotifyDnsCache();
    LOGI(L"NRPT: rule removed.");
    return true;
}

// ---- The service that enforces all of the above ------------------------------

DnsClient QueryDnsClient() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        LOGW(L"NRPT: cannot reach the service manager to check the DNS Client (err " +
             std::to_wstring(GetLastError()) + L").");
        return DnsClient::Unavailable;
    }
    SC_HANDLE service =
        OpenServiceW(scm, kServiceName, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!service) {
        LOGW(L"NRPT: cannot open the DNS Client service (err " +
             std::to_wstring(GetLastError()) + L").");
        CloseServiceHandle(scm);
        return DnsClient::Unavailable;
    }

    SERVICE_STATUS status = {};
    const bool haveStatus = QueryServiceStatus(service, &status) != FALSE;
    const DWORD startType = StartType(service);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    if (!haveStatus) return DnsClient::Unavailable;

    if (status.dwCurrentState == SERVICE_RUNNING) {
        // Disabling a running service does not stop it, so this machine works now
        // and silently stops working at the next sign-in. Saying so here is the
        // only chance anyone gets to connect the two events.
        if (startType == SERVICE_DISABLED)
            LOGW(
                L"The DNS Client service is running but its start type is Disabled; "
                L"DNS redirection will stop working after the next restart.");
        return DnsClient::Running;
    }
    return (startType == SERVICE_DISABLED) ? DnsClient::Disabled : DnsClient::Stopped;
}

}  // namespace Nrpt
}  // namespace Dns
