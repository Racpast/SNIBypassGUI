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

// ---- Reading the rule back ---------------------------------------------------
//
// Each of these answers "is this value present, of this type, and exactly this?" —
// never "close enough". A rule that differs from what we would write is a rule that
// routes somewhere else or covers a different set of names, and both are wrong in
// the way this program exists to prevent.

bool DwordEquals(HKEY key, const wchar_t* name, DWORD expected) {
    DWORD value = 0;
    DWORD size = sizeof(value);
    DWORD type = 0;
    if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE*>(&value), &size) !=
        ERROR_SUCCESS)
        return false;
    return type == REG_DWORD && size == sizeof(value) && value == expected;
}

// Read a string-shaped value as the exact character block stored, terminators
// included. Both REG_SZ and REG_MULTI_SZ are compared this way, so the comparison
// is over the same bytes the writer produced rather than over a re-parse of them.
bool ReadBlock(HKEY key, const wchar_t* name, DWORD wantType, std::wstring& out) {
    DWORD bytes = 0;
    DWORD type = 0;
    if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS)
        return false;
    if (type != wantType || bytes % sizeof(wchar_t) != 0) return false;

    out.assign(bytes / sizeof(wchar_t), L'\0');
    if (out.empty()) return true;
    if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<BYTE*>(out.data()),
                         &bytes) != ERROR_SUCCESS)
        return false;
    return true;
}

// A REG_SZ holding exactly `expected`. The stored block is the characters plus the
// one terminating null the type implies, and a value written by something else may
// carry a different number of them — so the comparison is against what SetSz writes.
bool SzEquals(HKEY key, const wchar_t* name, const std::wstring& expected) {
    std::wstring stored;
    if (!ReadBlock(key, name, REG_SZ, stored)) return false;
    return stored == expected + std::wstring(1, L'\0');
}

bool MultiSzEquals(HKEY key, const wchar_t* name, const std::wstring& expectedBlock) {
    std::wstring stored;
    if (!ReadBlock(key, name, REG_MULTI_SZ, stored)) return false;
    return stored == expectedBlock;
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

bool RuleMatches(const std::vector<std::string>& namespaces, const std::wstring& dnsServer) {
    // Nothing to route means the rule should not be there at all, so its absence is
    // the match and its presence is not.
    HKEY key = nullptr;
    const LSTATUS status =
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, FullRulePath().c_str(), 0, KEY_QUERY_VALUE, &key);
    if (status != ERROR_SUCCESS) return namespaces.empty();
    if (namespaces.empty()) {
        RegCloseKey(key);
        return false;
    }

    const bool same = DwordEquals(key, L"Version", kRuleVersion) &&
                      MultiSzEquals(key, L"Name", PackMultiSz(namespaces)) &&
                      SzEquals(key, L"GenericDNSServers", dnsServer) &&
                      DwordEquals(key, L"ConfigOptions", kConfigGenericDnsServers) &&
                      SzEquals(key, L"Comment", kComment);
    RegCloseKey(key);
    return same;
}

// ---- RuleWatch ---------------------------------------------------------------

RuleWatch::~RuleWatch() {
    if (m_key) RegCloseKey(m_key);
    if (m_event) CloseHandle(m_event);
}

bool RuleWatch::Arm() {
    // The subscription is one-shot, so nothing can signal this event between the
    // notification just consumed and this call — the reset cannot drop anything.
    // Manual-reset all the same, so that a signal arriving while the caller is busy
    // elsewhere is still there when it returns to the wait.
    ResetEvent(m_event);
    const LSTATUS status = RegNotifyChangeKeyValue(
        m_key, TRUE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, m_event, TRUE);
    if (status == ERROR_SUCCESS) return true;
    LOGW(L"NRPT: cannot subscribe to policy-table changes (err " + std::to_wstring(status) +
         L").");
    return false;
}

bool RuleWatch::Open() {
    // Created once and kept: Rearm may come back through here to replace a key that
    // was deleted underneath us, and a waiter that has this handle in a wait array
    // must not have it swapped out from under the wait.
    if (!m_event) {
        m_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!m_event) {
            LOGW(L"NRPT: cannot create the policy-table watch event (err " +
                 std::to_wstring(GetLastError()) + L").");
            return false;
        }
    }
    if (m_key) {
        RegCloseKey(m_key);
        m_key = nullptr;
    }

    // Created rather than merely opened: a machine that has never held an NRPT rule
    // has no policy table to subscribe to, and the key we would be told about is the
    // one we are about to write. Creating it is what makes the watch work from the
    // first start rather than from the second.
    const LSTATUS status =
        RegCreateKeyExW(HKEY_LOCAL_MACHINE, kPolicyKey, 0, nullptr, REG_OPTION_NON_VOLATILE,
                        KEY_NOTIFY, nullptr, &m_key, nullptr);
    if (status != ERROR_SUCCESS) {
        LOGW(L"NRPT: cannot open the policy table for watching (err " +
             std::to_wstring(status) + L").");
        m_key = nullptr;
        return false;
    }
    return Arm();
}

bool RuleWatch::Rearm() {
    if (!m_key || !m_event) return false;
    if (Arm()) return true;

    // Deleting the policy table itself invalidates this key, and every later
    // subscription on it fails. Reopening is the whole recovery — it creates the
    // table again and subscribes to the new one.
    LOGW(L"NRPT: the policy table went away; reopening the watch.");
    return Open();
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
