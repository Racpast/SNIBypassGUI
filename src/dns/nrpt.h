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

#pragma once
// The Name Resolution Policy Table: telling Windows which names to resolve here.
//
// The NRPT is the DNS Client service's own routing table. A rule names a set of
// namespaces and the server that answers for them, and the service consults it
// before its ordinary per-adapter servers — so a name it covers is sent where the
// rule says and nowhere else. Every resolver on the machine that goes through the
// system stack obeys it, browsers included.
//
// Two namespace forms exist, and they are exactly the two the rule file offers:
//   ".a.com"   the apex and every subdomain
//   "a.com"    that one host
// There is no exclusion form, and none is emulated here (see dns/rules.h).
//
// This module writes the registry directly rather than shelling out to the
// PowerShell cmdlets that front it. The cmdlets would cost a process launch and a
// module load per call and are absent from some installations; the key layout is
// the actual interface, and it is stable. What is written takes effect within
// about a second, and immediately once the service is told to re-read it.
//
// Everything installed lives under ONE rule with a fixed, well-known key name, so
// removal is exact: there is no enumeration, no matching heuristic, and no way to
// delete a rule the user or their administrator put there. That is what makes
// crash recovery safe — the next start deletes precisely what a previous run could
// have left behind.
#include <string>
#include <vector>

namespace Dns {
namespace Nrpt {

// Install (replacing any previous copy of) the rule that routes `namespaces` to
// `dnsServer`. An empty list installs nothing and removes the rule instead, since
// a rule with no namespace has nothing to route. Returns false if the registry
// could not be written, in which case nothing has been left half-applied.
bool InstallRule(const std::vector<std::string>& namespaces, const std::wstring& dnsServer);

// Remove the rule. Returns true if one was there to remove — which, at startup,
// is exactly the signal that a previous run did not shut down cleanly.
bool RemoveRule();

// ---- The service that enforces all of the above ------------------------------
//
// The policy table is the DNS Client service's own: it is stored under that
// service's Parameters key and applied by it. If the service is not running, an
// installed rule sits in the registry doing nothing — every listed name resolves
// the ordinary way, the local proxy never sees a connection, and not one thing
// about the failure points at DNS. So the state is checked before anything is
// installed, rather than discovered afterwards by a user whose sites all broke.
//
// Windows ships the service as Automatic and does not allow it to be stopped
// (it reports NOT_STOPPABLE), so the only way it is ever found down is that
// something set its start type to Disabled and the machine was restarted — which
// several widely copied "system tuning" guides tell people to do.
//
// Nothing here tries to repair that, and the reason is not squeamishness. Both
// routes were measured and both are dead ends within a running session:
//   * ChangeServiceConfig cannot be reached at all. Dnscache's security descriptor
//     denies SERVICE_CHANGE_CONFIG even to an administrator, and OpenService fails
//     outright when that right is requested.
//   * Writing the start type straight into the registry succeeds, but the service
//     control manager caches the configuration it read at boot, so StartService
//     still refuses with ERROR_SERVICE_DISABLED afterwards.
// Either way the machine has to be restarted, so the honest thing to offer is the
// instruction to restart it — not code that changes service configuration and then
// asks for a restart anyway.

enum class DnsClient {
    Running,      // the normal state, and the only one this program can work in
    Stopped,      // down, but not barred from starting
    Disabled,     // down and barred from starting until its start type changes
    Unavailable,  // the service manager could not be asked
};

DnsClient QueryDnsClient();

}  // namespace Nrpt
}  // namespace Dns
