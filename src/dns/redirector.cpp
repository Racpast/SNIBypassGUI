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

#include "dns/redirector.h"

#include <utility>
#include <vector>

#include "app/logging.h"
#include "dns/file_watcher.h"
#include "dns/nrpt.h"

namespace Dns {

Redirector::Redirector() : m_rules(std::make_shared<const RuleSet>()) {}

Redirector::~Redirector() {
    Stop();
}

std::shared_ptr<const RuleSet> Redirector::Rules() const {
    std::lock_guard<std::mutex> lock(m_mx);
    return m_rules;
}

size_t Redirector::RuleCount() const {
    return Rules()->RuleCount();
}

size_t Redirector::LoadRules(const std::wstring& path) {
    size_t loaded = 0;
    std::shared_ptr<const RuleSet> rules = LoadRuleFile(path, L"hosts", loaded);
    if (!rules) {
        LOGE(L"Cannot read the DNS rule file: " + path);
        return 0;
    }
    Apply(std::move(rules));
    return loaded;
}

void Redirector::Apply(std::shared_ptr<const RuleSet> rules) {
    const std::vector<std::string> namespaces = rules->Namespaces();
    {
        std::lock_guard<std::mutex> lock(m_mx);
        m_rules = rules;
    }

    // The resolver learns the rules before the policy table is told to send names
    // to it. The other order has a window in which Windows routes a name here and
    // the answer comes from the rule set being replaced.
    m_resolver.Publish(std::move(rules));

    // Reinstalled unconditionally rather than only when the namespace list has
    // changed. Writing what the table should say — instead of trusting a memory of
    // what it was last told — is what makes a reload repair a rule that something
    // else removed, and it costs a registry write on a file the user just saved.
    if (m_resolver.Running()) Nrpt::InstallRule(namespaces, kResolverAddress);
}

bool Redirector::Start() {
    // A rule set that names nothing is not a failure. The file may simply have no
    // rules in it yet, and nothing about the machine is wrong — so this is something
    // to say out loud, not a reason to refuse.
    //
    // The server is started regardless, and that is the point. With no namespace
    // installed nothing is routed to it, so it sits idle — but it IS running, which
    // is what lets a later edit to the rule file bring redirection up through the
    // ordinary hot-reload path. Refusing to start would leave a reload with nothing
    // to publish to, and the user would have to restart the stack by hand to be heard.
    const std::vector<std::string> namespaces = Rules()->Namespaces();
    if (namespaces.empty())
        LOGW(
            L"No DNS rules are loaded, so no domain is redirected yet; the local DNS "
            L"server is starting anyway and will pick the file up when it changes.");

    // Nothing is routed anywhere until there is something listening to route to.
    if (!m_resolver.Start()) return false;

    // An empty list installs no rule and removes any earlier one, which is exactly
    // right: there is nothing to route.
    if (!Nrpt::InstallRule(namespaces, kResolverAddress)) {
        m_resolver.Stop();
        return false;
    }
    return true;
}

void Redirector::Stop() {
    // The watcher belongs to the session, not to this object's lifetime: left for
    // the destructor, its thread would outlive every caller's idea of "stopped".
    DisableHotReload();

    // Names stop being sent here before the server that answers them goes away, so
    // no query is ever routed to a port that has just closed.
    Nrpt::RemoveRule();
    m_resolver.Stop();
}

void Redirector::EnableHotReload(const std::wstring& path, unsigned debounceMs) {
    if (m_watcher && m_rulesPath == path) return;
    DisableHotReload();
    m_rulesPath = path;

    m_watcher = std::make_unique<FileWatcher>(
        path,
        [this, path] {
            LOGI(L"Hot-reload: reloading DNS rules from " + path);
            size_t loaded = 0;
            std::shared_ptr<const RuleSet> rules = LoadRuleFile(path, L"Hot-reload", loaded);
            if (!rules) {
                LOGE(L"Hot-reload: cannot open " + path);
                return;
            }
            Apply(std::move(rules));
            LOGI(L"Hot-reload: loaded " + std::to_wstring(loaded) + L" rule(s).");
        },
        debounceMs);

    m_watcher->Start();
}

void Redirector::DisableHotReload() {
    if (m_watcher) {
        m_watcher->Stop();
        m_watcher.reset();
    }
    m_rulesPath.clear();
}

}  // namespace Dns
