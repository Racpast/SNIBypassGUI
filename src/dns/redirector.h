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
// DNS redirection, whole: the rules, the policy table that routes names here, and
// the server that answers them.
//
// The two mechanisms are one feature and are owned together, because they are only
// ever correct together. A policy rule pointing at a resolver that is not listening
// breaks every name it covers; a resolver holding rules the policy table has not
// been told about answers nothing. So they are brought up in the order that is safe
// to be interrupted in — resolver first, policy table second — taken down in the
// reverse one, and a hot-reload updates both from the same parse of the file.
//
// The rule set is owned here rather than by the resolver. The resolver needs
// something to match against; which names are redirected, and how many, is a question
// about the file this class read.
//
// Nothing is left behind by a clean stop. What an unclean one leaves is a single
// registry key with a fixed name, which the next start removes before it does
// anything else (see Services::EnforceCleanSlate).
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>

#include "dns/resolver.h"

namespace Dns {

class FileWatcher;

class Redirector {
public:
    Redirector();
    ~Redirector();
    Redirector(const Redirector&) = delete;
    Redirector& operator=(const Redirector&) = delete;

    // Read `path` and hold the result as the rules to start with. Returns how many
    // rules were loaded; zero means the file was missing or said nothing.
    size_t LoadRules(const std::wstring& path);

    size_t RuleCount() const;

    // Start the local server, then route every namespace the rules name to it.
    // Returns false having undone whatever it managed to do.
    //
    // A rule set that names nothing still starts the server. Nothing is routed to it,
    // so it sits idle, but a later edit to the rule file can then bring redirection up
    // through the hot-reload path rather than needing the stack restarted.
    bool Start();

    // Stop names being sent here, then stop answering.
    void Stop();

    // Watch `path` and re-apply it when it changes, debounced to absorb editors
    // that write in chunks. A reload republishes the rules and rewrites the policy
    // table from the same parse. Safe to call before or after Start().
    void EnableHotReload(const std::wstring& path, unsigned debounceMs = 500);
    void DisableHotReload();

    bool Running() const { return m_resolver.Running(); }

private:
    // Adopt `rules`: publish them to the resolver and, when running, bring the
    // policy table in line with them.
    void Apply(std::shared_ptr<const RuleSet> rules);

    std::shared_ptr<const RuleSet> Rules() const;

    // Guards the rule pointer alone. A hot-reload replaces it from the watcher's
    // thread while a start or a status query reads it from another.
    mutable std::mutex m_mx;
    std::shared_ptr<const RuleSet> m_rules;

    LocalResolver m_resolver;
    std::unique_ptr<FileWatcher> m_watcher;
    std::wstring m_rulesPath;  // path being monitored
};

}  // namespace Dns
