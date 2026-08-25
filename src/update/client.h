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
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

// Update endpoints. Chunk URLs in the manifest are relative to the manifest's own
// directory, so the whole tree can be rehosted under any prefix without editing it.
#define UPDATE_MANIFEST_URL L"https://update.rpnet.cc/snibypassgui/manifest.json"
#define UPDATE_MANIFEST_SIG_URL UPDATE_MANIFEST_URL L".sig"

// Every updatable file — the executable and every data asset — is delivered as a
// list of content-addressed chunks, each small enough for the per-file host limit.
// The manifest describing them is signed with ECDSA P-256/SHA-256 and verified
// against the public key compiled into this binary, so integrity does not depend
// on TLS or on the host being uncompromised.
namespace Update {

struct Chunk {
    std::wstring name;  // path relative to the manifest's directory
    uint64_t size = 0;
    std::wstring sha256;  // lowercase hex
};

struct File {
    std::wstring path;  // install path relative to the program directory
    bool isExe = false;
    uint64_t size = 0;
    std::wstring sha256;  // lowercase hex of the whole file
    std::vector<Chunk> chunks;
};

struct Info {
    bool ok = false;
    std::wstring error;  // populated when ok == false
    std::wstring version;
    std::wstring released;
    std::wstring notes;  // release notes for the current language
    uint64_t chunkSize = 0;
    bool reinstallRequired = false;  // we predate min_upgradable_from
    std::vector<File> files;
};

// Fetch manifest.json and manifest.json.sig, verify the signature over the exact
// manifest bytes, then parse. Info.ok is false on any network, parse, signature or
// policy failure, with Info.error set to a localized reason.
Info FetchManifest();

// True if any manifest file differs from what is installed. `summary` gets one
// line per file that would change.
bool UpdateAvailable(const Info& info, std::wstring& summary);

// Optional progress hooks. Every callback fires on the thread that called
// PerformUpdate and may be left empty.
struct Progress {
    // Fired as each changed file BEGINS transferring: `done` is its 1-based index
    // among the `total` files that will change. Runs while the services are still
    // up — the download only writes <path>.new and never touches the live install.
    std::function<void(size_t done, size_t total, const std::wstring& path)> onFile;

    // Fired ONCE after every file is downloaded and verified, immediately before
    // the first byte of the live install is replaced. This is where the caller
    // stops the services: deferring the stop to here keeps the proxy up for the
    // whole download and only drops it for the seconds the apply takes. It never
    // fires if the download fails, so a mid-download failure leaves the services
    // untouched.
    std::function<void()> onBeforeApply;
};

// Download and verify every changed file into <path>.new, then apply them all at
// once: assets are moved into place keeping a .bak, and the running executable is
// swapped by a wait-and-relaunch helper. Any failure before the apply leaves the
// install untouched; a failure during it rolls back from the .bak copies.
//
// Returns true if an executable swap was scheduled and the caller must exit.
bool PerformUpdate(const Info& info, const Progress& progress = {});

// Lowercase hex SHA-256 of a file. Empty on failure.
std::wstring Sha256File(const std::wstring& path);

// ---- Pure helpers (no I/O; exposed for unit testing) ------------------------

// The directory part of `url`, including the trailing '/'.
std::wstring UrlBaseDir(const std::wstring& url);

// Numeric-aware dot-separated version compare (tolerates a leading 'v'/'V' and
// ignores per-component suffixes). Returns <0, 0, >0 like strcmp. Drives both the
// executable-update decision and the min_upgradable_from floor. The executable
// updates whenever manifest.version != APP_VERSION_NUM (INEQUALITY, not ">"), so
// the client follows the channel DOWN as well as up — a force-aligned downgrade is
// a normal update. Only the strict-numeric APP_VERSION_NUM is ever passed here.
int CompareVersions(const std::wstring& a, const std::wstring& b);

// True if `s` is a 64-character lowercase hex SHA-256 digest.
bool IsHexDigest(const std::wstring& s);

}  // namespace Update
