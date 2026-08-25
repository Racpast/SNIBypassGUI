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

#include "update/client.h"

#include <windows.h>

#include <fstream>
#include <map>
#include <set>
#include <utility>

#include "app/filesystem.h"
#include "app/i18n.h"
#include "app/logging.h"
#include "app/paths.h"
#include "app/services.h"
#include "app/text.h"
#include "app/version.h"
#include "platform/command.h"
#include "platform/process.h"
#include "update/crypto.h"
#include "update/http.h"
#include "update/json.h"

namespace Update {
namespace {

bool FileExists(const std::wstring& p) {
    const DWORD attr = GetFileAttributesW(p.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

// Normalize a manifest path to backslashes for use on disk.
std::wstring ToNative(std::wstring p) {
    for (wchar_t& c : p)
        if (c == L'/') c = L'\\';
    return p;
}

// Absolute install path for a manifest entry. The executable is matched to
// wherever we actually run from, so a renamed executable still updates in place.
std::wstring InstallPath(const File& f) {
    return f.isExe ? ExePath() : PathUnder(f.path);
}

// Whether a file entry should be (re)downloaded.
//
// The executable is decided ONLY by the numeric version, and by INEQUALITY rather
// than "greater than": the remote build simply differs from what we run. That
// makes a DOWNGRADE a first-class operation — when the release channel is
// force-aligned to an older version, every newer client steps DOWN to what the
// channel currently serves. A too-old install that cannot step forward is gated
// separately by the min_upgradable_from floor.
//
// We deliberately do NOT compare the executable's SHA: data no longer lives inside
// it, so its hash is a pure function of source and would force spurious
// re-downloads on byte-different builds. The manifest SHA is still verified AFTER
// download, so it remains an integrity check; it just never triggers the update.
//
// Data assets are decided by content: local SHA differs from the manifest SHA, or
// the file is missing. Because the comparison is local-versus-manifest, a file the
// user hand-edited is restored to canonical on the next update even if the remote
// copy is unchanged — updates fully own the payload tree.
bool NeedsUpdate(const File& f, const Info& info) {
    if (f.isExe) return CompareVersions(info.version, APP_VERSION_NUM) != 0;

    const std::wstring full = InstallPath(f);
    if (!FileExists(full)) return true;
    const std::wstring local = Sha256File(full);
    return local.empty() || local != f.sha256;
}

// Fetch every chunk of `f`, verifying each, and write the reassembled file to
// `dest`. The whole-file hash is checked before returning success, so a true result
// means `dest` is byte-for-byte what the signed manifest promised.
//
// On failure, `stale` separates two very different situations:
//   stale == true   the REMOTE tree disagreed with the manifest we hold: a chunk
//                   404'd, or a chunk / the reassembled file failed its hash. Most
//                   likely a publish landed between our manifest fetch and now, so
//                   the manifest is worth re-fetching and the download retried.
//   stale == false  a LOCAL problem (cannot create, write or flush the staging
//                   file, or the hash engine is unavailable). Re-fetching would not
//                   help; the caller should give up.
bool DownloadFile(const File& f, const std::wstring& base, const std::wstring& dest,
                  std::wstring& err, bool& stale) {
    stale = false;

    // Ensure the parent directory exists.
    const size_t slash = dest.find_last_of(L"\\/");
    if (slash != std::wstring::npos) {
        FileSystem::EnsureDirectory(dest.substr(0, slash));
    }

    Crypto::Sha256 whole;
    if (!whole.valid()) {
        err = T(L"msg.updHashFail");
        return false;
    }

    {
        std::ofstream out(dest.c_str(), std::ios::binary | std::ios::trunc);
        if (!out) {
            LOGE(L"Update: cannot create " + dest);
            err = T(L"msg.updWriteFail");
            return false;
        }
        size_t index = 0;
        for (const Chunk& c : f.chunks) {
            ++index;
            const std::wstring url = base + c.name;
            std::string data;
            if (!Http::Get(url, data)) {
                LOGE(L"Update: chunk download failed: " + url);
                err = std::wstring(T(L"msg.updChunkDlFail")) + L"\n" + f.path;
                stale = true;  // remote content moved, or a transient network fault
                return false;
            }
            // Per-chunk verification happens BEFORE the bytes are appended.
            if (static_cast<uint64_t>(data.size()) != c.size ||
                Crypto::Sha256Hex(data.data(), data.size()) != c.sha256) {
                LOGE(L"Update: chunk hash/size mismatch for " + f.path + L" chunk " +
                     std::to_wstring(index));
                err = std::wstring(T(L"msg.updChunkHash")) + L"\n" + f.path;
                stale = true;  // a URL we resolved now serves different bytes
                return false;
            }
            whole.Add(data.data(), data.size());
            out.write(data.data(), static_cast<std::streamsize>(data.size()));
            if (!out) {
                LOGE(L"Update: write failed while staging " + dest);
                err = T(L"msg.updWriteFail");
                return false;
            }
        }
        out.flush();
        if (!out) {
            LOGE(L"Update: flush failed while staging " + dest);
            err = T(L"msg.updWriteFail");
            return false;
        }
    }

    if (whole.Hex() != f.sha256) {
        LOGE(L"Update: reassembled file failed verification: " + f.path);
        err = std::wstring(T(L"msg.updFileHash")) + L"\n" + f.path;
        stale = true;  // chunks each verified but the file record no longer matches
        return false;
    }
    LOGI(L"Update: staged and verified " + f.path);
    return true;
}

struct Staged {
    const File* file = nullptr;
    std::wstring target;  // final install path
    std::wstring tmp;     // <target>.new
    std::wstring bak;     // <target>.bak (assets only)
    bool movedBak = false;
    bool applied = false;
};

// Outcome of one download pass over a manifest.
enum class DownloadResult {
    Ok,     // every changed file staged and verified
    Stale,  // remote disagreed with the manifest — re-fetch and retry
    Hard,   // local error a retry cannot fix (disk, write, hash engine)
};

// Download every file `info` says needs changing into <target>.new, verifying each,
// and record the resulting Staged list. Content-addressed reuse across retries:
// `verified` maps target to the SHA already staged there this run, so a file whose
// bytes are unchanged between manifest versions is NOT re-downloaded. Every .new
// path touched is recorded in `allNew` so the caller can clean up after a failure
// regardless of which pass created it.
DownloadResult DownloadPhase(const Info& info, std::vector<Staged>& staged,
                             std::map<std::wstring, std::wstring>& verified,
                             std::set<std::wstring>& allNew, const Progress& progress,
                             std::wstring& err) {
    const std::wstring base = UrlBaseDir(UPDATE_MANIFEST_URL);

    // Resolve the work list up front so progress can report a real "done / total".
    // A reused-from-a-prior-pass file still counts as one step, so the reported
    // total stays stable across a stale retry.
    std::vector<const File*> todo;
    for (const File& f : info.files)
        if (NeedsUpdate(f, info)) todo.push_back(&f);

    size_t done = 0;
    for (const File* fp : todo) {
        const File& f = *fp;
        ++done;
        if (progress.onFile) progress.onFile(done, todo.size(), f.path);

        Staged s;
        s.file = &f;
        s.target = InstallPath(f);
        s.tmp = s.target + L".new";
        s.bak = s.target + L".bak";
        allNew.insert(s.tmp);

        // An earlier pass may already have staged and verified this exact content.
        auto it = verified.find(s.target);
        if (it != verified.end() && it->second == f.sha256 && FileExists(s.tmp)) {
            LOGI(L"Update: reusing already-staged " + f.path);
            staged.push_back(std::move(s));
            continue;
        }

        bool stale = false;
        if (!DownloadFile(f, base, s.tmp, err, stale))
            return stale ? DownloadResult::Stale : DownloadResult::Hard;
        verified[s.target] = f.sha256;
        staged.push_back(std::move(s));
    }
    return DownloadResult::Ok;
}

// The commands of the wait-and-relaunch helper that replaces the running executable
// after we exit. Crash-safe: the current executable is preserved as .bak first, and
// if the swap fails the backup is restored, so the install is never left without a
// working executable.
//
// `args` is what this process was started with, and it is handed back to the copy
// that replaces us because the relaunch continues this session rather than beginning
// a new one. A logon start carries -autostart, which is what tells the program to
// bring the service stack up and to leave the desktop shortcut alone; dropping it
// would bring the tray back with nothing running and a shortcut prompt in front of
// someone who only agreed to an update.
std::wstring BuildSelfUpdateScript(const std::wstring& self, const std::wstring& newExe,
                                   const std::wstring& bak, const std::wstring& args) {
    std::wstring s;
    s += L"set \"SELF=" + self + L"\"\r\n";
    s += L"set \"NEW=" + newExe + L"\"\r\n";
    s += L"set \"BAK=" + bak + L"\"\r\n";
    s += L"set \"ARGS=" + args + L"\"\r\n";
    s += L"del \"%BAK%\" >nul 2>&1\r\n";
    s += L"set /a TRIES=0\r\n";
    s += L":wait\r\n";
    s += L"ping 127.0.0.1 -n 2 >nul\r\n";
    // Retry until the old process has exited and released the image.
    s += L"move /Y \"%SELF%\" \"%BAK%\" >nul 2>&1\r\n";
    s += L"if not exist \"%SELF%\" goto swap\r\n";
    s += L"set /a TRIES+=1\r\n";
    s += L"if %TRIES% LSS 60 goto wait\r\n";
    // Never took the lock: leave the install exactly as it was.
    s += L"del \"%NEW%\" >nul 2>&1\r\n";
    s += L"start \"\" \"%SELF%\" %ARGS%\r\n";
    s += L"goto done\r\n";
    s += L":swap\r\n";
    s += L"move /Y \"%NEW%\" \"%SELF%\" >nul 2>&1\r\n";
    s += L"if exist \"%SELF%\" (\r\n";
    s += L"  del \"%BAK%\" >nul 2>&1\r\n";
    s += L") else (\r\n";
    s += L"  move /Y \"%BAK%\" \"%SELF%\" >nul 2>&1\r\n";
    s += L")\r\n";
    s += L"start \"\" \"%SELF%\" %ARGS%\r\n";
    s += L":done\r\n";
    s += L"(goto) 2>nul & del \"%~f0\"\r\n";
    return s;
}

void ReportFailure(const std::wstring& message) {
    MessageBoxW(nullptr, message.c_str(), APP_NAME, MB_ICONERROR);
}

}  // namespace

std::wstring UrlBaseDir(const std::wstring& url) {
    const size_t query = url.find_first_of(L"?#");
    const std::wstring clean = (query == std::wstring::npos) ? url : url.substr(0, query);
    const size_t slash = clean.find_last_of(L'/');
    if (slash == std::wstring::npos) return clean + L"/";
    return clean.substr(0, slash + 1);
}

int CompareVersions(const std::wstring& a, const std::wstring& b) {
    const auto components = [](const std::wstring& s) {
        std::vector<unsigned long> out;
        size_t i = 0;
        if (i < s.size() && (s[i] == L'v' || s[i] == L'V')) ++i;
        unsigned long current = 0;
        bool hasDigits = false;
        for (; i <= s.size(); ++i) {
            if (i == s.size() || s[i] == L'.') {
                out.push_back(hasDigits ? current : 0);
                current = 0;
                hasDigits = false;
                if (i == s.size()) break;
            } else if (s[i] >= L'0' && s[i] <= L'9') {
                if (current < 100000000UL)
                    current = current * 10 + static_cast<unsigned long>(s[i] - L'0');
                hasDigits = true;
            }
            // Any other character (e.g. "-rc1") is ignored for ordering.
        }
        return out;
    };

    const std::vector<unsigned long> pa = components(a);
    const std::vector<unsigned long> pb = components(b);
    const size_t n = pa.size() > pb.size() ? pa.size() : pb.size();
    for (size_t i = 0; i < n; ++i) {
        const unsigned long x = i < pa.size() ? pa[i] : 0;
        const unsigned long y = i < pb.size() ? pb[i] : 0;
        if (x != y) return x < y ? -1 : 1;
    }
    return 0;
}

bool IsHexDigest(const std::wstring& s) {
    if (s.size() != 64) return false;
    for (wchar_t c : s)
        if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'))) return false;
    return true;
}

std::wstring Sha256File(const std::wstring& path) {
    std::ifstream in(path.c_str(), std::ios::binary);
    if (!in) return L"";
    Crypto::Sha256 hash;
    if (!hash.valid()) return L"";
    std::vector<char> buf(65536);
    while (in) {
        in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize got = in.gcount();
        if (got > 0) hash.Add(buf.data(), static_cast<size_t>(got));
    }
    if (in.bad()) return L"";
    return hash.Hex();
}

Info FetchManifest() {
    Info info;

    std::string manifestRaw;
    if (!Http::Get(UPDATE_MANIFEST_URL, manifestRaw) || manifestRaw.empty()) {
        LOGE(L"Update: failed to download the manifest.");
        info.error = T(L"msg.updFail");
        return info;
    }
    std::string signatureBase64;
    if (!Http::Get(UPDATE_MANIFEST_SIG_URL, signatureBase64) || signatureBase64.empty()) {
        LOGE(L"Update: failed to download the manifest signature.");
        info.error = T(L"msg.updFail");
        return info;
    }

    // Signature first — do not parse anything until the bytes are trusted.
    std::vector<uint8_t> signature;
    if (!Crypto::Base64Decode(signatureBase64, signature) ||
        !Crypto::VerifySignature(manifestRaw, signature)) {
        LOGE(L"Update: manifest signature verification FAILED — refusing to continue.");
        info.error = T(L"msg.updSigFail");
        return info;
    }
    LOGI(L"Update: manifest signature verified.");

    Json::Value root;
    if (!Json::Parse(manifestRaw, root) || root.type != Json::Value::Type::Object) {
        LOGE(L"Update: manifest is not valid JSON.");
        info.error = T(L"msg.updParseFail");
        return info;
    }

    uint64_t schema = 0;
    if (!root.GetUInt("schema", schema) || schema != 2) {
        LOGE(L"Update: unsupported manifest schema.");
        info.error = T(L"msg.updSchema");
        return info;
    }

    info.version = TrimW(Utf8ToWide(root.GetStr("version")));
    if (info.version.empty()) {
        LOGE(L"Update: manifest has no version.");
        info.error = T(L"msg.updParseFail");
        return info;
    }
    info.released = Utf8ToWide(root.GetStr("released"));

    if (!root.GetUInt("chunk_size", info.chunkSize) || info.chunkSize == 0) {
        LOGE(L"Update: chunk_size missing or zero.");
        info.error = T(L"msg.updParseFail");
        return info;
    }

    // Release notes for the active language, falling back to English.
    if (const Json::Value* notes = root.Find("notes")) {
        if (notes->type == Json::Value::Type::Object) {
            const char* want = (GetLang() == Lang::Chinese) ? "zh-CN" : "en";
            std::string text = notes->GetStr(want);
            if (text.empty()) text = notes->GetStr("en");
            info.notes = TrimW(Utf8ToWide(text));
        }
    }

    // An install older than min_upgradable_from cannot be stepped forward
    // incrementally; tell the user to reinstall rather than half-applying.
    const std::wstring minFrom = TrimW(Utf8ToWide(root.GetStr("min_upgradable_from")));
    if (!minFrom.empty() && CompareVersions(APP_VERSION_NUM, minFrom) < 0) {
        LOGW(L"Update: this install (" APP_VERSION_NUM L") predates min_upgradable_from " +
             minFrom);
        info.reinstallRequired = true;
        info.error = T(L"msg.updReinstall");
        return info;
    }

    const Json::Array* files = root.GetArr("files");
    if (!files || files->empty()) {
        LOGE(L"Update: manifest lists no files.");
        info.error = T(L"msg.updParseFail");
        return info;
    }

    // Any malformed or unsafe entry invalidates the whole manifest: silently
    // skipping one would apply a partial release that no longer matches the version
    // we are about to record.
    for (const Json::Value& entry : *files) {
        if (entry.type != Json::Value::Type::Object) {
            info.error = T(L"msg.updParseFail");
            return info;
        }
        File f;
        f.path = Utf8ToWide(entry.GetStr("path"));
        if (!FileSystem::IsSafePath(f.path)) {
            LOGE(L"Update: rejecting unsafe path in manifest: " + f.path);
            info.error = T(L"msg.updBadPath");
            return info;
        }
        f.path = ToNative(f.path);
        f.isExe = entry.GetStr("role") == "exe";
        f.sha256 = LowerW(Utf8ToWide(entry.GetStr("sha256")));
        if (!IsHexDigest(f.sha256) || !entry.GetUInt("size", f.size)) {
            LOGE(L"Update: bad size/sha256 for " + f.path);
            info.error = T(L"msg.updParseFail");
            return info;
        }

        const Json::Array* chunks = entry.GetArr("chunks");
        if (!chunks || chunks->empty()) {
            LOGE(L"Update: no chunks for " + f.path);
            info.error = T(L"msg.updParseFail");
            return info;
        }
        uint64_t sum = 0;
        for (const Json::Value& chunkEntry : *chunks) {
            if (chunkEntry.type != Json::Value::Type::Object) {
                info.error = T(L"msg.updParseFail");
                return info;
            }
            Chunk c;
            c.name = Utf8ToWide(chunkEntry.GetStr("name"));
            c.sha256 = LowerW(Utf8ToWide(chunkEntry.GetStr("sha256")));
            if (!FileSystem::IsSafePath(c.name) || !IsHexDigest(c.sha256) ||
                !chunkEntry.GetUInt("size", c.size) || c.size > info.chunkSize) {
                LOGE(L"Update: bad chunk record for " + f.path);
                info.error = T(L"msg.updParseFail");
                return info;
            }
            sum += c.size;
            f.chunks.push_back(std::move(c));
        }
        // Catch a manifest whose chunk list cannot possibly reassemble to the stated
        // file before spending any bandwidth on it.
        if (sum != f.size) {
            LOGE(L"Update: chunk sizes do not sum to the file size for " + f.path);
            info.error = T(L"msg.updParseFail");
            return info;
        }
        info.files.push_back(std::move(f));
    }

    info.ok = true;
    return info;
}

bool UpdateAvailable(const Info& info, std::wstring& summary) {
    summary.clear();
    if (!info.ok) return false;
    bool any = false;
    for (const File& f : info.files) {
        if (NeedsUpdate(f, info)) {
            summary += L"- " + f.path + L"\n";
            any = true;
        }
    }
    return any;
}

bool PerformUpdate(const Info& info, const Progress& progress) {
    if (!info.ok) return false;

    // ---- Phase 1: download and verify everything. Nothing is touched yet. ----
    //
    // The pass may run twice. If a chunk 404s or fails its hash mid-download, a
    // publish most likely landed between our manifest fetch and now, so the manifest
    // we hold is stale. We re-fetch AND RE-VERIFY THE SIGNATURE of a fresh manifest,
    // then reconcile: files already staged and verified whose content is unchanged
    // are reused, and only what actually moved is re-downloaded. A single retry is
    // enough — if the tree is being republished faster than we can settle, the user's
    // next check picks it up. A local failure or a failed re-fetch aborts immediately.
    Info current = info;
    std::vector<Staged> staged;
    std::map<std::wstring, std::wstring> verified;  // target -> staged .new SHA
    std::set<std::wstring> allNew;                  // every .new path we created
    std::wstring err;

    bool ok = false;
    for (int attempt = 0; attempt < 2; ++attempt) {
        // The previous attempt's entries point into the previous Info, so rebuild the
        // list against `current`. Staged .new files survive on disk and are reused.
        staged.clear();
        const DownloadResult result =
            DownloadPhase(current, staged, verified, allNew, progress, err);
        if (result == DownloadResult::Ok) {
            ok = true;
            break;
        }
        if (result == DownloadResult::Hard) break;
        if (attempt == 1) break;  // already retried once

        LOGW(L"Update: download disagreed with the manifest; re-fetching to reconcile.");
        Info fresh = FetchManifest();
        if (!fresh.ok) {
            err = fresh.error.empty() ? std::wstring(T(L"msg.updFail")) : fresh.error;
            break;
        }
        current = std::move(fresh);
    }

    if (!ok) {
        // Roll back the staging area only — the install is untouched.
        for (const std::wstring& path : allNew) DeleteFileW(path.c_str());
        ReportFailure(err);
        return false;
    }

    if (staged.empty()) {
        LOGI(L"Update: nothing to do.");
        for (const std::wstring& path : allNew) DeleteFileW(path.c_str());
        return false;
    }

    // Drop any .new left over from a discarded stale attempt (e.g. a file the fresh
    // manifest no longer lists) so the staging area holds only what we will apply.
    {
        std::set<std::wstring> keep;
        for (const Staged& s : staged) keep.insert(s.tmp);
        for (const std::wstring& path : allNew)
            if (keep.count(path) == 0) DeleteFileW(path.c_str());
    }

    // Everything is downloaded and verified; the live install has not been touched.
    // Now — and only now — let the caller stop the services, so the proxy stayed up
    // for the whole download and a locked binary can be overwritten in the apply that
    // immediately follows.
    if (progress.onBeforeApply) progress.onBeforeApply();

    // ---- Phase 2: apply. Assets move into place now; the executable is swapped by
    // a helper after we exit, since a running image cannot replace itself. ----
    Staged* exeEntry = nullptr;
    bool failed = false;
    for (Staged& s : staged) {
        if (s.file->isExe) {
            exeEntry = &s;
            continue;
        }

        DeleteFileW(s.bak.c_str());
        if (FileExists(s.target)) {
            if (!MoveFileExW(s.target.c_str(), s.bak.c_str(), MOVEFILE_REPLACE_EXISTING)) {
                LOGE(L"Update: cannot move aside " + s.target + L" (err " +
                     std::to_wstring(GetLastError()) + L")");
                failed = true;
                break;
            }
            s.movedBak = true;
        }
        if (!MoveFileExW(s.tmp.c_str(), s.target.c_str(), MOVEFILE_REPLACE_EXISTING)) {
            LOGE(L"Update: cannot install " + s.target + L" (err " +
                 std::to_wstring(GetLastError()) + L")");
            failed = true;
            break;
        }
        s.applied = true;
        LOGI(L"Update: applied " + s.file->path);
    }

    if (failed) {
        // Restore every asset already replaced, so the install returns to a
        // consistent pre-update state.
        LOGE(L"Update: apply failed — rolling back.");
        for (Staged& s : staged) {
            if (s.applied) {
                DeleteFileW(s.target.c_str());
                s.applied = false;
            }
            if (s.movedBak) {
                MoveFileExW(s.bak.c_str(), s.target.c_str(), MOVEFILE_REPLACE_EXISTING);
                s.movedBak = false;
            }
            DeleteFileW(s.tmp.c_str());
        }
        ReportFailure(T(L"msg.updApplyFail"));
        return false;
    }

    // Assets are in place; drop their backups.
    for (const Staged& s : staged)
        if (s.applied) DeleteFileW(s.bak.c_str());

    // Ensure required directories exist after applying the update.
    Services::EnsureRequiredDirectories();

    if (!exeEntry) {
        LOGI(L"Update: complete (assets only).");
        return false;
    }

    // ---- Phase 3: swap the running executable via a wait-and-relaunch helper. ----
    LOGI(L"Update: launching the self-update helper and exiting.");
    if (!Command::RunDetachedScript(
            L"selfupdate.bat",
            BuildSelfUpdateScript(exeEntry->target, exeEntry->tmp, exeEntry->bak,
                                  Process::OwnCommandLineArgs()))) {
        LOGE(L"Update: cannot start the self-update helper.");
        DeleteFileW(exeEntry->tmp.c_str());
        ReportFailure(T(L"msg.updApplyFail"));
        return false;
    }
    return true;  // the caller must exit so the helper can replace us
}

}  // namespace Update
