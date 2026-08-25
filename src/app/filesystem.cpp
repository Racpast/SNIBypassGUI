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

#include "app/filesystem.h"

#include <windows.h>

#include <algorithm>
#include <map>

#include "app/logging.h"
#include "app/text.h"

namespace FileSystem {
namespace {

// Normalize path separators to backslashes.
std::wstring NormalizePath(std::wstring p) {
    for (wchar_t& c : p)
        if (c == L'/') c = L'\\';
    return p;
}

// Split a path into segments by backslash or forward slash.
std::vector<std::wstring> SplitPath(const std::wstring& p) {
    std::vector<std::wstring> out;
    size_t start = 0;
    for (size_t i = 0; i <= p.size(); ++i) {
        if (i == p.size() || p[i] == L'\\' || p[i] == L'/') {
            if (i > start) out.push_back(p.substr(start, i - start));
            start = i + 1;
        }
    }
    return out;
}

// True if a segment contains wildcards.
bool HasWildcard(const std::wstring& seg) {
    return seg.find(L'*') != std::wstring::npos || seg.find(L'?') != std::wstring::npos;
}

// Match a single path segment against a pattern segment containing * and ?.
// Does not handle ** (that's structural, not per-segment).
bool MatchSegment(const std::wstring& seg, const std::wstring& pattern) {
    size_t si = 0, pi = 0;
    size_t starIdx = std::wstring::npos, matchIdx = 0;

    while (si < seg.size()) {
        if (pi < pattern.size() && pattern[pi] == L'?') {
            ++si;
            ++pi;
        } else if (pi < pattern.size() && pattern[pi] == L'*') {
            starIdx = pi;
            matchIdx = si;
            ++pi;
        } else if (pi < pattern.size() && pattern[pi] == seg[si]) {
            ++si;
            ++pi;
        } else if (starIdx != std::wstring::npos) {
            pi = starIdx + 1;
            ++matchIdx;
            si = matchIdx;
        } else {
            return false;
        }
    }

    while (pi < pattern.size() && pattern[pi] == L'*') ++pi;
    return pi == pattern.size();
}

// Recursively enumerate paths under `dir`, calling `callback` for each.
// `relPath` is the path relative to the original base directory.
// Reparse points are reported but not descended.
void EnumerateRecursive(const std::wstring& dir, const std::wstring& relPath,
                        const std::function<void(const std::wstring&, bool isDir)>& callback) {
    WIN32_FIND_DATAW find;
    HANDLE handle = FindFirstFileW((dir + L"\\*").c_str(), &find);
    if (handle == INVALID_HANDLE_VALUE) return;

    do {
        const std::wstring name = find.cFileName;
        if (name == L"." || name == L"..") continue;

        const bool isDir = (find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        const bool isReparse = (find.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
        const std::wstring fullPath = dir + L"\\" + name;
        const std::wstring rel = relPath.empty() ? name : relPath + L"\\" + name;

        callback(rel, isDir);

        // Descend into real directories, but not reparse points (symlinks/junctions).
        if (isDir && !isReparse) {
            EnumerateRecursive(fullPath, rel, callback);
        }
    } while (FindNextFileW(handle, &find));

    FindClose(handle);
}

}  // namespace

GlobPattern CompilePattern(const std::wstring& pattern) {
    GlobPattern compiled;
    compiled.raw = pattern;
    compiled.isValid = false;
    compiled.isRecursive = false;

    // Safety checks first.
    if (pattern.empty()) return compiled;
    if (pattern.find(L':') != std::wstring::npos) return compiled;   // drive letter or ADS
    if (pattern[0] == L'\\' || pattern[0] == L'/') return compiled;  // absolute path
    if (pattern.find(L"..") != std::wstring::npos) return compiled;  // traversal

    const std::wstring normalized = NormalizePath(pattern);
    const std::vector<std::wstring> segments = SplitPath(normalized);
    if (segments.empty()) return compiled;

    // Check for forbidden patterns.
    for (const std::wstring& seg : segments) {
        if (seg == L"." || seg == L"..") return compiled;
    }

    // Detect ** and validate its usage.
    bool hasRecursive = false;
    for (size_t i = 0; i < segments.size(); ++i) {
        if (segments[i] == L"**") {
            hasRecursive = true;
            // Forbid bare "**" (no pattern after it).
            if (i == segments.size() - 1) return compiled;
            // Forbid "**\*" (redundant; use "*" instead) and "dir\**\*" (use "dir\*").
            if (i == segments.size() - 2 && segments[i + 1] == L"*") return compiled;
        }
    }
    compiled.isRecursive = hasRecursive;

    // Compile segments.
    for (const std::wstring& seg : segments) {
        if (seg == L"**") {
            compiled.segments.push_back({GlobPattern::Segment::RecursiveWildcard, L""});
        } else if (HasWildcard(seg)) {
            compiled.segments.push_back({GlobPattern::Segment::Wildcard, seg});
        } else {
            compiled.segments.push_back({GlobPattern::Segment::Literal, seg});
        }
    }

    compiled.isValid = true;
    return compiled;
}

bool MatchesPattern(const std::wstring& rel, const GlobPattern& pattern) {
    if (!pattern.isValid) return false;

    const std::wstring normalized = NormalizePath(rel);
    const std::vector<std::wstring> pathSegs = SplitPath(normalized);
    const std::vector<GlobPattern::Segment>& patSegs = pattern.segments;

    // Non-recursive patterns: simple segment-by-segment match.
    if (!pattern.isRecursive) {
        if (pathSegs.size() != patSegs.size()) return false;
        for (size_t i = 0; i < pathSegs.size(); ++i) {
            const auto& ps = patSegs[i];
            if (ps.type == GlobPattern::Segment::Literal) {
                if (pathSegs[i] != ps.text) return false;
            } else if (ps.type == GlobPattern::Segment::Wildcard) {
                if (!MatchSegment(pathSegs[i], ps.text)) return false;
            }
        }
        return true;
    }

    // Recursive patterns: backtracking match where ** can consume 0+ segments.
    // This is a classic DP/backtracking problem.
    std::function<bool(size_t, size_t)> match = [&](size_t pi, size_t si) -> bool {
        // Both exhausted: match.
        if (pi == patSegs.size() && si == pathSegs.size()) return true;
        // Pattern exhausted but path remains: no match.
        if (pi == patSegs.size()) return false;
        // Path exhausted but pattern remains: only if all remaining are ** (consume 0).
        if (si == pathSegs.size()) {
            for (size_t i = pi; i < patSegs.size(); ++i)
                if (patSegs[i].type != GlobPattern::Segment::RecursiveWildcard) return false;
            return true;
        }

        const auto& ps = patSegs[pi];
        if (ps.type == GlobPattern::Segment::RecursiveWildcard) {
            // ** can consume 0 segments (try to match next pattern segment immediately)
            if (match(pi + 1, si)) return true;
            // or consume 1+ segments (advance path, keep pattern position).
            return match(pi, si + 1);
        } else if (ps.type == GlobPattern::Segment::Literal) {
            if (pathSegs[si] != ps.text) return false;
            return match(pi + 1, si + 1);
        } else {  // Wildcard
            if (!MatchSegment(pathSegs[si], ps.text)) return false;
            return match(pi + 1, si + 1);
        }
    };

    return match(0, 0);
}

bool IsSafePath(const std::wstring& p) {
    if (p.empty()) return false;
    if (p.find(L':') != std::wstring::npos) return false;  // drive letter or ADS
    if (p[0] == L'\\' || p[0] == L'/') return false;       // root-relative or UNC
    if (p.find(L'*') != std::wstring::npos || p.find(L'?') != std::wstring::npos)
        return false;  // wildcards not allowed in strict paths

    const std::vector<std::wstring> segments = SplitPath(p);
    for (const std::wstring& seg : segments) {
        if (seg.empty() || seg == L"." || seg == L"..") return false;
    }
    return true;
}

bool IsSafePatternSyntax(const std::wstring& p) {
    if (p.empty()) return false;
    if (p.find(L':') != std::wstring::npos) return false;   // drive letter or ADS
    if (p[0] == L'\\' || p[0] == L'/') return false;        // root-relative or UNC
    if (p.find(L"..") != std::wstring::npos) return false;  // traversal

    const std::vector<std::wstring> segments = SplitPath(p);
    for (const std::wstring& seg : segments) {
        if (seg.empty() || seg == L"." || seg == L"..") return false;
    }
    return true;
}

bool EnsureDirectory(const std::wstring& dir) {
    if (dir.empty()) return false;

    // Already exists?
    const DWORD attr = GetFileAttributesW(dir.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES) {
        return (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }

    // Build the path incrementally, creating each level.
    std::wstring partial;
    for (wchar_t c : dir) {
        partial.push_back(c);
        if (c == L'\\' || c == L'/') {
            CreateDirectoryW(partial.c_str(), nullptr);
        }
    }
    return CreateDirectoryW(dir.c_str(), nullptr) != 0 ||
           GetLastError() == ERROR_ALREADY_EXISTS;
}

size_t EnsureDirectories(const std::vector<std::wstring>& dirs) {
    size_t created = 0;
    for (const std::wstring& dir : dirs) {
        const DWORD before = GetFileAttributesW(dir.c_str());
        const bool existed =
            (before != INVALID_FILE_ATTRIBUTES && (before & FILE_ATTRIBUTE_DIRECTORY) != 0);
        if (EnsureDirectory(dir) && !existed) ++created;
    }
    return created;
}

void DeleteTree(const std::wstring& dir) {
    WIN32_FIND_DATAW find;
    HANDLE handle = FindFirstFileW((dir + L"\\*").c_str(), &find);
    if (handle == INVALID_HANDLE_VALUE) return;

    do {
        const std::wstring name = find.cFileName;
        if (name == L"." || name == L"..") continue;
        const std::wstring full = dir + L"\\" + name;

        // Clear read-only so we can delete.
        if (find.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
            SetFileAttributesW(full.c_str(), FILE_ATTRIBUTE_NORMAL);

        // Unlink reparse points without following them.
        if (find.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            if (find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                RemoveDirectoryW(full.c_str());
            else
                DeleteFileW(full.c_str());
        } else if (find.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            DeleteTree(full);
        } else {
            DeleteFileW(full.c_str());
        }
    } while (FindNextFileW(handle, &find));

    FindClose(handle);
    RemoveDirectoryW(dir.c_str());
}

void Delete(const std::wstring& path) {
    const DWORD attr = GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return;

    if (attr & FILE_ATTRIBUTE_READONLY) SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_NORMAL);

    if (attr & FILE_ATTRIBUTE_REPARSE_POINT) {
        if (attr & FILE_ATTRIBUTE_DIRECTORY)
            RemoveDirectoryW(path.c_str());
        else
            DeleteFileW(path.c_str());
    } else if (attr & FILE_ATTRIBUTE_DIRECTORY) {
        DeleteTree(path);
    } else {
        DeleteFileW(path.c_str());
    }
}

std::vector<std::wstring> Enumerate(const std::wstring& baseDir, const std::wstring& pattern) {
    const GlobPattern compiled = CompilePattern(pattern);
    if (!compiled.isValid) return {};

    std::vector<std::wstring> results;
    EnumerateRecursive(baseDir, L"", [&](const std::wstring& rel, bool isDir) {
        if (MatchesPattern(rel, compiled)) {
            results.push_back(isDir ? rel + L"\\" : rel);
        }
    });

    return results;
}

size_t DeleteByPattern(const std::wstring& baseDir, const std::wstring& pattern,
                       const DeletionFilter& filter) {
    const GlobPattern compiled = CompilePattern(pattern);
    if (!compiled.isValid) {
        LOGW(L"FileSystem: rejecting unsafe pattern: " + pattern);
        return 0;
    }

    // Collect matches first (enumeration invalidated by deletion).
    struct Match {
        std::wstring rel;
        std::wstring full;
        bool isDir;
    };
    std::vector<Match> matches;

    EnumerateRecursive(baseDir, L"", [&](const std::wstring& rel, bool isDir) {
        if (MatchesPattern(rel, compiled)) {
            matches.push_back({rel, baseDir + L"\\" + rel, isDir});
        }
    });

    // Sort by depth (deepest first) so children are deleted before parents.
    std::sort(matches.begin(), matches.end(), [](const Match& a, const Match& b) {
        const size_t depthA = std::count(a.rel.begin(), a.rel.end(), L'\\');
        const size_t depthB = std::count(b.rel.begin(), b.rel.end(), L'\\');
        return depthA > depthB;
    });

    size_t deleted = 0;
    for (const Match& m : matches) {
        if (filter && !filter(m.rel, m.isDir)) continue;
        Delete(m.full);
        ++deleted;
        LOGI(L"FileSystem: deleted " + m.rel);
    }

    return deleted;
}

size_t DeleteByPatterns(const std::wstring& baseDir, const std::vector<std::wstring>& patterns,
                        const DeletionFilter& filter) {
    // Compile all patterns first.
    std::vector<GlobPattern> compiled;
    for (const std::wstring& p : patterns) {
        GlobPattern c = CompilePattern(p);
        if (!c.isValid) {
            LOGW(L"FileSystem: rejecting unsafe pattern: " + p);
            continue;
        }
        compiled.push_back(std::move(c));
    }

    if (compiled.empty()) return 0;

    // Collect matches (deduplicated by path).
    struct Match {
        std::wstring rel;
        std::wstring full;
        bool isDir;
    };
    std::map<std::wstring, Match> matchMap;

    EnumerateRecursive(baseDir, L"", [&](const std::wstring& rel, bool isDir) {
        for (const GlobPattern& pat : compiled) {
            if (MatchesPattern(rel, pat)) {
                matchMap[rel] = {rel, baseDir + L"\\" + rel, isDir};
                break;
            }
        }
    });

    // Sort by depth (deepest first).
    std::vector<Match> matches;
    matches.reserve(matchMap.size());
    for (auto& kv : matchMap) matches.push_back(std::move(kv.second));

    std::sort(matches.begin(), matches.end(), [](const Match& a, const Match& b) {
        const size_t depthA = std::count(a.rel.begin(), a.rel.end(), L'\\');
        const size_t depthB = std::count(b.rel.begin(), b.rel.end(), L'\\');
        return depthA > depthB;
    });

    size_t deleted = 0;
    for (const Match& m : matches) {
        if (filter && !filter(m.rel, m.isDir)) continue;
        Delete(m.full);
        ++deleted;
        LOGI(L"FileSystem: deleted " + m.rel);
    }

    return deleted;
}

}  // namespace FileSystem
