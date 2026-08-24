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
#include <functional>
#include <string>
#include <vector>

// File system utilities: glob pattern matching, recursive operations, and safe path
// validation. Shared across uninstall, cache cleanup, and directory management.
namespace FileSystem {

// ---- Pattern matching ----

// A compiled glob pattern that can be matched against file paths.
struct GlobPattern {
    std::wstring raw;           // original pattern string
    bool         isRecursive;   // contains **
    bool         isValid;       // passed safety checks

    // Internal compiled representation (opaque to callers).
    struct Segment {
        enum Type { Literal, Wildcard, RecursiveWildcard };
        Type         type;
        std::wstring text;  // for Literal segments
    };
    std::vector<Segment> segments;
};

// Compile a glob pattern. Returns a GlobPattern with isValid set based on safety
// checks (no .., no drive letters, no absolute paths). Supports:
//   *      - matches any characters except path separators
//   ?      - matches a single character except path separators
//   **     - recursively matches any depth of directories
//
// Examples:
//   "*.log"           - all .log files in the root
//   "data\*.conf"     - all .conf files directly under data
//   "data\**\*.log"   - all .log files recursively under data
//   "logs\*"          - all direct children under logs (empties the directory)
//   "**\*.tmp"        - all .tmp files anywhere recursively
//
// Forbidden patterns (isValid will be false):
//   "..\path"         - directory traversal
//   "C:\path"         - absolute path
//   "**\*"            - redundant (use * instead)
//   "dir\**\*"        - redundant (use dir\* instead)
//   "**"              - ambiguous semantics
GlobPattern CompilePattern(const std::wstring& pattern);

// True if the relative path `rel` matches the compiled `pattern`. Both are
// normalized to backslashes before matching.
bool MatchesPattern(const std::wstring& rel, const GlobPattern& pattern);

// ---- Path safety ----

// True if `p` is a plain relative path safe to operate on under the program
// directory: no drive letter or ADS, not root-relative or UNC, no "." or ".."
// component. This is the strictest validation, used for paths that will be written
// or deleted.
bool IsSafePath(const std::wstring& p);

// True if `p` is a valid glob pattern safe to match under the program directory.
// Allows * and ? wildcards, but still rejects .., drive letters, and absolute paths.
// Does NOT validate ** semantics (use CompilePattern for that).
bool IsSafePatternSyntax(const std::wstring& p);

// ---- Directory operations ----

// Recursively create `dir` and all parent directories. Idempotent: succeeds if the
// directory already exists. Returns true on success.
bool EnsureDirectory(const std::wstring& dir);

// Ensure every directory in `dirs` exists, creating them recursively as needed.
// Returns the count of directories that were created (not how many already existed).
size_t EnsureDirectories(const std::vector<std::wstring>& dirs);

// ---- Deletion operations ----

// Callback invoked before each deletion. Return false to skip that item.
using DeletionFilter = std::function<bool(const std::wstring& path, bool isDir)>;

// Recursively delete `dir` and everything under it. Read-only attributes are cleared
// first. Reparse points are removed as links and never followed, so a symlink or
// junction in the payload cannot redirect the recursion outside it.
void DeleteTree(const std::wstring& dir);

// Delete the file or directory at `path`. If it's a directory, recursively deletes
// its contents. Reparse points are unlinked without following.
void Delete(const std::wstring& path);

// Find all paths under `baseDir` matching `pattern` and delete them. The pattern is
// relative to `baseDir`. If `filter` is provided, it is called before each deletion
// and can veto it by returning false.
//
// Examples:
//   DeleteByPattern(ExeDir(), "*.log")           - delete all .log in root
//   DeleteByPattern(ExeDir(), "logs\*")          - empty logs directory
//   DeleteByPattern(ExeDir(), "data\**\*.tmp")   - delete all .tmp under data
//
// Returns the count of items deleted.
size_t DeleteByPattern(const std::wstring& baseDir, const std::wstring& pattern,
                       const DeletionFilter& filter = nullptr);

// Delete multiple patterns under `baseDir`. Equivalent to calling DeleteByPattern
// for each, but more efficient when patterns overlap (a file is deleted at most once).
// Returns the total count of items deleted.
size_t DeleteByPatterns(const std::wstring& baseDir,
                        const std::vector<std::wstring>& patterns,
                        const DeletionFilter& filter = nullptr);

// ---- Enumeration ----

// Enumerate all files and directories under `baseDir` matching `pattern`. The pattern
// is relative to `baseDir`, and results are returned as paths relative to `baseDir`.
// Directories have a trailing backslash.
std::vector<std::wstring> Enumerate(const std::wstring& baseDir,
                                     const std::wstring& pattern);

}  // namespace FileSystem
