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

#include "ui/supported_sites.h"

#include <fstream>
#include <sstream>
#include <utility>

#include "app/i18n.h"
#include "app/logging.h"
#include "app/services.h"
#include "app/text.h"

// Data file format (UTF-8, optional BOM, one directive per line), interpreted
// top-to-bottom. Directive keywords are case-insensitive:
//
//   # comment            '#' or '//' starts a comment line
//   TEXT "label"         non-clickable, grayed label
//   LINK "label" "url"   clickable entry; the url must be http:// or https://
//   SEP                  separator
//   GROUP "label"        begin a nested submenu
//   END                  close the innermost GROUP
//   INCLUDE "rel/path"   inline another file's directives at this point
//
// Language conditionals select entries by the current UI language. They may nest and
// may wrap any directives, including GROUP/END and other IF blocks:
//
//   IF zh / ELIF en / ELSE / ENDIF
//
// The language code is compared case-insensitively; an unknown code simply never
// matches, so older builds skip conditions they do not know.
//
// GROUP/END and IF/ENDIF must nest like matching brackets: "IF ... GROUP ... ENDIF"
// is rejected because the ENDIF would cross the still-open GROUP. A closer that does
// not match the innermost open block is warned about and ignored.
//
// INCLUDE pastes another file's directives inline, so a fragment can be the body
// reused by several localized GROUPs. Include paths are relative to the including
// file and confined to the root file's directory tree; cycles and excessive depth
// are refused.
//
// Quoted values support the escapes \" and \\. Malformed lines are skipped with a
// warning; the file being absent is normal (the submenu simply grays out).
//
// Every entry point runs on the UI thread during tray menu construction, so the
// module is intentionally not thread-safe.

namespace SupportedSites {
namespace {

// Bounds the reserved command-id range. This is NOT a limit on file size, only on
// the number of clickable entries.
constexpr size_t kMaxLinkItems = 1024;

// Hard cap on parsed entries, so a pathological file cannot produce an unusable menu
// or exhaust memory while building it.
constexpr size_t kMaxNodes = 4096;

// Groups deeper than this are inlined into their parent, with the title as a grayed
// heading, so nothing is silently lost.
constexpr int kMaxGroupDepth = 4;

// Menu text longer than this is truncated with an ellipsis.
constexpr size_t kMaxTextLen = 100;

// Maximum INCLUDE nesting (the root file is depth 0). Bounds the work even without a
// cycle; cycles are caught separately by the include stack.
constexpr int kMaxIncludeDepth = 8;

struct Node {
    enum class Type { Text, Separator, Link, GroupBegin, GroupEnd };
    Type type = Type::Text;
    std::wstring text;
    std::wstring link;
};

// Extract a double-quoted string at or after `pos`, honouring \" and \\ escapes. On
// success advances `pos` past the closing quote.
bool ExtractQuoted(const std::wstring& line, size_t& pos, std::wstring& out) {
    const size_t start = line.find(L'"', pos);
    if (start == std::wstring::npos) return false;

    out.clear();
    for (size_t i = start + 1; i < line.size(); ++i) {
        const wchar_t c = line[i];
        if (c == L'\\' && i + 1 < line.size()) {
            const wchar_t next = line[i + 1];
            if (next == L'"' || next == L'\\') {
                out.push_back(next);
                ++i;
                continue;
            }
        }
        if (c == L'"') {
            pos = i + 1;
            return true;
        }
        out.push_back(c);
    }
    return false;  // unterminated quote
}

// Replace control characters and clamp length, so a crafted or corrupted file cannot
// break the menu layout.
std::wstring SanitizeText(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size());
    for (wchar_t c : s) out.push_back((c < 0x20 || c == 0x7F) ? L' ' : c);
    if (out.size() > kMaxTextLen) {
        out.resize(kMaxTextLen);
        out += L"…";
    }
    return out;
}

// The current UI language as the lowercase code used in IF/ELIF conditions.
std::wstring CurrentLangCode() {
    return GetLang() == Lang::Chinese ? L"zh" : L"en";
}

// Split a directive into its lowercased keyword and the trimmed remainder.
void SplitDirective(const std::wstring& line, std::wstring& keyword, std::wstring& operand) {
    size_t i = 0;
    while (i < line.size() && line[i] != L' ' && line[i] != L'\t') ++i;
    keyword = LowerW(line.substr(0, i));
    operand = TrimW(line.substr(i));
}

// Only plain web URLs may reach the shell. Anything else (file:, ms-*:, command
// lines, UNC paths) is rejected, so a tampered data file cannot be used to launch
// arbitrary programs from the tray menu.
bool IsSafeWebUrl(const std::wstring& url) {
    const std::wstring low = LowerW(url);
    return low.rfind(L"http://", 0) == 0 || low.rfind(L"https://", 0) == 0;
}

// Escape '&' so Win32 menus render it literally instead of as a mnemonic.
std::wstring EscapeMenuText(const std::wstring& s) {
    std::wstring out;
    out.reserve(s.size() + 4);
    for (wchar_t c : s) {
        if (c == L'&') out.push_back(L'&');
        out.push_back(c);
    }
    return out;
}

// Directory portion of a path with a trailing backslash, empty if there is none.
std::wstring DirOf(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? L"" : path.substr(0, slash + 1);
}

// Full canonical path, collapsing "." and ".." and normalizing slashes.
std::wstring CanonicalPath(const std::wstring& path) {
    wchar_t buf[MAX_PATH * 4];
    const DWORD n =
        GetFullPathNameW(path.c_str(), static_cast<DWORD>(std::size(buf)), buf, nullptr);
    if (n == 0 || n >= std::size(buf)) return L"";
    return buf;
}

// Reject an INCLUDE operand that is not a plain relative path: absolute,
// drive-qualified and UNC paths could escape the data directory.
bool IsRelativeIncludePath(const std::wstring& p) {
    if (p.empty()) return false;
    if (p[0] == L'\\' || p[0] == L'/') return false;  // root-relative or UNC
    if (p.size() >= 2 && p[1] == L':') return false;  // drive-qualified
    return true;
}

// Resolve an INCLUDE against the including file's directory and confirm the result
// stays within `rootDir`. Returns the canonical absolute path, or empty if unsafe.
std::wstring ResolveInclude(const std::wstring& rootDir, const std::wstring& includingDir,
                            const std::wstring& rel) {
    if (!IsRelativeIncludePath(rel)) return L"";
    const std::wstring full = CanonicalPath(includingDir + rel);
    if (full.empty()) return L"";
    std::wstring root = CanonicalPath(rootDir);
    if (root.empty()) return L"";
    if (root.back() != L'\\') root.push_back(L'\\');
    if (LowerW(full).rfind(LowerW(root), 0) != 0) return L"";  // escaped the root tree
    return full;
}

// ---- Cache ------------------------------------------------------------------
//
// The menu is rebuilt every time the tray icon is right-clicked, so the parsed nodes
// are cached and invalidated when any participating file's size or write time
// changes. A missing file is cached too, so we neither re-parse nor spam the log on
// every menu open.

struct FileStamp {
    long long size = -1;
    long long mtime = -1;
    bool operator==(const FileStamp& o) const { return size == o.size && mtime == o.mtime; }
};

void StampFile(const std::wstring& path, FileStamp& out) {
    WIN32_FILE_ATTRIBUTE_DATA data = {};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) return;
    out.size = (static_cast<long long>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
    out.mtime = (static_cast<long long>(data.ftLastWriteTime.dwHighDateTime) << 32) |
                static_cast<long long>(data.ftLastWriteTime.dwLowDateTime);
}

struct Cache {
    bool valid = false;
    std::wstring path;                // canonical root path
    std::wstring lang;                // language the nodes were parsed for
    std::vector<std::wstring> files;  // root plus every included file, first-seen order
    std::vector<FileStamp> stamps;    // one per entry in `files`
    std::vector<Node> nodes;
};

Cache g_cache;

// A single nesting-stack frame. GROUP/END and IF/ENDIF share one stack so their
// interleaving is validated as matching brackets: a closer must match the kind of the
// innermost open block.
//
// Cond frames also carry branch state:
//   taken        some branch in this IF chain has already matched
//   active       the branch we are currently inside is the matching one
//   parentActive was the enclosing context emitting when the IF opened
//   seenElse     an ELSE has been consumed, so no ELIF/ELSE may follow
struct Frame {
    enum class Kind { Group, Cond };
    Kind kind = Kind::Group;
    bool taken = false;
    bool active = false;
    bool parentActive = false;
    bool seenElse = false;
    bool emitted = false;  // Group only: did we emit a GroupBegin?
};

// State threaded through the (recursive, via INCLUDE) parse.
struct ParseContext {
    std::wstring langCode = CurrentLangCode();
    std::wstring rootDir;  // confines INCLUDE targets
    std::vector<Node> nodes;
    std::vector<Frame> stack;
    std::vector<std::wstring> includeStack;  // canonical paths, for cycle detection
    std::vector<std::wstring> filesSeen;     // every file parsed, for cache stamping
    bool overflow = false;

    // Emitting only when every enclosing Cond frame is active; Group frames never
    // suppress output.
    bool Emitting() const {
        for (const Frame& f : stack)
            if (f.kind == Frame::Kind::Cond && !f.active) return false;
        return true;
    }
};

// Parse one already-canonical file into `ctx`. Returns false only on a hard stop
// (node overflow); structural problems are warnings that skip the offender.
bool ParseInto(ParseContext& ctx, const std::wstring& path, int depth) {
    ctx.filesSeen.push_back(path);

    std::ifstream in(path.c_str(), std::ios::binary);
    if (!in) {
        if (depth == 0)
            // A missing root file is normal before the payload has been delivered;
            // the submenu simply grays out.
            LOGI(L"Supported sites file not found: " + path);
        else
            LOGW(L"Supported sites: INCLUDE target could not be opened: " + path);
        return true;
    }

    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (raw.size() >= 3 && static_cast<unsigned char>(raw[0]) == 0xEF &&
        static_cast<unsigned char>(raw[1]) == 0xBB &&
        static_cast<unsigned char>(raw[2]) == 0xBF)
        raw.erase(0, 3);

    const std::wstring dir = DirOf(path);
    std::wistringstream lines(Utf8ToWide(raw));
    std::wstring line;
    size_t lineNo = 0;

    while (std::getline(lines, line)) {
        ++lineNo;
        if (!line.empty() && line.back() == L'\r') line.pop_back();

        const std::wstring trimmed = TrimW(line);
        if (trimmed.empty()) continue;
        if (trimmed[0] == L'#' ||
            (trimmed.size() >= 2 && trimmed[0] == L'/' && trimmed[1] == L'/'))
            continue;

        std::wstring keyword;
        std::wstring operand;
        SplitDirective(trimmed, keyword, operand);

        // Conditionals are processed regardless of the emit state, so nesting stays
        // balanced even inside inactive branches.
        if (keyword == L"if") {
            const bool parentActive = ctx.Emitting();
            const bool match = parentActive && LowerW(operand) == ctx.langCode;
            Frame f;
            f.kind = Frame::Kind::Cond;
            f.taken = match;
            f.active = match;
            f.parentActive = parentActive;
            ctx.stack.push_back(f);
            continue;
        }
        if (keyword == L"elif" || keyword == L"else") {
            if (ctx.stack.empty() || ctx.stack.back().kind != Frame::Kind::Cond) {
                LOGW(L"Supported sites: " + keyword + L" without IF at line " +
                     std::to_wstring(lineNo));
                continue;
            }
            Frame& f = ctx.stack.back();
            if (f.seenElse) {
                LOGW(L"Supported sites: " + keyword + L" after ELSE at line " +
                     std::to_wstring(lineNo));
                f.active = false;
                continue;
            }
            if (keyword == L"else") f.seenElse = true;
            const bool match = f.parentActive && !f.taken &&
                               (keyword == L"else" || LowerW(operand) == ctx.langCode);
            f.active = match;
            if (match) f.taken = true;
            continue;
        }
        if (keyword == L"endif") {
            if (ctx.stack.empty() || ctx.stack.back().kind != Frame::Kind::Cond) {
                LOGW(L"Supported sites: ENDIF without matching IF at line " +
                     std::to_wstring(lineNo));
                continue;
            }
            ctx.stack.pop_back();
            continue;
        }

        // GROUP/END are structural: tracked on the stack regardless of the emit state
        // so balance holds inside inactive branches, but they only produce nodes when
        // their branch is active. A GROUP remembers whether it emitted, so its END
        // matches.
        if (keyword == L"group") {
            size_t scan = 0;
            std::wstring title;
            if (!ExtractQuoted(operand, scan, title)) {
                LOGW(L"Supported sites: malformed GROUP at line " + std::to_wstring(lineNo));
                continue;
            }
            Frame f;
            f.kind = Frame::Kind::Group;
            f.emitted = ctx.Emitting();
            ctx.stack.push_back(f);
            if (f.emitted)
                ctx.nodes.push_back({Node::Type::GroupBegin, SanitizeText(title), L""});
            continue;
        }
        if (keyword == L"end") {
            if (ctx.stack.empty() || ctx.stack.back().kind != Frame::Kind::Group) {
                LOGW(L"Supported sites: END without matching GROUP at line " +
                     std::to_wstring(lineNo));
                continue;
            }
            const bool emitted = ctx.stack.back().emitted;
            ctx.stack.pop_back();
            if (emitted) ctx.nodes.push_back({Node::Type::GroupEnd, L"", L""});
            continue;
        }

        // Everything below produces content, so it is skipped in inactive branches.
        if (!ctx.Emitting()) continue;

        if (keyword == L"include") {
            size_t scan = 0;
            std::wstring rel;
            if (!ExtractQuoted(operand, scan, rel)) {
                LOGW(L"Supported sites: malformed INCLUDE at line " + std::to_wstring(lineNo));
                continue;
            }
            if (depth + 1 > kMaxIncludeDepth) {
                LOGW(L"Supported sites: INCLUDE depth exceeded at line " +
                     std::to_wstring(lineNo) + L": " + rel);
                continue;
            }
            const std::wstring target = ResolveInclude(ctx.rootDir, dir, TrimW(rel));
            if (target.empty()) {
                LOGW(L"Supported sites: rejected unsafe INCLUDE path at line " +
                     std::to_wstring(lineNo) + L": " + rel);
                continue;
            }
            bool cycle = false;
            for (const std::wstring& open : ctx.includeStack)
                if (LowerW(open) == LowerW(target)) {
                    cycle = true;
                    break;
                }
            if (cycle) {
                LOGW(L"Supported sites: INCLUDE cycle detected at line " +
                     std::to_wstring(lineNo) + L": " + target);
                continue;
            }
            ctx.includeStack.push_back(target);
            const bool keepGoing = ParseInto(ctx, target, depth + 1);
            ctx.includeStack.pop_back();
            if (!keepGoing) return false;  // propagate a hard stop
            continue;
        }

        if (ctx.nodes.size() >= kMaxNodes) {
            ctx.overflow = true;
            return false;
        }

        if (keyword == L"sep") {
            ctx.nodes.push_back({Node::Type::Separator, L"", L""});
            continue;
        }

        if (keyword == L"text") {
            size_t scan = 0;
            std::wstring label;
            if (ExtractQuoted(operand, scan, label)) {
                ctx.nodes.push_back({Node::Type::Text, SanitizeText(label), L""});
                continue;
            }
        } else if (keyword == L"link") {
            size_t scan = 0;
            std::wstring label;
            std::wstring url;
            if (ExtractQuoted(operand, scan, label) && ExtractQuoted(operand, scan, url)) {
                url = TrimW(url);
                if (!IsSafeWebUrl(url)) {
                    LOGW(L"Supported sites: rejected non-http(s) URL at line " +
                         std::to_wstring(lineNo) + L": " + url);
                    continue;
                }
                ctx.nodes.push_back({Node::Type::Link, SanitizeText(label), url});
                continue;
            }
        }

        LOGW(L"Supported sites: malformed line " + std::to_wstring(lineNo));
    }

    return true;
}

// Parse the root file and everything it includes. `filesSeen` receives every file
// that participated, in first-seen order, so the caller can stamp them.
std::vector<Node> ParseTree(const std::wstring& rootPath,
                            std::vector<std::wstring>& filesSeen) {
    ParseContext ctx;
    ctx.rootDir = DirOf(rootPath);
    ctx.includeStack.push_back(rootPath);
    ParseInto(ctx, rootPath, 0);

    if (ctx.overflow)
        LOGW(L"Supported sites: entry count exceeded " + std::to_wstring(kMaxNodes) +
             L"; remaining directives ignored.");

    // Close anything left open at end of input. Unterminated GROUPs get a synthetic
    // END so the menu tree stays balanced.
    if (!ctx.stack.empty() && !ctx.overflow) {
        size_t groups = 0;
        size_t conds = 0;
        for (const Frame& f : ctx.stack) (f.kind == Frame::Kind::Group ? groups : conds)++;
        LOGW(L"Supported sites: unclosed block(s) at end of input (" + std::to_wstring(groups) +
             L" GROUP, " + std::to_wstring(conds) + L" IF).");
    }
    while (!ctx.stack.empty() && !ctx.overflow) {
        const Frame& f = ctx.stack.back();
        if (f.kind == Frame::Kind::Group && f.emitted)
            ctx.nodes.push_back({Node::Type::GroupEnd, L"", L""});
        ctx.stack.pop_back();
    }

    filesSeen = std::move(ctx.filesSeen);
    return std::move(ctx.nodes);
}

const std::vector<Node>& LoadCached() {
    std::wstring rootPath = CanonicalPath(Services::SupportedSitesFile());
    std::wstring lang = CurrentLangCode();

    const auto stampAll = [](const std::vector<std::wstring>& files,
                             std::vector<FileStamp>& out) {
        out.clear();
        out.reserve(files.size());
        for (const std::wstring& f : files) {
            FileStamp stamp;  // an absent file stamps as {-1, -1}
            StampFile(f, stamp);
            out.push_back(stamp);
        }
    };

    // Re-stamp last time's included set, or just the root on the very first call. A
    // genuinely new include is still picked up, because adding one necessarily edited
    // a file already in the set.
    std::vector<std::wstring> toStamp = g_cache.files;
    if (toStamp.empty()) toStamp.push_back(rootPath);
    std::vector<FileStamp> nowStamps;
    stampAll(toStamp, nowStamps);

    if (g_cache.valid && g_cache.path == rootPath && g_cache.lang == lang &&
        nowStamps == g_cache.stamps)
        return g_cache.nodes;

    std::vector<std::wstring> filesSeen;
    g_cache.nodes = ParseTree(rootPath, filesSeen);
    if (filesSeen.empty()) filesSeen.push_back(rootPath);  // always stamp something
    stampAll(filesSeen, g_cache.stamps);
    g_cache.files = std::move(filesSeen);
    g_cache.path = std::move(rootPath);
    g_cache.lang = std::move(lang);
    g_cache.valid = true;
    return g_cache.nodes;
}

}  // namespace

std::vector<std::wstring> PopulateMenu(HMENU menu, UINT baseCmdId) {
    const std::vector<Node>& nodes = LoadCached();

    std::vector<std::wstring> links;
    links.reserve(nodes.size());

    // A submenu is appended to its parent on GroupEnd, at which point we know whether
    // it is empty and should be grayed. Every created submenu is always attached, so
    // destroying the root frees the whole tree.
    struct OpenGroup {
        HMENU menu;
        std::wstring title;
    };
    std::vector<HMENU> stack{menu};
    std::vector<OpenGroup> open;
    int inlinedDepth = 0;  // groups beyond kMaxGroupDepth render inline
    bool truncated = false;

    const auto attachGroup = [&stack](const OpenGroup& group) {
        UINT flags = MF_POPUP;
        if (GetMenuItemCount(group.menu) == 0) flags |= MF_GRAYED;
        AppendMenuW(stack.back(), flags, reinterpret_cast<UINT_PTR>(group.menu),
                    EscapeMenuText(group.title).c_str());
    };

    for (const Node& node : nodes) {
        HMENU target = stack.back();

        switch (node.type) {
            case Node::Type::Separator: AppendMenuW(target, MF_SEPARATOR, 0, nullptr); break;

            case Node::Type::Text:
                AppendMenuW(target, MF_STRING | MF_GRAYED, 0,
                            EscapeMenuText(node.text).c_str());
                break;

            case Node::Type::Link:
                if (links.size() >= kMaxLinkItems) {
                    truncated = true;
                    break;
                }
                AppendMenuW(target, MF_STRING, baseCmdId + static_cast<UINT>(links.size()),
                            EscapeMenuText(node.text).c_str());
                links.push_back(node.link);
                break;

            case Node::Type::GroupBegin:
                if (static_cast<int>(open.size()) >= kMaxGroupDepth) {
                    // Too deep: render the contents inline, with the title as a grayed
                    // heading so nothing is silently lost.
                    ++inlinedDepth;
                    AppendMenuW(target, MF_STRING | MF_GRAYED, 0,
                                EscapeMenuText(node.text).c_str());
                    break;
                }
                open.push_back({CreatePopupMenu(), node.text});
                stack.push_back(open.back().menu);
                break;

            case Node::Type::GroupEnd: {
                if (inlinedDepth > 0) {
                    --inlinedDepth;
                    break;
                }
                if (open.empty()) break;  // the parser guarantees balance; be safe
                const OpenGroup group = open.back();
                open.pop_back();
                stack.pop_back();
                attachGroup(group);
                break;
            }
        }
        if (truncated) break;
    }

    // If we stopped early at the link cap, attach any still-open submenus so they are
    // visible and owned by the root menu.
    while (!open.empty()) {
        const OpenGroup group = open.back();
        open.pop_back();
        stack.pop_back();
        attachGroup(group);
    }

    if (truncated)
        LOGW(L"Supported sites: link count exceeded " + std::to_wstring(kMaxLinkItems) +
             L"; extra entries dropped.");
    return links;
}

}  // namespace SupportedSites
