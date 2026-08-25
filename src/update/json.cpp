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

#include "update/json.h"

#include <cstdlib>
#include <cstring>

namespace Json {
namespace {

constexpr int kMaxDepth = 32;

class Parser {
public:
    explicit Parser(const std::string& s) : s_(s) {}

    bool Run(Value& out) {
        if (!ParseValue(out, 0)) return false;
        SkipWhitespace();
        return i_ == s_.size();  // reject trailing garbage
    }

private:
    void SkipWhitespace() {
        while (i_ < s_.size()) {
            const char c = s_[i_];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
                ++i_;
            else
                break;
        }
    }

    bool Literal(const char* lit) {
        const size_t n = std::strlen(lit);
        if (s_.compare(i_, n, lit) != 0) return false;
        i_ += n;
        return true;
    }

    bool ParseValue(Value& v, int depth) {
        if (depth > kMaxDepth) return false;
        SkipWhitespace();
        if (i_ >= s_.size()) return false;
        switch (s_[i_]) {
            case '{': return ParseObject(v, depth);
            case '[': return ParseArray(v, depth);
            case '"': v.type = Value::Type::String; return ParseString(v.str);
            case 't':
                v.type = Value::Type::Bool;
                v.boolean = true;
                return Literal("true");
            case 'f':
                v.type = Value::Type::Bool;
                v.boolean = false;
                return Literal("false");
            case 'n': v.type = Value::Type::Null; return Literal("null");
            default: return ParseNumber(v);
        }
    }

    bool ParseObject(Value& v, int depth) {
        v.type = Value::Type::Object;
        v.obj = std::make_shared<Object>();
        ++i_;  // '{'
        SkipWhitespace();
        if (i_ < s_.size() && s_[i_] == '}') {
            ++i_;
            return true;
        }
        for (;;) {
            SkipWhitespace();
            std::string key;
            if (i_ >= s_.size() || s_[i_] != '"' || !ParseString(key)) return false;
            SkipWhitespace();
            if (i_ >= s_.size() || s_[i_] != ':') return false;
            ++i_;
            Value child;
            if (!ParseValue(child, depth + 1)) return false;
            v.obj->emplace_back(std::move(key), std::move(child));
            SkipWhitespace();
            if (i_ >= s_.size()) return false;
            if (s_[i_] == ',') {
                ++i_;
                continue;
            }
            if (s_[i_] == '}') {
                ++i_;
                return true;
            }
            return false;
        }
    }

    bool ParseArray(Value& v, int depth) {
        v.type = Value::Type::Array;
        v.arr = std::make_shared<Array>();
        ++i_;  // '['
        SkipWhitespace();
        if (i_ < s_.size() && s_[i_] == ']') {
            ++i_;
            return true;
        }
        for (;;) {
            Value child;
            if (!ParseValue(child, depth + 1)) return false;
            v.arr->push_back(std::move(child));
            SkipWhitespace();
            if (i_ >= s_.size()) return false;
            if (s_[i_] == ',') {
                ++i_;
                continue;
            }
            if (s_[i_] == ']') {
                ++i_;
                return true;
            }
            return false;
        }
    }

    static void AppendUtf8(std::string& out, unsigned cp) {
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }

    bool ParseHex4(unsigned& out) {
        if (i_ + 4 > s_.size()) return false;
        out = 0;
        for (int k = 0; k < 4; ++k) {
            const char c = s_[i_++];
            unsigned digit;
            if (c >= '0' && c <= '9')
                digit = static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f')
                digit = static_cast<unsigned>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F')
                digit = static_cast<unsigned>(c - 'A' + 10);
            else
                return false;
            out = (out << 4) | digit;
        }
        return true;
    }

    bool ParseString(std::string& out) {
        out.clear();
        ++i_;  // opening quote
        while (i_ < s_.size()) {
            const auto c = static_cast<unsigned char>(s_[i_]);
            if (c == '"') {
                ++i_;
                return true;
            }
            if (c < 0x20) return false;  // a raw control character is invalid JSON
            if (c != '\\') {
                out.push_back(static_cast<char>(c));
                ++i_;
                continue;
            }
            if (++i_ >= s_.size()) return false;
            const char esc = s_[i_++];
            switch (esc) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    unsigned cp;
                    if (!ParseHex4(cp)) return false;
                    if (cp >= 0xD800 && cp <= 0xDBFF) {  // high surrogate
                        if (i_ + 1 < s_.size() && s_[i_] == '\\' && s_[i_ + 1] == 'u') {
                            i_ += 2;
                            unsigned low;
                            if (!ParseHex4(low)) return false;
                            cp = (low >= 0xDC00 && low <= 0xDFFF)
                                     ? 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00)
                                     : 0xFFFD;  // unpaired
                        } else {
                            cp = 0xFFFD;
                        }
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        cp = 0xFFFD;  // lone low surrogate
                    }
                    AppendUtf8(out, cp);
                    break;
                }
                default: return false;
            }
        }
        return false;  // unterminated
    }

    bool ParseNumber(Value& v) {
        const size_t start = i_;
        if (i_ < s_.size() && (s_[i_] == '-' || s_[i_] == '+')) ++i_;
        bool digits = false;
        while (i_ < s_.size() && s_[i_] >= '0' && s_[i_] <= '9') {
            ++i_;
            digits = true;
        }
        if (i_ < s_.size() && s_[i_] == '.') {
            ++i_;
            while (i_ < s_.size() && s_[i_] >= '0' && s_[i_] <= '9') {
                ++i_;
                digits = true;
            }
        }
        if (!digits) return false;
        if (i_ < s_.size() && (s_[i_] == 'e' || s_[i_] == 'E')) {
            ++i_;
            if (i_ < s_.size() && (s_[i_] == '-' || s_[i_] == '+')) ++i_;
            bool expDigits = false;
            while (i_ < s_.size() && s_[i_] >= '0' && s_[i_] <= '9') {
                ++i_;
                expDigits = true;
            }
            if (!expDigits) return false;
        }
        v.type = Value::Type::Number;
        v.number = std::strtod(s_.substr(start, i_ - start).c_str(), nullptr);
        return true;
    }

    const std::string& s_;
    size_t i_ = 0;
};

}  // namespace

const Value* Value::Find(const char* key) const {
    if (type != Type::Object || !obj) return nullptr;
    for (const auto& [k, v] : *obj)
        if (k == key) return &v;
    return nullptr;
}

std::string Value::GetStr(const char* key) const {
    const Value* v = Find(key);
    return (v && v->type == Type::String) ? v->str : std::string();
}

bool Value::GetUInt(const char* key, uint64_t& out) const {
    const Value* v = Find(key);
    if (!v || v->type != Type::Number) return false;
    if (v->number < 0 || v->number > 9007199254740992.0) return false;
    out = static_cast<uint64_t>(v->number);
    return static_cast<double>(out) == v->number;
}

const Array* Value::GetArr(const char* key) const {
    const Value* v = Find(key);
    return (v && v->type == Type::Array && v->arr) ? v->arr.get() : nullptr;
}

bool Parse(const std::string& text, Value& out) {
    return Parser(text).Run(out);
}

}  // namespace Json
