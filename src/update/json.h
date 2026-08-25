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
#include <memory>
#include <string>
#include <utility>
#include <vector>

// A small, strict JSON reader.
//
// The manifest is signature-verified before it reaches this code, so this is not a
// trust boundary — but a real parser (rather than key scanning) is what makes
// correct handling of nesting, escapes and unexpected shapes possible, and it fails
// cleanly on anything malformed.
namespace Json {

struct Value;
using Object = std::vector<std::pair<std::string, Value>>;
using Array = std::vector<Value>;

struct Value {
    enum class Type { Null, Bool, Number, String, Array, Object };

    Type type = Type::Null;
    bool boolean = false;
    double number = 0;
    std::string str;
    std::shared_ptr<Array> arr;
    std::shared_ptr<Object> obj;

    const Value* Find(const char* key) const;
    std::string GetStr(const char* key) const;

    // Manifest sizes are byte counts; a double carries them exactly well past any
    // plausible file size (2^53), and this rejects negatives and non-integers.
    bool GetUInt(const char* key, uint64_t& out) const;

    const Array* GetArr(const char* key) const;
};

// Parse `text` into `out`. Returns false on malformed input, excessive nesting,
// or trailing garbage.
bool Parse(const std::string& text, Value& out);

}  // namespace Json
