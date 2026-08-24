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
#include <string>

// Text baked into the executable's own resources. Used for content that must be
// readable before any file or network access exists — currently the user
// agreement, which gates the first launch.
namespace EmbeddedText {

// Resource ids of the embedded documents (see app.rc).
enum : int {
    kEulaEnglish = 100,
    kEulaChinese = 101,
};

// Read one embedded UTF-8 document. Returns an empty string if the resource is
// missing. A leading byte-order mark is stripped.
std::string Read(int resourceId);

}  // namespace EmbeddedText
