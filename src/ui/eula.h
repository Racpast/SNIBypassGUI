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
#include <windows.h>

namespace Eula {

// If the agreement has not been accepted, show it modally in the current language.
// Returns true if the user agreed (and the acceptance has been persisted), false if
// they declined or the text could not be loaded. An already-accepted agreement
// returns true immediately without showing anything.
bool EnsureAccepted(HINSTANCE instance);

// Show the agreement for reading only: no gate, no change to the stored acceptance.
void ShowForReading(HINSTANCE instance);

}  // namespace Eula
