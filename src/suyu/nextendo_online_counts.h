// SPDX-FileCopyrightText: Copyright 2026 suyu Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <functional>
#include <map>
#include <optional>
#include <string>

#include "common/common_types.h"

class QObject;

namespace Nextendo::OnlineCounts {

using CountMap = std::map<std::string, int>;

void Start(QObject* owner, std::function<void()> updated);
void Update(CountMap counts);
[[nodiscard]] std::optional<int> For(u64 program_id);

} // namespace Nextendo::OnlineCounts