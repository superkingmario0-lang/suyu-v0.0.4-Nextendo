// SPDX-FileCopyrightText: Copyright 2026 suyu Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <string>
#include <string_view>

#include "common/common_types.h"

namespace Common::NextendoAccount {

struct Account {
    u64 pid{};
    std::string username;
    std::string friend_code;
    std::string token;
};

[[nodiscard]] Account Get();
[[nodiscard]] bool IsLinked();
[[nodiscard]] u64 GetPid();
[[nodiscard]] std::string GetUsername();
[[nodiscard]] std::string GetFriendCode();
[[nodiscard]] std::string GetToken();

void Save(u64 pid, std::string_view username, std::string_view friend_code,
          std::string_view token);
void Clear();

} // namespace Common::NextendoAccount