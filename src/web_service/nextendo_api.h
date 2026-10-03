// SPDX-FileCopyrightText: Copyright 2026 suyu Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <functional>
#include <map>
#include <string>
#include <vector>

#include "common/common_types.h"

namespace WebService::NextendoApi {

struct LoginResult {
    bool ok{};
    u64 pid{};
    std::string username;
    std::string friend_code;
    std::string token;
    std::string error;
};

struct Friend {
    u64 pid{};
    std::string username;
    std::string friend_code;
    s32 presence_status{};
    std::string app_name;
};

struct FriendList {
    bool ok{};
    std::string error;
    std::vector<Friend> friends;
    std::vector<Friend> requests;
};

[[nodiscard]] bool IsConfigured();
[[nodiscard]] LoginResult SignInWithBrowser(
    const std::function<void(const std::string&)>& open_url);
[[nodiscard]] FriendList GetFriends();
[[nodiscard]] std::string AddFriendByCode(const std::string& friend_code);
[[nodiscard]] std::string AcceptFriend(u64 pid);
[[nodiscard]] std::string DeclineFriend(u64 pid);
[[nodiscard]] std::string RemoveFriend(u64 pid);
[[nodiscard]] std::map<std::string, int> GetOnlineCounts();
[[nodiscard]] std::string PushPresence(s32 status, const std::string& app_id = {},
                                       const std::string& app_name = {});

} // namespace WebService::NextendoApi