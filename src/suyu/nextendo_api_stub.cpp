// SPDX-FileCopyrightText: Copyright 2026 suyu Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "web_service/nextendo_api.h"

namespace WebService::NextendoApi {

bool IsConfigured() {
    return false;
}

LoginResult SignInWithBrowser(const std::function<void(const std::string&)>&) {
    LoginResult result;
    result.error = "Web services are disabled in this build.";
    return result;
}

FriendList GetFriends() {
    FriendList result;
    result.error = "Web services are disabled in this build.";
    return result;
}

std::string AddFriendByCode(const std::string&) {
    return "Web services are disabled in this build.";
}

std::string AcceptFriend(u64) {
    return "Web services are disabled in this build.";
}

std::string DeclineFriend(u64) {
    return "Web services are disabled in this build.";
}

std::string RemoveFriend(u64) {
    return "Web services are disabled in this build.";
}

std::map<std::string, int> GetOnlineCounts() {
    return {};
}

std::string PushPresence(s32, const std::string&, const std::string&) {
    return "Web services are disabled in this build.";
}

} // namespace WebService::NextendoApi