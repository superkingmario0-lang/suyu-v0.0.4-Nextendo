// SPDX-FileCopyrightText: Copyright 2026 suyu Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "common/nextendo_account.h"

#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

#include <fmt/format.h>

#include "common/fs/file.h"
#include "common/fs/fs.h"
#include "common/fs/path_util.h"
#include "common/string_util.h"

namespace Common::NextendoAccount {

namespace {

std::mutex g_mutex;
Account g_account;
bool g_loaded{};

std::filesystem::path FilePath() {
    return FS::GetSuyuPath(FS::SuyuPath::ConfigDir) / "nextendo_account.txt";
}

void EnsureLoaded() {
    if (g_loaded) {
        return;
    }
    g_loaded = true;

    const std::string contents = FS::ReadStringFromFile(FilePath(), FS::FileType::TextFile);
    std::vector<std::string> lines;
    Common::SplitString(contents, '\n', lines);
    for (const auto& line : lines) {
        const std::size_t separator = line.find('=');
        if (separator == std::string::npos) {
            continue;
        }
        const std::string key = line.substr(0, separator);
        const std::string value = line.substr(separator + 1);
        if (key == "pid") {
            try {
                g_account.pid = std::stoull(value);
            } catch (...) {
                g_account.pid = 0;
            }
        } else if (key == "username") {
            g_account.username = value;
        } else if (key == "friend_code") {
            g_account.friend_code = value;
        } else if (key == "token") {
            g_account.token = value;
        }
    }

    if (g_account.pid == 0 || g_account.token.empty()) {
        g_account = {};
    }
}

void WriteFile() {
    const auto path = FilePath();
    void(FS::CreateParentDirs(path));
    const std::string contents = fmt::format("pid={}\nusername={}\nfriend_code={}\ntoken={}\n",
                                              g_account.pid, g_account.username,
                                              g_account.friend_code, g_account.token);
    void(FS::WriteStringToFile(path, FS::FileType::TextFile, contents));
#ifndef _WIN32
    std::error_code error;
    std::filesystem::permissions(path, std::filesystem::perms::owner_read |
                                            std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace, error);
#endif
}

} // namespace

Account Get() {
    std::lock_guard lock{g_mutex};
    EnsureLoaded();
    return g_account;
}

bool IsLinked() {
    return Get().pid != 0;
}

u64 GetPid() {
    return Get().pid;
}

std::string GetUsername() {
    return Get().username;
}

std::string GetFriendCode() {
    return Get().friend_code;
}

std::string GetToken() {
    return Get().token;
}

void Save(u64 pid, std::string_view username, std::string_view friend_code,
          std::string_view token) {
    std::lock_guard lock{g_mutex};
    g_loaded = true;
    g_account = {pid, std::string{username}, std::string{friend_code}, std::string{token}};
    WriteFile();
}

void Clear() {
    std::lock_guard lock{g_mutex};
    g_loaded = true;
    g_account = {};
    void(FS::RemoveFile(FilePath()));
}

} // namespace Common::NextendoAccount