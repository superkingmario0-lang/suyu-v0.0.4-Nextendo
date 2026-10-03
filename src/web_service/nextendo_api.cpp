// SPDX-FileCopyrightText: Copyright 2026 suyu Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "web_service/nextendo_api.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <fmt/format.h>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "common/nextendo_account.h"
#include "common/string_util.h"

#if __has_include("nextendo_secrets.h")
#include "nextendo_secrets.h"
#else
namespace WebService::NextendoApi {
constexpr const char* AppClientId = "";
}
#endif

namespace WebService::NextendoApi {

namespace {

constexpr std::string_view BaseUrl = "https://nextendo.network";
constexpr auto RequestTimeout = std::chrono::seconds{15};
std::mutex g_http_mutex;

struct OAuthCallback {
    std::mutex mutex;
    std::condition_variable ready;
    bool received{};
    std::string code;
    std::string state;
    std::string error;
};

std::string RandomUrlSafe(std::size_t size) {
    std::vector<u8> bytes(size);
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        return {};
    }
    static constexpr std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string result;
    result.reserve((bytes.size() * 4 + 2) / 3);
    u32 buffer{};
    int bits{};
    for (const u8 byte : bytes) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            result += alphabet[(buffer >> bits) & 0x3f];
        }
    }
    if (bits != 0) {
        result += alphabet[(buffer << (6 - bits)) & 0x3f];
    }
    return result;
}

std::string Base64UrlSha256(const std::string& value) {
    std::array<u8, SHA256_DIGEST_LENGTH> digest{};
    SHA256(reinterpret_cast<const u8*>(value.data()), value.size(), digest.data());
    std::string encoded;
    encoded.reserve(43);
    static constexpr std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    u32 buffer{};
    int bits{};
    for (const u8 byte : digest) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            encoded += alphabet[(buffer >> bits) & 0x3f];
        }
    }
    if (bits != 0) {
        encoded += alphabet[(buffer << (6 - bits)) & 0x3f];
    }
    return encoded;
}

std::string UrlEncode(std::string_view value) {
    std::string result;
    for (const unsigned char byte : value) {
        if ((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
            (byte >= '0' && byte <= '9') || byte == '-' || byte == '_' || byte == '.' ||
            byte == '~') {
            result += static_cast<char>(byte);
        } else {
            result += fmt::format("%{:02X}", byte);
        }
    }
    return result;
}

void ConfigureClient(httplib::Client& client) {
    client.set_connection_timeout(RequestTimeout);
    client.set_read_timeout(RequestTimeout);
    client.set_write_timeout(RequestTimeout);
    client.set_follow_location(false);
#ifdef __linux__
    constexpr std::array ca_paths{"/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem",
                                  "/etc/pki/tls/certs/ca-bundle.crt"};
    for (const char* path : ca_paths) {
        if (std::filesystem::exists(path)) {
            client.set_ca_cert_path(path);
            break;
        }
    }
#endif
}

httplib::Headers Headers(const std::string& token = {}) {
    httplib::Headers headers{{"User-Agent", "suyu"}};
    if (IsConfigured()) {
        headers.emplace("X-Nextendo-Client-Id", AppClientId);
    }
    if (!token.empty()) {
        headers.emplace("Authorization", "Bearer " + token);
    }
    return headers;
}

httplib::Result Request(std::string_view method, const std::string& path,
                        const std::string& body = {}, const std::string& token = {}) {
    static httplib::Client client{std::string{BaseUrl}};
    std::lock_guard lock{g_http_mutex};
    ConfigureClient(client);
    if (method == "GET") {
        return client.Get(path, Headers(token));
    }
    return client.Post(path, Headers(token), body, "application/json");
}

std::string ErrorMessage(const httplib::Result& response, std::string fallback) {
    if (!response) {
        return "Could not connect to the Nextendo account server.";
    }
    try {
        const auto json = nlohmann::json::parse(response->body);
        if (json.contains("error") && json["error"].is_string()) {
            return json["error"].get<std::string>();
        }
        if (json.contains("message") && json["message"].is_string()) {
            return json["message"].get<std::string>();
        }
    } catch (const nlohmann::json::exception&) {
    }
    return fmt::format("{} (HTTP {})", fallback, response->status);
}

Friend ParseFriend(const nlohmann::json& json) {
    Friend entry;
    entry.pid = json.value("pid", u64{});
    entry.username = json.value("name", json.value("username", std::string{}));
    entry.friend_code = json.value("friend_code", std::string{});
    if (const auto presence = json.find("presence"); presence != json.end() && presence->is_object()) {
        entry.presence_status = presence->value("status", s32{});
        entry.app_name = presence->value("app_name", std::string{});
    }
    return entry;
}

std::string PostPid(const std::string& path, u64 pid) {
    if (!IsConfigured()) {
        return "This build has no Nextendo client ID.";
    }
    const auto response = Request("POST", path, nlohmann::json{{"pid", pid}}.dump(),
                                  Common::NextendoAccount::GetToken());
    if (!response || response->status != 200) {
        return ErrorMessage(response, "Nextendo rejected the request.");
    }
    return {};
}

} // namespace

bool IsConfigured() {
    return AppClientId != nullptr && *AppClientId != '\0';
}

LoginResult SignInWithBrowser(const std::function<void(const std::string&)>& open_url) {
    LoginResult result;
    if (!IsConfigured()) {
        result.error = "This build has no Nextendo client ID. Configure the NEXTENDO_CLIENT_ID "
                       "GitHub Actions secret and rebuild.";
        return result;
    }

    const std::string verifier = RandomUrlSafe(48);
    const std::string state = RandomUrlSafe(24);
    if (verifier.empty() || state.empty()) {
        result.error = "Could not create secure sign-in state.";
        return result;
    }

    OAuthCallback callback;
    httplib::Server server;
    server.Get("/callback", [&callback](const httplib::Request& request,
                                         httplib::Response& response) {
        {
            std::lock_guard lock{callback.mutex};
            callback.code = request.get_param_value("code");
            callback.state = request.get_param_value("state");
            callback.error = request.get_param_value("error");
            callback.received = true;
        }
        response.set_content("<!doctype html><title>Nextendo</title><p>Sign-in complete. "
                             "Return to suyu.</p>",
                             "text/html; charset=utf-8");
        callback.ready.notify_all();
    });

    const int port = server.bind_to_any_port("127.0.0.1");
    if (port < 0) {
        result.error = "Could not start the local sign-in callback.";
        return result;
    }
    std::thread listener{[&server] { static_cast<void>(server.listen_after_bind()); }};
    const std::string redirect_uri = fmt::format("http://127.0.0.1:{}/callback", port);
    const std::string challenge = Base64UrlSha256(verifier);
    const std::string authorize_url =
        fmt::format("{}/api/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&"
                    "scope=identity+friends+presence&app=suyu&state={}&code_challenge={}&"
                    "code_challenge_method=S256",
                    BaseUrl, UrlEncode(AppClientId), UrlEncode(redirect_uri), state, challenge);
    open_url(authorize_url);

    {
        std::unique_lock lock{callback.mutex};
        callback.ready.wait_for(lock, std::chrono::minutes{5},
                                [&callback] { return callback.received; });
    }
    server.stop();
    listener.join();

    if (!callback.received) {
        result.error = "Sign-in timed out.";
        return result;
    }
    if (!callback.error.empty()) {
        result.error = callback.error == "access_denied" ? "Sign-in was cancelled."
                                                          : callback.error;
        return result;
    }
    if (callback.code.empty() || callback.state != state) {
        result.error = "The sign-in callback was invalid. Please try again.";
        return result;
    }

    httplib::Client client{std::string{BaseUrl}};
    ConfigureClient(client);
    const httplib::Params form{{"grant_type", "authorization_code"},
                               {"code", callback.code},
                               {"client_id", AppClientId},
                               {"redirect_uri", redirect_uri},
                               {"code_verifier", verifier}};
    const auto response = client.Post("/api/oauth/token", Headers(), form);
    if (!response || response->status != 200) {
        result.error = ErrorMessage(response, "Could not complete Nextendo sign-in.");
        return result;
    }
    try {
        const auto json = nlohmann::json::parse(response->body);
        const auto& account = json.at("account");
        result.pid = account.at("pid").get<u64>();
        result.username = account.value("username", std::string{});
        result.friend_code = account.value("friend_code", std::string{});
        result.token = json.value("nex_token", std::string{});
        result.ok = result.pid != 0 && !result.token.empty();
        if (!result.ok) {
            result.error = "The account server returned incomplete sign-in details.";
        }
    } catch (const nlohmann::json::exception&) {
        result.error = "The account server returned an unexpected response.";
    }
    return result;
}

FriendList GetFriends() {
    FriendList out;
    if (!IsConfigured()) {
        out.error = "This build has no Nextendo client ID.";
        return out;
    }
    const auto response = Request("GET", "/api/friends", {},
                                  Common::NextendoAccount::GetToken());
    if (!response || response->status != 200) {
        out.error = ErrorMessage(response, "Could not load friends.");
        return out;
    }
    try {
        const auto json = nlohmann::json::parse(response->body);
        for (const auto& entry : json.value("friends", nlohmann::json::array())) {
            out.friends.push_back(ParseFriend(entry));
        }
        for (const auto& entry : json.value("requests", nlohmann::json::array())) {
            out.requests.push_back(ParseFriend(entry));
        }
        out.ok = true;
    } catch (const nlohmann::json::exception&) {
        out.error = "The account server returned an invalid friends list.";
    }
    return out;
}

std::string AddFriendByCode(const std::string& friend_code) {
    if (!IsConfigured()) {
        return "This build has no Nextendo client ID.";
    }
    const auto response = Request("POST", "/api/friends",
                                  nlohmann::json{{"friend_code", friend_code}}.dump(),
                                  Common::NextendoAccount::GetToken());
    if (!response || response->status != 200) {
        return ErrorMessage(response, "Could not send friend request.");
    }
    return {};
}

std::string AcceptFriend(u64 pid) {
    return PostPid("/api/friends/accept", pid);
}

std::string DeclineFriend(u64 pid) {
    return PostPid("/api/friends/decline", pid);
}

std::string RemoveFriend(u64 pid) {
    return PostPid("/api/friends/remove", pid);
}

std::map<std::string, int> GetOnlineCounts() {
    std::map<std::string, int> counts;
    if (!IsConfigured()) {
        return counts;
    }
    const auto response = Request("GET", "/api/online-counts");
    if (!response || response->status != 200) {
        return counts;
    }
    try {
        const auto json = nlohmann::json::parse(response->body);
        const auto items = json.find("counts");
        if (items == json.end() || !items->is_object()) {
            return counts;
        }
        for (const auto& [title_id, count] : items->items()) {
            if (count.is_number_integer() && count.get<int>() >= 0) {
                std::string normalized_id = title_id;
                std::transform(normalized_id.begin(), normalized_id.end(), normalized_id.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                counts.emplace(std::move(normalized_id), count.get<int>());
            }
        }
    } catch (const nlohmann::json::exception&) {
    }
    return counts;
}

std::string PushPresence(s32 status, const std::string& app_id, const std::string& app_name) {
    if (!IsConfigured()) {
        return "This build has no Nextendo client ID.";
    }
    const auto response = Request(
        "POST", "/api/presence",
        nlohmann::json{{"status", status}, {"app_field", ""}, {"app_id", app_id},
                       {"app_name", app_name}, {"app_detail", ""}}
            .dump(),
        Common::NextendoAccount::GetToken());
    if (!response || response->status != 200) {
        return ErrorMessage(response, "Could not update online status.");
    }
    return {};
}

} // namespace WebService::NextendoApi