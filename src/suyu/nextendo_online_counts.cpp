// SPDX-FileCopyrightText: Copyright 2026 suyu Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "suyu/nextendo_online_counts.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <mutex>

#include <fmt/format.h>
#include <QFutureWatcher>
#include <QtConcurrent/QtConcurrent>
#include <QTimer>

#include "web_service/nextendo_api.h"

namespace Nextendo::OnlineCounts {

namespace {

std::mutex g_counts_mutex;
CountMap g_counts;
std::atomic_bool g_request_pending{};
bool g_started{};

void Refresh(QObject* owner, const std::function<void()>& updated) {
    if (g_request_pending.exchange(true)) {
        return;
    }

    auto* watcher = new QFutureWatcher<CountMap>(owner);
    QObject::connect(watcher, &QFutureWatcher<CountMap>::finished, owner,
                     [watcher, updated] {
                         {
                             Update(watcher->result());
                         }
                         g_request_pending = false;
                         watcher->deleteLater();
                         if (updated) {
                             updated();
                         }
                     });
    watcher->setFuture(QtConcurrent::run(&WebService::NextendoApi::GetOnlineCounts));
}

} // namespace

void Start(QObject* owner, std::function<void()> updated) {
    if (g_started || !owner || !WebService::NextendoApi::IsConfigured()) {
        return;
    }
    g_started = true;

    auto* timer = new QTimer(owner);
    timer->setInterval(5'000);
    QObject::connect(timer, &QTimer::timeout, owner,
                     [owner, updated] { Refresh(owner, updated); });
    timer->start();
    Refresh(owner, updated);
}

void Update(CountMap counts) {
    for (auto& [title_id, count] : counts) {
        std::transform(title_id.begin(), title_id.end(), title_id.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    }
    std::lock_guard lock{g_counts_mutex};
    g_counts = std::move(counts);
}

std::optional<int> For(u64 program_id) {
    const std::string key = fmt::format("{:016x}", program_id);
    std::lock_guard lock{g_counts_mutex};
    const auto iterator = g_counts.find(key);
    if (iterator == g_counts.end()) {
        return std::nullopt;
    }
    return iterator->second;
}

} // namespace Nextendo::OnlineCounts