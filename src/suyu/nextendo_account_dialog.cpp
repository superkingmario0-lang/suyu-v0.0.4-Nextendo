// SPDX-FileCopyrightText: Copyright 2026 suyu Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "suyu/nextendo_account_dialog.h"

#include <map>
#include <string>
#include <utility>

#include <QCoreApplication>
#include <QDesktopServices>
#include <QFutureWatcher>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QMetaObject>
#include <QPushButton>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>
#include <QtConcurrent/QtConcurrent>

#include "common/nextendo_account.h"
#include "common/nextendo_compatible_titles.h"
#include "suyu/nextendo_online_counts.h"
#include "web_service/nextendo_api.h"

namespace {

struct AccountData {
    WebService::NextendoApi::FriendList friends;
    std::map<std::string, int> counts;
};

QString PresenceText(const WebService::NextendoApi::Friend& entry) {
    switch (entry.presence_status) {
    case 1:
        return QObject::tr("Online");
    case 2:
        return QObject::tr("In game");
    default:
        return QObject::tr("Offline");
    }
}

QString GameName(const std::string& title_id) {
    try {
        const auto numeric_id = std::stoull(title_id, nullptr, 16);
        if (const auto entry = Nextendo::CompatibleTitles::Table().find(numeric_id);
            entry != Nextendo::CompatibleTitles::Table().end()) {
            return QObject::tr(entry->second.name.data());
        }
    } catch (...) {
    }
    return QString::fromStdString(title_id);
}

} // namespace

NextendoAccountDialog::NextendoAccountDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle(tr("Nextendo Network"));
    setMinimumSize(600, 500);

    auto* root = new QVBoxLayout(this);
    account_label = new QLabel(this);
    account_label->setWordWrap(true);
    root->addWidget(account_label);

    auto* account_actions = new QHBoxLayout;
    sign_in_button = new QPushButton(tr("Sign in to Nextendo"), this);
    sign_out_button = new QPushButton(tr("Sign out"), this);
    refresh_button = new QPushButton(tr("Refresh"), this);
    account_actions->addWidget(sign_in_button);
    account_actions->addWidget(sign_out_button);
    account_actions->addStretch();
    account_actions->addWidget(refresh_button);
    root->addLayout(account_actions);

    auto* tabs = new QTabWidget(this);
    auto* friends_page = new QWidget(tabs);
    auto* friends_layout = new QVBoxLayout(friends_page);
    friends_table = new QTableWidget(0, 3, friends_page);
    friends_table->setHorizontalHeaderLabels({tr("Friend"), tr("Status"), tr("Playing")});
    friends_table->horizontalHeader()->setStretchLastSection(true);
    friends_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    friends_layout->addWidget(friends_table, 1);

    auto* request_label = new QLabel(tr("Friend requests"), friends_page);
    friends_layout->addWidget(request_label);
    requests_list = new QListWidget(friends_page);
    friends_layout->addWidget(requests_list);

    auto* friend_actions = new QHBoxLayout;
    auto* add_friend_button = new QPushButton(tr("Add by friend code"), friends_page);
    auto* accept_button = new QPushButton(tr("Accept"), friends_page);
    auto* decline_button = new QPushButton(tr("Decline"), friends_page);
    auto* remove_friend_button = new QPushButton(tr("Remove friend"), friends_page);
    friend_actions->addWidget(add_friend_button);
    friend_actions->addStretch();
    friend_actions->addWidget(remove_friend_button);
    friend_actions->addWidget(accept_button);
    friend_actions->addWidget(decline_button);
    friends_layout->addLayout(friend_actions);
    tabs->addTab(friends_page, tr("Friends"));

    auto* population_page = new QWidget(tabs);
    auto* population_layout = new QVBoxLayout(population_page);
    auto* population_description = new QLabel(
        tr("Live player counts reported by Nextendo's supported game servers."), population_page);
    population_description->setWordWrap(true);
    population_layout->addWidget(population_description);
    population_table = new QTableWidget(0, 2, population_page);
    population_table->setHorizontalHeaderLabels({tr("Game"), tr("Players online")});
    population_table->horizontalHeader()->setStretchLastSection(true);
    population_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    population_layout->addWidget(population_table, 1);
    tabs->addTab(population_page, tr("Population"));
    root->addWidget(tabs, 1);

    message_label = new QLabel(this);
    message_label->setWordWrap(true);
    root->addWidget(message_label);

    connect(sign_in_button, &QPushButton::clicked, this, [this] { StartSignIn(); });
    connect(sign_out_button, &QPushButton::clicked, this, [this] { SignOut(); });
    connect(refresh_button, &QPushButton::clicked, this, [this] { RefreshAccountData(); });
    connect(add_friend_button, &QPushButton::clicked, this,
            [this] { SendFriendRequest(); });
    connect(accept_button, &QPushButton::clicked, this,
            [this] { RespondToFriendRequest(true); });
    connect(decline_button, &QPushButton::clicked, this,
            [this] { RespondToFriendRequest(false); });
        connect(remove_friend_button, &QPushButton::clicked, this,
            [this] { RemoveSelectedFriend(); });

    if (!WebService::NextendoApi::IsConfigured()) {
        sign_in_button->setEnabled(false);
        message_label->setText(tr("Account login is unavailable in this build. The build must be "
                                  "configured with a Nextendo client ID."));
    }
    RefreshAccountData();
        auto* friend_refresh_timer = new QTimer(this);
        friend_refresh_timer->setInterval(20'000);
        connect(friend_refresh_timer, &QTimer::timeout, this,
            [this] { RefreshAccountData(); });
        friend_refresh_timer->start();
}

void NextendoAccountDialog::RefreshAccountData() {
    const auto account = Common::NextendoAccount::Get();
    const bool linked = account.pid != 0 && !account.token.empty();
    sign_in_button->setEnabled(!linked && WebService::NextendoApi::IsConfigured() &&
                               !request_pending);
    sign_out_button->setEnabled(linked && !request_pending);
    refresh_button->setEnabled(linked && !request_pending);

    if (!linked) {
        account_label->setText(tr("Not signed in to a Nextendo account."));
        friends_table->setRowCount(0);
        requests_list->clear();
        message_label->setText(WebService::NextendoApi::IsConfigured()
                                   ? QString{}
                                   : tr("Set the NEXTENDO_CLIENT_ID GitHub Actions secret and "
                                        "rebuild to enable account services."));
        return;
    }

    account_label->setText(tr("Signed in as %1\nFriend code: %2")
                               .arg(QString::fromStdString(account.username),
                                    QString::fromStdString(account.friend_code)));
    if (request_pending) {
        return;
    }

    request_pending = true;
    refresh_button->setEnabled(false);
    message_label->setText(tr("Refreshing friends and population..."));
    auto* watcher = new QFutureWatcher<AccountData>(this);
    connect(watcher, &QFutureWatcher<AccountData>::finished, this, [this, watcher] {
        request_pending = false;
        const AccountData data = watcher->result();
        watcher->deleteLater();

        sign_out_button->setEnabled(true);
        refresh_button->setEnabled(true);
        sign_in_button->setEnabled(false);
        friends_table->setRowCount(0);
        requests_list->clear();

        if (!data.friends.ok) {
            message_label->setText(QString::fromStdString(data.friends.error));
        } else {
            message_label->clear();
            for (const auto& entry : data.friends.friends) {
                const int row = friends_table->rowCount();
                friends_table->insertRow(row);
                const QString friend_name = entry.username.empty()
                                                ? QString::fromStdString(entry.friend_code)
                                                : QString::fromStdString(entry.username);
                friends_table->setItem(
                    row, 0, new QTableWidgetItem(friend_name));
                friends_table->setItem(row, 1, new QTableWidgetItem(PresenceText(entry)));
                friends_table->setItem(
                    row, 2, new QTableWidgetItem(QString::fromStdString(entry.app_name)));
                friends_table->item(row, 0)->setData(Qt::UserRole,
                                                     QVariant::fromValue<qulonglong>(entry.pid));
            }
            for (const auto& entry : data.friends.requests) {
                auto* item = new QListWidgetItem(
                    QStringLiteral("%1  -  %2")
                        .arg(QString::fromStdString(entry.username),
                             QString::fromStdString(entry.friend_code)),
                    requests_list);
                item->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(entry.pid));
            }
        }

        population_table->setRowCount(0);
        int total{};
        for (const auto& [title_id, count] : data.counts) {
            const int row = population_table->rowCount();
            population_table->insertRow(row);
            auto* title_item = new QTableWidgetItem(GameName(title_id));
            title_item->setToolTip(QString::fromStdString(title_id));
            population_table->setItem(row, 0, title_item);
            population_table->setItem(row, 1, new QTableWidgetItem(QString::number(count)));
            total += count;
        }
        if (data.counts.empty() && WebService::NextendoApi::IsConfigured()) {
            message_label->setText(tr("No live population data was returned."));
        } else if (!data.counts.empty()) {
            message_label->setText(tr("Players online across reported games: %1").arg(total));
        }
        Nextendo::OnlineCounts::Update(data.counts);
    });
    watcher->setFuture(QtConcurrent::run([] {
        return AccountData{WebService::NextendoApi::GetFriends(),
                           WebService::NextendoApi::GetOnlineCounts()};
    }));
}

void NextendoAccountDialog::StartSignIn() {
    if (request_pending || !WebService::NextendoApi::IsConfigured()) {
        return;
    }
    request_pending = true;
    sign_in_button->setEnabled(false);
    message_label->setText(tr("Waiting for Nextendo account sign-in in your browser..."));

    auto* watcher = new QFutureWatcher<WebService::NextendoApi::LoginResult>(this);
    connect(watcher, &QFutureWatcher<WebService::NextendoApi::LoginResult>::finished, this,
            [this, watcher] {
                request_pending = false;
                const auto result = watcher->result();
                watcher->deleteLater();
                if (!result.ok) {
                    message_label->setText(QString::fromStdString(result.error));
                    RefreshAccountData();
                    return;
                }
                Common::NextendoAccount::Save(result.pid, result.username, result.friend_code,
                                              result.token);
                message_label->setText(tr("Nextendo account linked."));
                RefreshAccountData();
            });
    watcher->setFuture(QtConcurrent::run([] {
        return WebService::NextendoApi::SignInWithBrowser([](const std::string& url) {
            QMetaObject::invokeMethod(
                QCoreApplication::instance(),
                [url] { QDesktopServices::openUrl(QUrl(QString::fromStdString(url))); },
                Qt::QueuedConnection);
        });
    }));
}

void NextendoAccountDialog::SignOut() {
    if (request_pending) {
        return;
    }
    request_pending = true;
    sign_out_button->setEnabled(false);
    message_label->setText(tr("Signing out..."));
    auto* watcher = new QFutureWatcher<void>(this);
    connect(watcher, &QFutureWatcher<void>::finished, this, [this, watcher] {
        watcher->deleteLater();
        Common::NextendoAccount::Clear();
        request_pending = false;
        RefreshAccountData();
    });
    watcher->setFuture(QtConcurrent::run([] {
        WebService::NextendoApi::PushPresence(0);
    }));
}

void NextendoAccountDialog::SendFriendRequest() {
    bool accepted{};
    const QString friend_code = QInputDialog::getText(
        this, tr("Add Nextendo Friend"), tr("Friend code:"), QLineEdit::Normal, {}, &accepted);
    if (!accepted || friend_code.trimmed().isEmpty() || request_pending) {
        return;
    }

    request_pending = true;
    const std::string code = friend_code.trimmed().toStdString();
    auto* watcher = new QFutureWatcher<QString>(this);
    connect(watcher, &QFutureWatcher<QString>::finished, this, [this, watcher] {
        const QString error = watcher->result();
        watcher->deleteLater();
        request_pending = false;
        message_label->setText(error.isEmpty() ? tr("Friend request sent.") : error);
        RefreshAccountData();
    });
    watcher->setFuture(QtConcurrent::run([code] {
        return QString::fromStdString(WebService::NextendoApi::AddFriendByCode(code));
    }));
}

void NextendoAccountDialog::RespondToFriendRequest(bool accept) {
    const auto* item = requests_list->currentItem();
    if (!item || request_pending) {
        return;
    }
    const u64 pid = item->data(Qt::UserRole).toULongLong();
    request_pending = true;
    auto* watcher = new QFutureWatcher<QString>(this);
    connect(watcher, &QFutureWatcher<QString>::finished, this, [this, watcher] {
        const QString error = watcher->result();
        watcher->deleteLater();
        request_pending = false;
        message_label->setText(error.isEmpty() ? tr("Friend list updated.") : error);
        RefreshAccountData();
    });
    watcher->setFuture(QtConcurrent::run([pid, accept] {
        const auto error = accept ? WebService::NextendoApi::AcceptFriend(pid)
                                  : WebService::NextendoApi::DeclineFriend(pid);
        return QString::fromStdString(error);
    }));
}

void NextendoAccountDialog::RemoveSelectedFriend() {
    const int row = friends_table->currentRow();
    if (row < 0 || request_pending) {
        return;
    }
    const u64 pid = friends_table->item(row, 0)->data(Qt::UserRole).toULongLong();
    if (pid == 0) {
        return;
    }
    request_pending = true;
    auto* watcher = new QFutureWatcher<QString>(this);
    connect(watcher, &QFutureWatcher<QString>::finished, this, [this, watcher] {
        const QString error = watcher->result();
        watcher->deleteLater();
        request_pending = false;
        message_label->setText(error.isEmpty() ? tr("Friend removed.") : error);
        RefreshAccountData();
    });
    watcher->setFuture(QtConcurrent::run([pid] {
        return QString::fromStdString(WebService::NextendoApi::RemoveFriend(pid));
    }));
}