// SPDX-FileCopyrightText: Copyright 2026 suyu Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <QDialog>

class QLabel;
class QListWidget;
class QPushButton;
class QTableWidget;

class NextendoAccountDialog final : public QDialog {
public:
    explicit NextendoAccountDialog(QWidget* parent = nullptr);

private:
    void RefreshAccountData();
    void StartSignIn();
    void SignOut();
    void SendFriendRequest();
    void RespondToFriendRequest(bool accept);
    void RemoveSelectedFriend();

    QLabel* account_label{};
    QLabel* message_label{};
    QPushButton* sign_in_button{};
    QPushButton* sign_out_button{};
    QPushButton* refresh_button{};
    QTableWidget* friends_table{};
    QListWidget* requests_list{};
    QTableWidget* population_table{};
    bool request_pending{};
};