// SPDX-FileCopyrightText: Copyright 2019 yuzu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <QtConcurrent/QtConcurrent>
#include "common/settings.h"
#include "core/core.h"
#include "core/internal_network/network_interface.h"
#include "suyu/configuration/configure_network.h"
#include "suyu/nextendo_account_dialog.h"
#include "ui_configure_network.h"

ConfigureNetwork::ConfigureNetwork(const Core::System& system_, QWidget* parent)
    : QWidget(parent), ui(std::make_unique<Ui::ConfigureNetwork>()), system{system_} {
    ui->setupUi(this);
    connect(ui->open_nextendo_account, &QPushButton::clicked, this, [this] {
        auto* dialog = new NextendoAccountDialog(this);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->show();
    });
    connect(ui->enable_nextendo, &QCheckBox::toggled, this, [this](bool enabled) {
        const bool can_edit = !system.IsPoweredOn() && enabled;
        ui->nextendo_server_ip->setEnabled(can_edit);
        ui->nextendo_nat_ip->setEnabled(can_edit);
    });

    ui->network_interface->addItem(tr("None"));
    for (const auto& iface : Network::GetAvailableNetworkInterfaces()) {
        ui->network_interface->addItem(QString::fromStdString(iface.name));
    }

    this->SetConfiguration();
}

ConfigureNetwork::~ConfigureNetwork() = default;

void ConfigureNetwork::ApplyConfiguration() {
    Settings::values.network_interface = ui->network_interface->currentText().toStdString();
    Settings::values.network_replacement_host =
        ui->network_replacement_host->text().trimmed().toStdString();
    Settings::values.enable_nextendo = ui->enable_nextendo->isChecked();
    Settings::values.nextendo_server_ip = ui->nextendo_server_ip->text().trimmed().toStdString();
    Settings::values.nextendo_nat_ip = ui->nextendo_nat_ip->text().trimmed().toStdString();
}

void ConfigureNetwork::changeEvent(QEvent* event) {
    if (event->type() == QEvent::LanguageChange) {
        RetranslateUI();
    }

    QWidget::changeEvent(event);
}

void ConfigureNetwork::RetranslateUI() {
    ui->retranslateUi(this);
}

void ConfigureNetwork::SetConfiguration() {
    const bool runtime_lock = !system.IsPoweredOn();

    const std::string& network_interface = Settings::values.network_interface.GetValue();

    ui->network_interface->setCurrentText(QString::fromStdString(network_interface));
    ui->network_interface->setEnabled(runtime_lock);

    ui->network_replacement_host->setText(
        QString::fromStdString(Settings::values.network_replacement_host.GetValue()));
    ui->network_replacement_host->setEnabled(runtime_lock);

    const bool nextendo_enabled = Settings::values.enable_nextendo.GetValue();
    ui->enable_nextendo->setChecked(nextendo_enabled);
    ui->enable_nextendo->setEnabled(runtime_lock);
    ui->nextendo_server_ip->setText(
        QString::fromStdString(Settings::values.nextendo_server_ip.GetValue()));
    ui->nextendo_server_ip->setEnabled(runtime_lock && nextendo_enabled);
    ui->nextendo_nat_ip->setText(
        QString::fromStdString(Settings::values.nextendo_nat_ip.GetValue()));
    ui->nextendo_nat_ip->setEnabled(runtime_lock && nextendo_enabled);
}
