// SPDX-FileCopyrightText: Copyright 2026 suyu Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <string_view>
#include <unordered_map>

#include "common/common_types.h"

namespace Nextendo::CompatibleTitles {

struct Title {
    std::string_view name;
    std::string_view version;
};

inline const std::unordered_map<u64, Title>& Table() {
    static const std::unordered_map<u64, Title> titles{
        {0x0100152000022000, {"Mario Kart 8 Deluxe", "4.0.0"}},
        {0x01006a800016e000, {"Super Smash Bros. Ultimate", "13.0.5"}},
        {0x0100f8f0000a2000, {"Splatoon 2 (Europe)", "5.5.2"}},
        {0x01003bc0000a0000, {"Splatoon 2 (North America)", "5.5.2"}},
        {0x01003c700009c800, {"Splatoon 2 (Japan)", "5.5.2"}},
        {0x01006f8002326000, {"Animal Crossing: New Horizons", "3.0.3"}},
        {0x0100dca0064a6000, {"Luigi's Mansion 3", "1.4.0"}},
        {0x01009b500007c000, {"ARMS", "5.5.1"}},
        {0x0100bde00862a000, {"Mario Tennis Aces", "3.1.1"}},
        {0x0100c9c00e25c000, {"Mario Golf: Super Rush", "4.0.0"}},
        {0x0100c2500fc20000, {"Splatoon 3", "11.3.0"}},
        {0x01009b90006dc000, {"Super Mario Maker 2", "3.0.3"}},
        {0x010015100b514000, {"Super Mario Bros. Wonder", "1.2.1"}},
        {0x0100277011f1a000, {"Super Mario Bros. 35", "1.0.2"}},
        {0x0100770008dd8000, {"Monster Hunter Generations Ultimate", "1.4.0"}},
        {0x010047700d540000, {"Clubhouse Games: 51 Worldwide Classics", "1.3.0"}},
        {0x0100c6f01c4f8000, {"Metal Gear Solid: Peace Walker", "1.3.0"}},
        {0x01006fd0080b2000, {"Overcooked! 2", "1.0.19"}},
        {0x01006fe013472000, {"Mario Party Superstars", "1.1.1"}},
        {0x0100000000010000, {"Super Mario Odyssey", "1.4.1"}},
        {0x01008f6008c5e000, {"Pokemon Violet", "4.0.0"}},
        {0x0100a3d008c5c000, {"Pokemon Scarlet", "4.0.0"}},
        {0x0100f43008c44000, {"Pokemon Legends: Z-A", "2.0.2"}},
        {0x0100c9a00ece6000, {"Nintendo 64 - Nintendo Classics", "4.2.0"}},
        {0x0100f9f00c696000, {"Crash Team Racing Nitro-Fueled", "1.0.15"}},
        {0x01001b300b9be000, {"Diablo III: Eternal Collection", "2.7.7.92380"}},
        {0x0100a7c01b792000, {"Minecraft Dungeons II", "1.1.1.0"}},
    };
    return titles;
}

} // namespace Nextendo::CompatibleTitles