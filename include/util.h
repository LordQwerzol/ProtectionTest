#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <netfw.h>
#include <QString>

// Состояние встроенного брандмауэра Windows
struct FirewallStatus {
    bool    queried    = false;   // удалось ли вообще получить данные
    bool    domain     = false;
    bool    privateNet = false;
    bool    publicNet  = false;
    long    activeProfiles = 0;   // битовая маска NET_FW_PROFILE2_*
    QString error;
};

// Запрос через INetFwPolicy2 для проверки встроенного брандмауэра Windows
FirewallStatus queryWindowsFirewall();