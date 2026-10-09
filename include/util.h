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

// «Работает ли брандмауэр на самом деле» — только чтение, без изменений
struct FirewallEnforcement {
    bool queried = false;
    bool serviceRunning = false;          // служба mpssvc запущена
    bool bfeRunning = false;              // служба BFE (платформа фильтрации) запущена
    bool inboundBlockedByDefault = false; // входящие по умолчанию блокируются в активных сетях

    bool effective() const {
        return queried && serviceRunning && bfeRunning && inboundBlockedByDefault;
    }
};

FirewallEnforcement queryFirewallEnforcement();