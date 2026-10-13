#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <netfw.h>
#include <QString>
#include <string>

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

// Тестовое правило брандмауэра, созданное заранее командой netsh.
// Программа его только читает и ничего в брандмауэре не меняет.
struct TestRuleInfo {
    bool    found    = false;   // правило существует
    bool    enabled  = false;   // правило включено
    bool    outbound = false;   // направление — исходящее
    bool    block    = false;   // действие — блокировать
    QString remoteAddress;      // удалённый адрес из правила, например "1.1.1.1"
    quint16 remotePort = 0;     // удалённый порт из правила, например 80
    QString error;
};

TestRuleInfo queryTestRule();