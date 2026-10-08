#pragma once

#include <QList>
#include <QString>

// Какой класс Центра безопасности Windows опрашивать
enum class ProductKind {
    AntiVirus,   // root\SecurityCenter2 : AntiVirusProduct
    Firewall     // root\SecurityCenter2 : FirewallProduct
};

// Один зарегистрированный в Центре безопасности продукт
struct SecurityProduct {
    QString name;          // displayName, например "Kaspersky Internet Security"
    QString exePath;       // pathToSignedProductExe
    quint32 rawState = 0;  // productState как есть (для журнала/отчёта)
    bool    enabled  = false;  // защита включена
    bool    upToDate = false;  // базы актуальны (для антивирусов)
};

// Результат запроса
struct SecurityCenterResult {
    bool available = false;        // удалось ли подключиться к SecurityCenter2
    QString error;                 // текст ошибки, если available == false
    QList<SecurityProduct> products;

    bool hasEnabled() const {
        for (const auto &p : products)
            if (p.enabled) return true;
        return false;
    }
};

// Синхронный запрос к WMI. 
SecurityCenterResult querySecurityCenter(ProductKind kind);

// Расшифровка при наличинии продукта
QString describeProduct(const SecurityProduct &p, ProductKind kind);
