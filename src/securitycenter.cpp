#include "securitycenter.h"

#include <QFileInfo>
#include <QSet>

#ifdef Q_OS_WIN
#include <windows.h>
#include <wbemidl.h>
#endif

namespace {

#ifdef Q_OS_WIN

// Указатель для COM-интерфейсов
template <typename T>
struct ComRef {
    T *p = nullptr;
    ~ComRef() { if (p) p->Release(); }
    T *operator->() const { return p; }
    T **out() { return &p; }
};

// Освобождает BSTR при выходе из области видимости
struct Bstr {
    BSTR s;
    explicit Bstr(const wchar_t *text) : s(SysAllocString(text)) {}
    ~Bstr() { SysFreeString(s); }
};

QString hresultText(const QString &what, HRESULT hr)
{
    return QString("%1 (HRESULT 0x%2)")
        .arg(what)
        .arg(static_cast<quint32>(hr), 8, 16, QChar('0'));
}

// Читает строковое свойство объекта WMI
QString readString(IWbemClassObject *obj, const wchar_t *name)
{
    VARIANT v;
    VariantInit(&v);
    QString result;
    if (SUCCEEDED(obj->Get(name, 0, &v, nullptr, nullptr)) && v.vt == VT_BSTR && v.bstrVal)
        result = QString::fromWCharArray(v.bstrVal);
    VariantClear(&v);
    return result;
}

// Читает целочисленное свойство объекта WMI
quint32 readUInt(IWbemClassObject *obj, const wchar_t *name)
{
    VARIANT v;
    VariantInit(&v);
    quint32 result = 0;
    if (SUCCEEDED(obj->Get(name, 0, &v, nullptr, nullptr))) {
        if (v.vt == VT_I4)       result = static_cast<quint32>(v.lVal);
        else if (v.vt == VT_UI4) result = v.ulVal;
    }
    VariantClear(&v);
    return result;
}

#endif // Q_OS_WIN

} // namespace

SecurityCenterResult querySecurityCenter(ProductKind kind)
{
    SecurityCenterResult res;

#ifndef Q_OS_WIN
    Q_UNUSED(kind);
    res.error = "Центр безопасности доступен только в Windows";
    return res;
#else
    // 1. Инициализация COM. Если Qt уже инициализировал COM в этом потоке,
    //    вернётся S_FALSE или RPC_E_CHANGED_MODE — это не ошибка.
    const HRESULT hrInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool needUninit = SUCCEEDED(hrInit);

    // 2. Параметры безопасности процесса. Можно вызвать только один раз за
    //    время жизни процесса, поэтому RPC_E_TOO_LATE игнорируем — ниже всё
    //    равно настраивается CoSetProxyBlanket для конкретного подключения.
    CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                         RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                         nullptr, EOAC_NONE, nullptr);

    {   // отдельная область, чтобы COM-объекты освободились до CoUninitialize
        ComRef<IWbemLocator> locator;
        HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                      IID_IWbemLocator,
                                      reinterpret_cast<void **>(locator.out()));
        if (FAILED(hr)) {
            res.error = hresultText("Не удалось создать WbemLocator", hr);
        } else {
            // 3. Подключение к пространству имён Центра безопасности
            Bstr ns(L"ROOT\\SecurityCenter2");
            ComRef<IWbemServices> services;
            hr = locator->ConnectServer(ns.s, nullptr, nullptr, nullptr, 0,
                                        nullptr, nullptr, services.out());
            if (FAILED(hr)) {
                res.error = hresultText(
                    "Центр безопасности Windows недоступен (возможно, это Windows Server)", hr);
            } else {
                CoSetProxyBlanket(services.p, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                                  RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                                  nullptr, EOAC_NONE);

                // 4. WQL-запрос
                Bstr lang(L"WQL");
                Bstr query(kind == ProductKind::AntiVirus
                               ? L"SELECT displayName, pathToSignedProductExe, productState FROM AntiVirusProduct"
                               : L"SELECT displayName, pathToSignedProductExe, productState FROM FirewallProduct");

                ComRef<IEnumWbemClassObject> enumerator;
                hr = services->ExecQuery(lang.s, query.s,
                                         WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                         nullptr, enumerator.out());
                if (FAILED(hr)) {
                    res.error = hresultText("Ошибка WMI-запроса", hr);
                } else {
                    res.available = true;

                    // 5. Перебор найденных продуктов
                    while (true) {
                        ComRef<IWbemClassObject> obj;
                        ULONG returned = 0;
                        hr = enumerator->Next(5000, 1, obj.out(), &returned);
                        if (FAILED(hr) || returned == 0)
                            break;

                        SecurityProduct p;
                        p.name     = readString(obj.p, L"displayName");
                        p.exePath  = readString(obj.p, L"pathToSignedProductExe");
                        p.rawState = readUInt(obj.p, L"productState");

                        // productState официально не документирован. Общепринятая
                        // расшифровка (например, 0x061100 у включённого Defender):
                        //   биты 12–15: 1 — защита включена, 0 — выключена
                        //   биты 4–7:   0 — базы актуальны, 1 — устарели
                        p.enabled  = ((p.rawState >> 12) & 0xF) == 1;
                        p.upToDate = ((p.rawState >> 4) & 0xF) == 0;

                        res.products.append(p);
                    }
                    
                    QList<SecurityProduct> unique;
                    QSet<QString> seen;
                    for (const SecurityProduct &p : res.products) {
                        // путь может содержать переменные окружения, например %ProgramFiles%
                        wchar_t expanded[MAX_PATH] = {};
                        ExpandEnvironmentStringsW(reinterpret_cast<const wchar_t *>(p.exePath.utf16()),
                                                expanded, MAX_PATH);
                        const QString path = QString::fromWCharArray(expanded);

                        // «призрак» удалённой версии: обычный путь к файлу, но файла нет.
                        // У Defender путь вида "windowsdefender://", его не проверяем.
                        if (path.contains(":\\") && !QFileInfo::exists(path))
                            continue;

                        // один и тот же продукт, зарегистрированный несколько раз
                        const QString key = path.isEmpty() ? p.name.toLower() : path.toLower();
                        if (seen.contains(key)) {
                            // если хоть одна из копий включена — считаем продукт включённым
                            for (SecurityProduct &u : unique) {
                                const QString uKey = u.exePath.isEmpty() ? u.name.toLower() : u.exePath.toLower();
                                if (uKey == key) {
                                    u.enabled  = u.enabled  || p.enabled;
                                    u.upToDate = u.upToDate || p.upToDate;
                                }
                            }
                            continue;
                        }
                        seen.insert(key);

                        SecurityProduct copy = p;
                        copy.exePath = path;          // храним уже раскрытый путь
                        unique.append(copy);
                    }
                    res.products = unique;
                }
            }
        }
    }

    if (needUninit)
        CoUninitialize();
    return res;
#endif
}

QString describeProduct(const SecurityProduct &p, ProductKind kind)
{
    if (!p.enabled)
        return p.name + " (выкл.)";

    QString s = p.name + " (вкл.";
    if (kind == ProductKind::AntiVirus)
        s += p.upToDate ? ", базы актуальны" : ", базы устарели";
    return s + ")";
}
