#include "util.h"

// GUID объявлены явно, чтобы код одинаково собирался и в MSVC, и в MinGW
static const CLSID kClsidNetFwPolicy2 =
    {0xE2B3C97F, 0x6AE1, 0x41AC, {0x81, 0x7A, 0xF6, 0xF9, 0x21, 0x66, 0xD7, 0xDD}};
static const IID kIidINetFwPolicy2 =
    {0x98325047, 0xC671, 0x4174, {0x8D, 0x81, 0xDE, 0xFC, 0xD3, 0xF0, 0x31, 0x86}};

// Имя правила, которое заранее создаётся командой netsh
const wchar_t *const kCheckRuleName = L"ProtectionTest Block";

FirewallStatus queryWindowsFirewall()
{
    FirewallStatus st;

    // Qt обычно уже инициализировал COM в главном потоке — это не ошибка
    const HRESULT hrInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool needUninit = SUCCEEDED(hrInit);

    INetFwPolicy2 *policy = nullptr;
    const HRESULT hr = CoCreateInstance(kClsidNetFwPolicy2, nullptr, CLSCTX_INPROC_SERVER,
                                        kIidINetFwPolicy2, reinterpret_cast<void**>(&policy));
    if (FAILED(hr)) {
        st.error = QString("Не удалось получить доступ к брандмауэру (HRESULT 0x%1)")
                       .arg(static_cast<quint32>(hr), 8, 16, QChar('0'));
    } else {
        VARIANT_BOOL enabled = VARIANT_FALSE;
        if (SUCCEEDED(policy->get_FirewallEnabled(NET_FW_PROFILE2_DOMAIN, &enabled)))
            st.domain = (enabled == VARIANT_TRUE);
        if (SUCCEEDED(policy->get_FirewallEnabled(NET_FW_PROFILE2_PRIVATE, &enabled)))
            st.privateNet = (enabled == VARIANT_TRUE);
        if (SUCCEEDED(policy->get_FirewallEnabled(NET_FW_PROFILE2_PUBLIC, &enabled)))
            st.publicNet = (enabled == VARIANT_TRUE);
        policy->get_CurrentProfileTypes(&st.activeProfiles);

        st.queried = true;
        policy->Release();
    }

    if (needUninit)
        CoUninitialize();
    return st;
}

TestRuleInfo queryTestRule()
{
    TestRuleInfo info;

    const HRESULT hrInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool needUninit = SUCCEEDED(hrInit);

    INetFwPolicy2 *policy = nullptr;
    INetFwRules   *rules  = nullptr;
    INetFwRule    *rule   = nullptr;

    HRESULT hr = CoCreateInstance(kClsidNetFwPolicy2, nullptr, CLSCTX_INPROC_SERVER,
                                  kIidINetFwPolicy2, reinterpret_cast<void **>(&policy));
    if (FAILED(hr)) {
        info.error = "нет доступа к брандмауэру Windows";
    } else if (FAILED(policy->get_Rules(&rules))) {
        info.error = "не удалось получить список правил";
    } else {
        BSTR name = SysAllocString(kCheckRuleName);
        hr = rules->Item(name, &rule);
        SysFreeString(name);

        if (FAILED(hr) || !rule) {
            info.error = "тестовое правило не найдено";
        } else {
            info.found = true;

            VARIANT_BOOL enabled = VARIANT_FALSE;
            rule->get_Enabled(&enabled);
            info.enabled = (enabled == VARIANT_TRUE);

            NET_FW_RULE_DIRECTION dir = NET_FW_RULE_DIR_IN;
            rule->get_Direction(&dir);
            info.outbound = (dir == NET_FW_RULE_DIR_OUT);

            NET_FW_ACTION action = NET_FW_ACTION_ALLOW;
            rule->get_Action(&action);
            info.block = (action == NET_FW_ACTION_BLOCK);

            // RemoteAddresses приходит в виде "1.1.1.1/255.255.255.255" —
            // берём только сам адрес (первый, если их несколько)
            BSTR addr = nullptr;
            if (SUCCEEDED(rule->get_RemoteAddresses(&addr)) && addr) {
                std::wstring a(addr);
                a = a.substr(0, a.find_first_of(L"/,"));
                if (a != L"*")
                    info.remoteAddress = QString::fromWCharArray(a.c_str());
                SysFreeString(addr);
            }

            // RemotePorts — "80"; диапазоны и списки для теста не подходят
            BSTR ports = nullptr;
            if (SUCCEEDED(rule->get_RemotePorts(&ports)) && ports) {
                const std::wstring p(ports);
                if (!p.empty() && p.find_first_not_of(L"0123456789") == std::wstring::npos)
                    info.remotePort = static_cast<quint16>(std::wcstol(p.c_str(), nullptr, 10));
                SysFreeString(ports);
            }
        }
    }

    if (rule)   rule->Release();
    if (rules)  rules->Release();
    if (policy) policy->Release();
    if (needUninit) CoUninitialize();
    return info;
}