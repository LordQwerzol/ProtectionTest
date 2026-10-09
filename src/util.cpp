#include "util.h"

// GUID объявлены явно, чтобы код одинаково собирался и в MSVC, и в MinGW
static const CLSID kClsidNetFwPolicy2 =
    {0xE2B3C97F, 0x6AE1, 0x41AC, {0x81, 0x7A, 0xF6, 0xF9, 0x21, 0x66, 0xD7, 0xDD}};
static const IID kIidINetFwPolicy2 =
    {0x98325047, 0xC671, 0x4174, {0x8D, 0x81, 0xDE, 0xFC, 0xD3, 0xF0, 0x31, 0x86}};


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

static bool isServiceRunning(const wchar_t *serviceName)
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;

    bool running = false;
    SC_HANDLE svc = OpenServiceW(scm, serviceName, SERVICE_QUERY_STATUS);
    if (svc) {
        SERVICE_STATUS_PROCESS ssp{};
        DWORD needed = 0;
        if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                                 reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed))
            running = (ssp.dwCurrentState == SERVICE_RUNNING);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return running;
}

FirewallEnforcement queryFirewallEnforcement()
{
    FirewallEnforcement r;
    r.serviceRunning = isServiceRunning(L"mpssvc");   // служба «Брандмауэр Защитника Windows»
    r.bfeRunning     = isServiceRunning(L"BFE");      // служба базовой фильтрации (WFP)

    const HRESULT hrInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool needUninit = SUCCEEDED(hrInit);

    INetFwPolicy2 *policy = nullptr;
    if (SUCCEEDED(CoCreateInstance(kClsidNetFwPolicy2, nullptr, CLSCTX_INPROC_SERVER,
                                   kIidINetFwPolicy2, reinterpret_cast<void **>(&policy)))) {
        long active = 0;
        policy->get_CurrentProfileTypes(&active);
        r.queried = true;
        r.inboundBlockedByDefault = true;

        for (NET_FW_PROFILE_TYPE2 profile : {NET_FW_PROFILE2_DOMAIN,
                                             NET_FW_PROFILE2_PRIVATE,
                                             NET_FW_PROFILE2_PUBLIC}) {
            if (!(active & profile)) continue;   // смотрим только активные сети

            NET_FW_ACTION action = NET_FW_ACTION_ALLOW;
            if (FAILED(policy->get_DefaultInboundAction(profile, &action))
                || action != NET_FW_ACTION_BLOCK)
                r.inboundBlockedByDefault = false;
        }
        policy->Release();
    }

    if (needUninit) CoUninitialize();
    return r;
}