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