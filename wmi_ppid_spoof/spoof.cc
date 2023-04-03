#define _WIN32_DCOM
#include <Windows.h>
#include <stdio.h>
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

// https://learn.microsoft.com/en-us/windows/win32/wmisdk/example--calling-a-provider-method

#define warn(x, y) printf("%s : 0x%08X\n", x, y)

#define CLASSNAME L"Win32_Process"
#define METHODNAME L"Create"

#define CMD L"cmd.exe /k whoami /all"

int main(void)
{
    HRESULT             hr = S_OK;
    IWbemLocator        *pLoc = NULL;
    IWbemServices       *pSvc = NULL;
    IWbemClassObject    *pClass = NULL;
    IWbemClassObject    *pMethod = NULL;
    IWbemClassObject    *pClassInstance = NULL;
    VARIANT             varCommand, varResult;
    IWbemClassObject    *pOutParams = NULL;

    // initialize variants
    VariantInit(&varCommand);
    VariantInit(&varResult);

    // initialize COM
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (!SUCCEEDED(hr)) {
        warn("CoInitializeEx fail", hr);
        return 0;
    }

    // CoInitializeSecurity called by default

    // initialize WMI instance
    hr = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&pLoc)
    );
    if (!SUCCEEDED(hr)) {
        warn("CoCreateInstance fail", hr);
        goto out;
    }

    // connect to local WMI root namespace
    // and obtain pointer pSvc to make IWbemServices calls.
    hr = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc
    );
    if (!SUCCEEDED(hr)) {
        warn("IWbemLocator::ConnectServer fail", hr);
        goto out;
    }

    // Set IWbemServices security so the WMI service can impersonate us
    hr = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx 
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx 
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities 
    );
    if (!SUCCEEDED(hr)) {
        warn("CoSetProxyBlanket fail", hr);
        goto out;
    }

    // set up to call the Win32_Process::Create method

    // get Win32_Process class
    hr = pSvc->GetObject(_bstr_t(CLASSNAME), 0, NULL, &pClass, NULL);
    if (!SUCCEEDED(hr)) {
        warn("IWbemServices::GetObject fail", hr);
        goto out;
    }

    // get Create method
    hr = pClass->GetMethod(_bstr_t(METHODNAME), 0, &pMethod, NULL);
    if (!SUCCEEDED(hr)) {
        warn("IWbemServices::GetMethod fail", hr);
        goto out;
    }

    // spawn an instance of the class
    hr = pMethod->SpawnInstance(0, &pClassInstance);
    if (!SUCCEEDED(hr)) {
        warn("Win32_Process::Create::SpawnInstance fail", hr);
        goto out;
    }

    // set up commandline to call
    varCommand.vt = VT_BSTR;
    varCommand.bstrVal = _bstr_t(CMD);

    // store value
    hr = pClassInstance->Put(L"CommandLine", 0, &varCommand, 0);
    if (!SUCCEEDED(hr)) {
        warn("IWbemClassObject::Put fail", hr);
        goto out;
    }
    wprintf(L"The command is: %s\n", V_BSTR(&varCommand));

    // Execute Method
    hr = pSvc->ExecMethod(
        _bstr_t(CLASSNAME),
        _bstr_t(METHODNAME),
        0,
        NULL,
        pClassInstance,
        &pOutParams,
        NULL
    );
    if (!SUCCEEDED(hr)) {
        warn("IWbemService::ExecMethod fail", hr);
        goto out;
    }

    hr = pOutParams->Get(_bstr_t(L"ReturnValue"), 0, &varResult, NULL, 0);
    if (!SUCCEEDED(hr)) {
        warn("IWbemClassObject::Get fail", hr);
        puts("No output available");
    }
    else 
        wprintf(L"The output status is: %s\n", varResult.iVal);
    
out:
    if (pClass)
        pClass->Release();
    if (pClassInstance)
        pClassInstance->Release();
    if (pMethod)
        pMethod->Release();
    if (pOutParams)
        pOutParams->Release();
    if (pLoc)
        pLoc->Release();
    if (pSvc)
        pSvc->Release();

    VariantClear(&varCommand);
    VariantClear(&varResult);
    CoUninitialize();
    return 0;
}
