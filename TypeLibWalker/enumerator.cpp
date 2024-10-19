#include "enumerator.h"

std::vector<std::wstring> EnumerateCLSID()
{
    std::vector<std::wstring> clsidList;
    HKEY hKey;
    LONG nError;

    nError = RegOpenKeyEx(HKEY_CLASSES_ROOT, L"CLSID", 0, KEY_READ, &hKey);
    if (nError == ERROR_SUCCESS)
    {
        DWORD dwIndex = 0;
        WCHAR szName[MAX_PATH];
        DWORD dwNameSize = _countof(szName);
        FILETIME ftLastWriteTime;

        while (RegEnumKeyEx(hKey, dwIndex, szName, &dwNameSize, NULL, NULL, NULL, &ftLastWriteTime) == ERROR_SUCCESS)
        {
            clsidList.push_back(szName);
            dwNameSize = _countof(szName);
            dwIndex++;
        }

        RegCloseKey(hKey);
    }
    else
    {
        std::wcerr << L"Cant open HKEY_CLASSES_ROOT\\CLSID. Error: " << nError << std::endl;
    }

    return clsidList;
}
