#include "analyze.h"

void SetConsoleColor(WORD color)
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

void WriteRedText(const std::wstring& text)
{
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);

    std::wcout << text << std::endl;

    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

void WriteYellowText(const std::wstring& text)
{
    SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY);

    std::wcout << text << std::endl;

    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

void WriteGreenText(const std::wstring& text)
{
    SetConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);

    std::wcout << text << std::endl;

    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

bool CheckRegistryKeyExists(HKEY hive, const std::wstring& path) {
    HKEY hKey;
    DWORD res = RegOpenKeyEx(hive, path.c_str(), 0, KEY_READ, &hKey);
    if (res == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

bool CheckRegistryWriteCreateAccess(HKEY hive, const std::wstring& path)
{
    HKEY hKey;
    REGSAM samDesired = KEY_WRITE | KEY_CREATE_SUB_KEY;

    DWORD res = RegOpenKeyEx(hive, path.c_str(), 0, samDesired, &hKey);
    if (res == ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return true;
    }

    res = RegCreateKeyEx(hive, path.c_str(), 0, NULL,
        REG_OPTION_VOLATILE, 
        KEY_WRITE | KEY_CREATE_SUB_KEY,
        NULL, &hKey, NULL);

    if (res == ERROR_SUCCESS)
    {
        RegCloseKey(hKey);

        RegDeleteKey(hive, path.c_str());

        return true;
    }
    return false;
}

bool CheckFileWriteAccess(const std::wstring& filePath)
{
    DWORD filePermissions = GENERIC_WRITE;
    HANDLE hFile = CreateFile(filePath.c_str(), filePermissions, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DWORD dw = GetLastError();
        return false;
    }
    else {
        CloseHandle(hFile);
        return true;
    }
}

std::wstring ExpandEnvironmentStringsIfNeeded(const std::wstring& input) {
    if (input.empty()) {
        return input;
    }

    std::vector<wchar_t> expandedPath(MAX_PATH);
    DWORD result = ExpandEnvironmentStrings(input.c_str(), expandedPath.data(), MAX_PATH);
    if (result == 0 || result > MAX_PATH) {
        return input;
    }

    return std::wstring(expandedPath.data());
}

std::wstring GetRegistryStringValue(HKEY hKeyRoot, const std::wstring& subKey) {
    HKEY hKey;
    LONG lResult = RegOpenKeyEx(hKeyRoot, subKey.c_str(), 0, KEY_READ, &hKey);

    if (lResult != ERROR_SUCCESS) {
        return L"";
    }

    DWORD dwType = 0;
    DWORD dwSize = 0;
    lResult = RegQueryValueEx(hKey, nullptr, nullptr, &dwType, nullptr, &dwSize);

    if (lResult != ERROR_SUCCESS || (dwType != REG_SZ && dwType != REG_EXPAND_SZ)) {
        RegCloseKey(hKey);
        return L"";
    }

    std::wstring value(dwSize / sizeof(wchar_t), L'\0');
    lResult = RegQueryValueEx(hKey, nullptr, nullptr, nullptr, reinterpret_cast<LPBYTE>(&value[0]), &dwSize);

    RegCloseKey(hKey);

    if (lResult != ERROR_SUCCESS) {
        return L"";
    }

    if (!value.empty() && value.back() == L'\0') {
        value.pop_back();
    }

    if (dwType == REG_EXPAND_SZ) {
        value = ExpandEnvironmentStringsIfNeeded(value);
    }

    return value;
}

void CheckAndPrintRegistryInfo(HKEY hRootKey, const std::wstring& path, const std::wstring& label)
{
    bool exists = CheckRegistryKeyExists(hRootKey, path.substr(path.find_first_of(L'\\') + 1));
    bool writable = CheckRegistryWriteCreateAccess(hRootKey, path.substr(path.find_first_of(L'\\') + 1));

    std::wstring output = L"\t" + label + (writable ? L"Writable" : L"Non Writable") + L": ";
    output += path + L" (" + (exists ? L"Exists" : L"Does not exist") + L")";

    if (writable)
    {
        WriteRedText(output);
    }
    else
    {
        std::wcout << output << std::endl;
    }
}

VOID AnalyzeCLSID(std::wstring& wsclsid)
{
	
	std::wstring subKey = L"CLSID\\" + wsclsid + L"\\TypeLib";
	std::wstring subKeyVersion = L"CLSID\\" + wsclsid + L"\\Version";

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, subKey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        WCHAR bufferTypeLib[256];
        DWORD bufferSizeTypeLib = sizeof(bufferTypeLib);
        if (RegQueryValueExW(hKey, nullptr, nullptr, nullptr, (LPBYTE)bufferTypeLib, &bufferSizeTypeLib) == ERROR_SUCCESS)
        {
            RegCloseKey(hKey);

            if (RegOpenKeyExW(HKEY_CLASSES_ROOT, subKeyVersion.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
            {
                WCHAR bufferVersion[256];
                DWORD bufferSizeVersion = sizeof(bufferVersion);
                if (RegQueryValueExW(hKey, nullptr, nullptr, nullptr, (LPBYTE)bufferVersion, &bufferSizeVersion) == ERROR_SUCCESS)
                {
                    RegCloseKey(hKey);
                    
                    std::wstring typeLibId(bufferTypeLib);
                    std::wstring version(bufferVersion);
                    
                    std::wcout << L"----------------------------" << std::endl;
                    std::wcout << L"CLSID: " << wsclsid << std::endl;
                    std::wcout << L"TypeLib: " << typeLibId << std::endl;
                    std::wcout << L"Version: " << version << std::endl;

                    std::wstring rootPaths[] = { L"HKCU\\Software\\Classes\\TypeLib\\", L"HKLM\\Software\\Classes\\TypeLib\\" };

                    for (size_t i = 0; i < std::size(rootPaths); ++i)
                    {
                        const auto& root = rootPaths[i];
                        std::wstring typeLibPath = root + bufferTypeLib + L"\\" + bufferVersion;
                        HKEY hRootKey = (root.find(L"HKCU") != std::wstring::npos) ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE;

                        CheckAndPrintRegistryInfo(hRootKey, typeLibPath, L"[" + std::to_wstring(i + 1) + L"] ");

                        std::wstring architectures[] = { L"WIN64", L"WIN32"};
                        for (const auto& arch : architectures)
                        {
                            std::wstring fullPath = typeLibPath + L"\\0\\" + arch;
                            CheckAndPrintRegistryInfo(hRootKey, fullPath, L"\t[" + std::to_wstring(i + 1) + L"." + arch + L"] ");

                            std::wstring diskPath = GetRegistryStringValue(hRootKey, fullPath.substr(fullPath.find_first_of(L'\\') + 1));
             
                            if (!diskPath.empty())
                            {
                                std::wcout << L"\t\t[?] Value: " << diskPath << std::endl;
                                if (CheckFileWriteAccess(diskPath))
                                {
                                    WriteGreenText(L"\t\t[+] Writable path on disk: " + diskPath);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}