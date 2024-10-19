#include "main.h"
#include "enumerator.h"
#include "argparse.h"
#include "analyze.h"

void ShowBanner()
{
	WriteRedText(L"       wWWWw               wWWWw");
	WriteYellowText(L" vVVVv (___) wWWWw         (___)  vVVVv");
	WriteYellowText(L" (___)  ~Y~  (___)  vVVVv   ~Y~   (___)");
	WriteYellowText(L"  ~Y~   \\|    ~Y~   (___)    |/    ~Y~");
	WriteYellowText(L"  \\|   \\ |/   \\| /  \\~Y~/   \\|    \\ |/");
	WriteGreenText(L" \\|// \\|// \\|/// \\|//  \\|// \\|///  \\|//");
	WriteGreenText(L" ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");

	std::wcout << L"TypeLibWalker - find suitable TypeLibs for TypeLib Hijacking" << std::endl;

	std::wcout << L"CICADA8 Research" << std::endl;
}

void ShowHelp()
{
	ShowBanner();
	std::wcout << L"[ARGS]" << std::endl;
	std::wcout << L"\t-h/--help <- shows this message" << std::endl;
	std::wcout << L"\t--from <CLSID> <- analyze CLSIDs from this clsid" << std::endl;
	std::wcout << L"\t--target <CLSID> <- analyze one target clsid" << std::endl;
}


int wmain(int argc, wchar_t* argv[])
{
	setlocale(LC_ALL, "");

	if (cmdOptionExists(argv, argv + argc, L"-h") || cmdOptionExists(argv, argv + argc, L"--help"))
	{
		ShowHelp();
		return 0;
	}

	ShowBanner();

	Sleep(1000);

	std::wstring targetClsid;
	if (cmdOptionExists(argv, argv + argc, L"--target"))
	{
		targetClsid = getCmdOption(argv, argv + argc, L"--target");
	}

	std::wstring startFromClsid;
	if (cmdOptionExists(argv, argv + argc, L"--from"))
	{
		startFromClsid = getCmdOption(argv, argv + argc, L"--from");
	}

	std::vector<std::wstring> clsidList;
	if (targetClsid.empty())
	{
		std::wcout << L"[+] Analyzing all CLSIDs" << std::endl;
		clsidList = EnumerateCLSID();
	}
	else
	{
		std::wcout << L"[+] Analyzing CLSID: " << targetClsid << std::endl;
		clsidList.push_back(targetClsid);
	}

	CoInitialize(NULL);
	std::wcout << "[+] Total CLSID: " << clsidList.size() << std::endl;

	auto it = clsidList.begin();
	if (!startFromClsid.empty()) {
		it = std::find(clsidList.begin(), clsidList.end(), startFromClsid);
		if (it == clsidList.end()) {
			std::wcerr << L"[-] Specified CLSID not found in the list: " << startFromClsid << std::endl;
			return 1;
		}
		else
		{
			++it; // --from + 1
		}
	}

	for (; it != clsidList.end(); it++)
	{
		AnalyzeCLSID(*it);
	}

	CoUninitialize();


	return 0;
}