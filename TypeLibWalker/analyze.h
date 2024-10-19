#pragma once
#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <utility>
#include <atlbase.h>
#include <Psapi.h>

VOID AnalyzeCLSID(std::wstring& clsid);
void WriteGreenText(const std::wstring& text);
void WriteRedText(const std::wstring& text);
void WriteYellowText(const std::wstring& text);