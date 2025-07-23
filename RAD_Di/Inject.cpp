#include <Windows.h>

#include "pch.h"

#include <cstdio>
#include <cstdlib>

extern "C"
{
	struct date_arg {
		SYSTEMTIME custom_arg;
		bool move_forward;
	};

	ULONGLONG s_PatchTimeTickCount = 0;
	date_arg s_Arg;

	void WINAPI RAD_GetSystemTimeAsFileTime(LPFILETIME outval)
	{
		FILETIME tmp{};
		ULARGE_INTEGER* ul = reinterpret_cast<ULARGE_INTEGER *>(&tmp);

		SystemTimeToFileTime(&s_Arg.custom_arg, &tmp);

		if (s_Arg.move_forward)
			ul->QuadPart += 10000 * (GetTickCount64() - s_PatchTimeTickCount);

		outval->dwHighDateTime = ul->HighPart;
		outval->dwLowDateTime = ul->LowPart;
	}

	void WINAPI RAD_GetSystemTime(LPSYSTEMTIME outval)
	{
		FILETIME time{};
		RAD_GetSystemTimeAsFileTime(&time);
		FileTimeToSystemTime(&time, outval);
	}

	void WINAPI_RAD_GetLocalTime(LPSYSTEMTIME outval)
	{
		SYSTEMTIME tmp{};
		RAD_GetSystemTime(&tmp);

		SystemTimeToTzSpecificLocalTime(NULL, &tmp, outval);
	}


	void patch_func(LPCWSTR libname, LPCSTR funcname, void* func) {
		HMODULE lib = GetModuleHandleW(libname);

		if (lib == NULL)
		{ 
			fwprintf(stderr, L"[RAD] could not load library %s!\n", libname);
			fprintf(stderr, "[RAD] GetLastError(): 0x%lX\n", GetLastError());
			return;
		}

		FARPROC ptr = GetProcAddress(lib, funcname);
		if (ptr == NULL)
		{ 
			fprintf(stderr, "[RAD] could not resolve symbol \"%s\" from library\n", funcname);
			fprintf(stderr, "[RAD] GetLastError(): 0x%lX\n", GetLastError());
			return;
		}

		unsigned char inj[12] = { 0 };

		// movabs rax, func
		// jmp rax

		inj[0] = 0x48;
		inj[1] = 0xB8;
		*((UINT_PTR *)(&inj[2])) = (UINT_PTR)func;
		inj[10] = 0xFF;
		inj[11] = 0xE0;

		SIZE_T written = 0;
		if (!WriteProcessMemory(GetCurrentProcess(), ptr, &inj, 0xC, &written))
		{
			fprintf(stderr, "[RAD] could not patch function \"%s\"\n", funcname);
			fprintf(stderr, "[RAD] GetLastError(): 0x%lX\n", GetLastError());
		}
	}

	void __declspec(dllexport) __stdcall DateInject(date_arg *arg)
	{
		s_Arg = *arg;
		s_PatchTimeTickCount = GetTickCount64();

		patch_func(L"kernel32.dll", "GetLocalTime", &RAD_GetSystemTime);
		patch_func(L"kernel32.dll", "GetSystemTime", &RAD_GetSystemTime);
		patch_func(L"kernel32.dll", "GetSystemTimeAsFileTime", &RAD_GetSystemTimeAsFileTime);
		patch_func(L"kernel32.dll", "GetSystemTimePreciseAsFileTime", &RAD_GetSystemTimeAsFileTime);

		patch_func(L"kernelbase.dll", "GetLocalTime", &RAD_GetSystemTime);
		patch_func(L"kernelbase.dll", "GetSystemTime", &RAD_GetSystemTime);
		patch_func(L"kernelbase.dll", "GetSystemTimeAsFileTime", &RAD_GetSystemTimeAsFileTime);
		patch_func(L"kernelbase.dll", "GetSystemTimePreciseAsFileTime", &RAD_GetSystemTimeAsFileTime);

		patch_func(L"ntdll.dll", "NtQuerySystemTime", &RAD_GetSystemTimeAsFileTime);
	}
}