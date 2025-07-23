#include <iostream>
#include <filesystem>
#include <Windows.h>
#include "resource.h"
#include "shlwapi.h"

struct date_arg;
typedef void (* init_cb_t)(date_arg *arg);
typedef HMODULE (* libload_cb_t)(LPCWSTR name);
typedef FARPROC (* getprocadr_cb_t)(HMODULE lib, LPCSTR name);

struct date_arg {
	SYSTEMTIME custom_arg;
	bool move_forward;
};

struct init_cb_arg {
    wchar_t inject_dll_path[MAX_PATH + 1];
    libload_cb_t c_LoadLibraryW;
    getprocadr_cb_t c_GetProcAddress;
    char funcname[64 + 1];
    date_arg date_cfg;
};


static void tmain(init_cb_arg *arg) {
    HMODULE lib = arg->c_LoadLibraryW(arg->inject_dll_path);
    if (lib != NULL)
    {
        init_cb_t cb = (init_cb_t)arg->c_GetProcAddress(lib, arg->funcname);
        if (cb != NULL)
            cb(&arg->date_cfg);
    }
}

void print_usage_and_exit() {
    puts("usage: RADCLI.exe <path to program> <year> <month> <day> <hour> <minute> <second> <0/1 = advance time with system clock>\n");
    exit(1);
}

int parse_int_or_exit(LPCWSTR input) {
    int res = _wtoi(input);
    if (errno != 0) print_usage_and_exit();
    return res;
}

bool delete_inject_dll(LPWSTR pathbuf)
{
    if (PathFileExistsW(pathbuf)) {
        if (!DeleteFileW(pathbuf))
        {
            int err = GetLastError();
            printf("%d\n", err);
            return false;
        }
    }

    return true;
}

bool write_inject_dll(LPWSTR pathbuf)
{
    HRSRC rsrc = FindResourceW(GetModuleHandle(NULL), MAKEINTRESOURCEW(IDR_INJDATE), RT_RCDATA);
    if (rsrc == NULL) return false;

    DWORD dll_size = SizeofResource(GetModuleHandle(NULL), rsrc);
    if (!dll_size) return false;

    HGLOBAL globrsrc = LoadResource(GetModuleHandle(NULL), rsrc);
    if (globrsrc == NULL) return false;

    void* raw_dll = LockResource(globrsrc);
    if (!raw_dll) return false;

    DWORD tmp_path_size = GetTempPathW(MAX_PATH, pathbuf);
    if (!tmp_path_size)
        return false;

    if (tmp_path_size + sizeof("\\RAD_Di.dll") * 2 < MAX_PATH)
    {
        wchar_t* backslash = wcsrchr(pathbuf, L'\\');
        if (backslash) *backslash = L'\0';
        wcscat(pathbuf, L"\\RAD_Di.dll");
    }

    if (!delete_inject_dll(pathbuf))
        return false;

    HANDLE tmp_file = CreateFileW(pathbuf, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);
    if (!tmp_file) return false;

    DWORD written = 0;

    BOOL wres = WriteFile(tmp_file, raw_dll, dll_size, &written, NULL);

    CloseHandle(tmp_file);
    return wres && written == dll_size;
}

int main()
{
    // command line stuff
    LPWSTR cmdline = NULL;
    LPWSTR* argv = NULL;
    int argc = 0;
    // target process
    PROCESS_INFORMATION pinfo{};
    STARTUPINFO startup_info{};
    // inject thread
    void *code_memchunk = NULL, *arg_memchunk = NULL;
    HANDLE inject_thread = NULL;
    DWORD inject_thread_id = 0;
    init_cb_arg arg;
    // misc
    HMODULE kernel32 = NULL;
    SIZE_T written = 0;

    memset(&startup_info, 0, sizeof(startup_info));
    memset(&pinfo, 0, sizeof(pinfo));
    startup_info.cb = sizeof(STARTUPINFO);

    cmdline = GetCommandLineW();
    if (cmdline == nullptr)
    {
        DWORD err = GetLastError();
        fprintf(stderr, "could not get command line\n");
        fprintf(stderr, "GetLastError(): 0x%lX\n", err);
        goto free_exit;
    }

    argv = CommandLineToArgvW(cmdline, &argc);
    if (argv == nullptr)
    {
        DWORD err = GetLastError();
        fprintf(stderr, "command line to argv failed\n");
        fprintf(stderr, "GetLastError(): 0x%lX\n", err);
        goto free_exit;
    }

    // RADCLI.exe my_exe (dd mm yyyy hh mm ss) 0/1
    if (argc < 9) print_usage_and_exit();

    if (!PathFileExistsW(argv[1])) {
        fprintf(stderr, "file does not exist\n");
        goto free_exit;
    }

    memset(&arg, 0, sizeof(arg));
    arg.date_cfg.custom_arg.wDay = parse_int_or_exit(argv[2]);
    arg.date_cfg.custom_arg.wMonth = parse_int_or_exit(argv[3]);
    arg.date_cfg.custom_arg.wYear = parse_int_or_exit(argv[4]);
    arg.date_cfg.custom_arg.wHour = parse_int_or_exit(argv[5]);
    arg.date_cfg.custom_arg.wMinute = parse_int_or_exit(argv[6]);
    arg.date_cfg.custom_arg.wSecond = parse_int_or_exit(argv[7]);

    if (wcsncmp(argv[8], L"0", 1) != 0 && wcsncmp(argv[8], L"1", 1) != 0) print_usage_and_exit();

    arg.date_cfg.move_forward = argv[8][0] == L'1';

    puts("Creating process...");

    if (!CreateProcessW(
        argv[1],
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &startup_info,
        &pinfo))
    {
        fprintf(stderr, "could not create process\n");
        fprintf(stderr, "GetLastError(): 0x%lX\n", GetLastError());
        goto free_exit;
    }

    puts("Allocating memory in target process for date injection...");

    code_memchunk = VirtualAllocEx(pinfo.hProcess, NULL, 0x400, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    arg_memchunk = VirtualAllocEx(pinfo.hProcess, NULL, 0x400, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (!code_memchunk || !arg_memchunk) {
        fprintf(stderr, "could not allocate memory for process\n");
        fprintf(stderr, "GetLastError(): 0x%lX\n", GetLastError());
        goto free_exit;
    }

    puts("Setting up parameters for date patching...");

    kernel32 = GetModuleHandleW(L"kernel32.dll");

    if (!kernel32) {
        DWORD err = GetLastError();
        fprintf(stderr, "could not load kernel32.dll\n");
        fprintf(stderr, "GetLastError(): 0x%lX\n", err);
        goto free_exit;
    }

	arg.c_LoadLibraryW = (libload_cb_t)GetProcAddress(kernel32, "LoadLibraryW");
	arg.c_GetProcAddress = (getprocadr_cb_t)GetProcAddress(kernel32, "GetProcAddress");
	strcpy(arg.funcname, "DateInject");

    puts("Writing patcher DLL into temp folder...");

    if (!write_inject_dll(arg.inject_dll_path)) {
        DWORD err = GetLastError();
        fprintf(stderr, "could not write inject dll to temp folder\n");
        fprintf(stderr, "GetLastError(): 0x%lX\n", err);
        goto free_exit;
    }

    wprintf(L"Wrote DLL to \"%s\".\n", arg.inject_dll_path);

    puts("Injecting patch trigger into target process...");

    if (!WriteProcessMemory(pinfo.hProcess, code_memchunk, &tmain, 0x400, &written) ||
        !WriteProcessMemory(pinfo.hProcess, arg_memchunk, &arg, sizeof(arg), &written))
    {
        DWORD err = GetLastError();
        fprintf(stderr, "could not write into target process memory\n");
        fprintf(stderr, "GetLastError(): 0x%lX\n", err);
        goto free_exit;
    }


    puts("Creating thread in target process to install patches...");

    inject_thread = CreateRemoteThread(
        pinfo.hProcess,
        0,
        0,
        (LPTHREAD_START_ROUTINE)code_memchunk,
        arg_memchunk,
        CREATE_SUSPENDED,
        &inject_thread_id);

    if (inject_thread == NULL)
    {
        DWORD err = GetLastError();
        fprintf(stderr, "could not create thread for process\n");
        fprintf(stderr, "GetLastError(): 0x%lX\n", err);
        goto free_exit;
    }

    puts("Waiting for patchwork to complete...");

    // fire off the inject thread and wait for patching to be complete

    ResumeThread(inject_thread);
    if (WaitForSingleObject(inject_thread, INFINITE) == WAIT_OBJECT_0)
    {
		VirtualFreeEx(pinfo.hProcess, arg_memchunk, NULL, MEM_RELEASE);
		VirtualFreeEx(pinfo.hProcess, code_memchunk, NULL, MEM_RELEASE);
		arg_memchunk = NULL;
		code_memchunk = NULL;
		CloseHandle(inject_thread);
		inject_thread = NULL;
    }

    puts("Done! Resuming target process.");

    // resume the main thread of the target program
    ResumeThread(pinfo.hThread);

    // wait for the program to exit
    WaitForSingleObject(pinfo.hProcess, INFINITE);

    GetExitCodeProcess(pinfo.hProcess, &inject_thread_id);
    printf("The target process has exited (exit code: %d [0x%lX]).\n", inject_thread_id, inject_thread_id);

    // final cleanup
    CloseHandle(pinfo.hThread);
    CloseHandle(pinfo.hProcess);
    pinfo.hProcess = NULL;
    pinfo.hThread = NULL;

    if (!delete_inject_dll(arg.inject_dll_path))
    {
        int err = GetLastError();
        fprintf(stderr, "Could not delete temp DLL!\n");
        fprintf(stderr, "GetLastError(): 0x%lX\n", err);
    }
    else
        puts("Removed DLL from temp folder.");


    return 0;

free_exit:
	if (pinfo.hProcess) TerminateProcess(pinfo.hProcess, -1);
	if (code_memchunk) VirtualFreeEx(pinfo.hProcess, code_memchunk, 0, MEM_RELEASE);
	if (arg_memchunk) VirtualFreeEx(pinfo.hProcess, arg_memchunk, 0, MEM_RELEASE);

    if (inject_thread) CloseHandle(inject_thread);
    if (pinfo.hThread) CloseHandle(pinfo.hThread);
    if (pinfo.hProcess) CloseHandle(pinfo.hProcess);

    return 1;
}
