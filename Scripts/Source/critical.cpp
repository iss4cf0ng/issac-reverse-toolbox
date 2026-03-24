#include <iostream>
#include <string>
#include <tchar.h>
#include <windows.h>

typedef LONG NTSTATUS;
#ifndef NTAPI
#define NTAPI __stdcall
#endif

typedef NTSTATUS (NTAPI *pNtSetInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
);

bool SetDebugPrivilege(bool enable) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) 
    {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) 
    {
        CloseHandle(hToken);
        return false;
    }

    bool result = (GetLastError() == ERROR_SUCCESS);
    CloseHandle(hToken);
    return result;
}

void SetCriticalStatus(DWORD pid, BOOL enable) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;

    pNtSetInformationProcess NtSetInformationProcess = 
        (pNtSetInformationProcess)GetProcAddress(hNtdll, "NtSetInformationProcess");

    if (!NtSetInformationProcess) return;

    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process. Error: %lu\n", GetLastError());
        return;
    }

    ULONG isCritical = enable ? 1 : 0; // 1: enable, 0: disable
    ULONG processInfoClass = 29;       // 0x1D = ProcessBreakOnTermination

    NTSTATUS status = NtSetInformationProcess(
        hProcess,
        processInfoClass,
        &isCritical,
        sizeof(ULONG)
    );

    if (status == 0) {
        printf("[+] Success! Process %lu is now %s\n", pid, enable ? "CRITICAL" : "NORMAL");
    } else {
        printf("[-] Failed. NTSTATUS: 0x%X (Check if running as Admin)\n", status);
    }

    CloseHandle(hProcess);
}

int _tmain(int argc, _TCHAR* argv[]) 
{
    if (argc < 3) 
    {
        std::wcout << L"Usage: " << argv[0] << L" <PID> <0|1>" << std::endl;
        return 1;
    }

    DWORD pid = atoi(argv[1]);
    BOOL enable = atoi(argv[2]);

    if (!SetDebugPrivilege(true)) 
    {
        std::cerr << "Failed to enable SeDebugPrivilege. Please run as Administrator!" << std::endl;
        return 1;
    }

    SetCriticalStatus(pid, enable);
    
    return 0;
}