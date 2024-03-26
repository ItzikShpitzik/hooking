#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

char DLLPATH[MAX_PATH];
SIZE_T dwSize = sizeof(DLLPATH) + 1;

DWORD FindPID(wchar_t* process);

int main() {
    printf("Enter DLL path: ");
    scanf_s("%s", DLLPATH, sizeof(DLLPATH));

    wchar_t process[] = L"BasicExeFile.exe";
    DWORD pid = FindPID(process);

    printf("PID: %d\n", pid);

    if (pid != 0) {
        HMODULE ker32 = GetModuleHandleA("kernel32.dll");
        void* loadLib = GetProcAddress(ker32, "LoadLibraryA");

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        LPVOID allocatedAddress = VirtualAllocEx(hProcess, NULL, dwSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
        BOOL writeReturn = WriteProcessMemory(hProcess, allocatedAddress, DLLPATH, dwSize, NULL);

        if (writeReturn != 0) {
            HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLib, allocatedAddress, 0, NULL);

            if (hThread == INVALID_HANDLE_VALUE) {
                printf("CreateRemoteThread: INVALID_HANDLE_VALUE.\n");
            }
            else {
                printf("Remote Thread Created.\n");
            }
        }

        CloseHandle(hProcess);
    }

    return 0;
}

DWORD FindPID(wchar_t* process) {
    DWORD pid = 0;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &entry) == TRUE){
        while (Process32Next(snapshot, &entry) == TRUE){
            if (_wcsicmp(entry.szExeFile, process) == 0){
                pid = entry.th32ProcessID;
            }
        }
    }

    CloseHandle(snapshot);
    return pid;
}