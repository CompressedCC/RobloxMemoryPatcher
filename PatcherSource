#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip> 

DWORD GetProcessIdByName(const std::wstring& processName) {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName.c_str()) == 0) {
                processId = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return processId;
}

std::string ProtectToString(DWORD protect) {
    switch (protect) {
    case PAGE_EXECUTE: return "EXECUTE";
    case PAGE_EXECUTE_READ: return "EXECUTE_READ";
    case PAGE_EXECUTE_READWRITE: return "EXECUTE_READWRITE";
    case PAGE_EXECUTE_WRITECOPY: return "EXECUTE_WRITECOPY";
    case PAGE_NOACCESS: return "NOACCESS";
    case PAGE_READONLY: return "READONLY";
    case PAGE_READWRITE: return "READWRITE";
    case PAGE_WRITECOPY: return "WRITECOPY";
    default: return "UNKNOWN";
    }
}

std::string StateToString(DWORD state) {
    switch (state) {
    case MEM_COMMIT: return "COMMIT";
    case MEM_FREE: return "FREE";
    case MEM_RESERVE: return "RESERVE";
    default: return "UNKNOWN";
    }
}

std::string TypeToString(DWORD type) {
    switch (type) {
    case MEM_IMAGE: return "IMAGE";
    case MEM_MAPPED: return "MAPPED";
    case MEM_PRIVATE: return "PRIVATE";
    default: return "UNKNOWN";
    }
}

bool ContainsAntiCheatKeywords(const char* buffer, size_t size) {
    std::vector<std::string> keywords = {
        "cheat", "anti", "ban", "kick", "detour", "inject",
        "hook", "exploit", "patch", "Deleter", "deleter",
        "Deleter2", "deleter2" "crash", "RBX::Humanoid", "RBX::Players", "RBX::LocalScript"
    };
    std::string data(buffer, size);

    for (const std::string& keyword : keywords) {
        if (data.find(keyword) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool IsReadableMemory(HANDLE process, LPCVOID addr) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(process, addr, &mbi, sizeof(mbi))) {
        DWORD protect = mbi.Protect;
        return (
            mbi.State == MEM_COMMIT &&
            !(protect & PAGE_NOACCESS) &&
            !(protect & PAGE_GUARD)
            );
    }
    return false;
}


int main() {
    std::wstring targetProcess = L"RobloxPlayerBeta.exe";
    DWORD pid = GetProcessIdByName(targetProcess);
    if (!pid) {
        std::cout << "[-] Process not found.\n";
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProcess) {
        std::cout << "[-] Could not open process.\n";
        return 1;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    std::ofstream outFile("MemoryWithAntiCheatDetection.txt");

    uintptr_t addr = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    uintptr_t maxAddr = (uintptr_t)sysInfo.lpMaximumApplicationAddress;

    while (addr < maxAddr) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi))) {
            if (IsReadableMemory(hProcess, mbi.BaseAddress)) {
                char testData[512] = {};
                SIZE_T bytesRead;

                bool readSuccess = ReadProcessMemory(hProcess, mbi.BaseAddress, testData, sizeof(testData), &bytesRead);
                bool isAntiCheat = readSuccess && ContainsAntiCheatKeywords(testData, bytesRead);

                outFile << "---------------------------------------------\n";
                outFile << "Base Address       : 0x" << std::hex << (uintptr_t)mbi.BaseAddress << "\n";
                outFile << "Allocation Base    : 0x" << std::hex << (uintptr_t)mbi.AllocationBase << "\n";
                outFile << "Region Size        : " << std::dec << mbi.RegionSize << " bytes\n";
                outFile << "State              : " << StateToString(mbi.State) << "\n";
                outFile << "Protection         : " << ProtectToString(mbi.Protect) << "\n";
                outFile << "Allocation Protect : " << ProtectToString(mbi.AllocationProtect) << "\n";
                outFile << "Type               : " << TypeToString(mbi.Type) << "\n";

                if (isAntiCheat) {
                    outFile << "Anti-Cheat Flag    : [!!!] POSSIBLE\n";

                  
                    BYTE patch = 0x28;
                    DWORD oldProtect;
                    if (VirtualProtectEx(hProcess, mbi.BaseAddress, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        SIZE_T bytesWritten;
                        if (WriteProcessMemory(hProcess, mbi.BaseAddress, &patch, sizeof(patch), &bytesWritten)) {
                            outFile << "[+] Wrote 0x28 to address: 0x" << std::hex << (uintptr_t)mbi.BaseAddress << "\n";
                        }
                        else {
                            outFile << "[-] Failed to write to address.\n";
                        }
                        VirtualProtectEx(hProcess, mbi.BaseAddress, sizeof(patch), oldProtect, &oldProtect);
                    }
                    else {
                        outFile << "[-] Failed to change memory protection.\n";
                    }
                }
                else {
                    outFile << "Anti-Cheat Flag    : None\n";
                }
            }
            addr += mbi.RegionSize;
        }
        else {
            addr += 0x1000;
        }
    }

    outFile.close();
    CloseHandle(hProcess);

    std::cout << "[+] Scan complete. Log and patching results written.\n";
    return 0;
}
