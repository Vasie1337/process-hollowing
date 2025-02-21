#pragma once

#include <Windows.h>
#include <vector>
#include <string>
#include <optional>

class ProcessHollowing {
public:
    struct ProcessInfo {
        LPVOID pebAddress;
        LPVOID imageBaseAddress;
    };

    ProcessHollowing(const std::vector<BYTE>& peBytes, const std::string& targetPath);
    bool Execute();

private:
    struct HandleGuard {
        HANDLE m_handle;
        HandleGuard(HANDLE h);
        ~HandleGuard();
    };

    std::vector<BYTE> m_peBytes;
    std::string m_targetProcessPath;
    PROCESS_INFORMATION m_processInfo{};
    STARTUPINFOA m_startupInfo{};

    bool CreateSuspendedProcess();
    std::optional<ProcessInfo> GetProcessAddressInfo();
    DWORD GetTargetSubsystem(LPVOID imageBaseAddress);
    bool IsValidPE() const;
    DWORD GetSourceSubsystem() const;
    bool HasRelocation() const;
    IMAGE_DATA_DIRECTORY GetRelocAddress() const;
    bool RunPE64();
    bool RunPEReloc64();
    void CleanupProcess(bool terminate);
}; 