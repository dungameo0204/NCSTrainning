#include <iostream>
#include "PeReader.h"

int main() {
    PeReader reader;
    // Thử trỏ vào chính file .exe của chương trình này hoặc notepad.exe
    std::wstring target = L"C:\\Windows\\System32\\notepad.exe";

    PeStatus status = reader.LoadFile(target);

    if (status == PeStatus::OK) {
        std::wcout << L"Successfully loaded: " << target << std::endl;
        std::wcout << L"Architecture: " << (reader.Is64Bit() ? L"x64" : L"x86") << std::endl;

        auto fileHeader = reader.GetFileHeader();
        if (fileHeader) {
            std::cout << "Machine: 0x" << std::hex << fileHeader->Machine << std::endl;
            std::cout << "Number of Sections: " << std::dec << fileHeader->NumberOfSections << std::endl;
        }
    }
    else {
        std::wcout << L"Failed to load. Error code: " << (int)status << std::endl;
    }

    if (status == PeStatus::OK) {
        // ... (In thông tin header cũ) ...

        // [MỚI] In danh sách Section
        std::wcout << L"\n--- SECTION TABLE ---" << std::endl;
        const auto& sections = reader.GetSections();
        for (const auto& sec : sections) {
            printf("Name: %-8s | RVA: %08X | Size: %08X | Raw: %08X\n",
                sec.name, sec.virtualAddress, sec.virtualSize, sec.rawAddress);
        }

        // [MỚI] Test thử hàm chuyển đổi RVA
        // Lấy EntryPoint RVA từ header
        DWORD entryPointRva = 0;
        if (reader.Is64Bit()) entryPointRva = reader.GetNtHeader64()->OptionalHeader.AddressOfEntryPoint;
        else entryPointRva = reader.GetNtHeader32()->OptionalHeader.AddressOfEntryPoint;

        DWORD entryPointOffset = reader.RvaToFileOffset(entryPointRva);
        printf("\nEntryPoint RVA: %08X -> File Offset: %08X\n", entryPointRva, entryPointOffset);
    }
	system("pause");
    return 0;
}