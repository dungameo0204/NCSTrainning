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

    return 0;
}