#include <windows.h>
#include <iostream>
#include <vector>
#include <iomanip> // Để format in số Hex đẹp
#include <ctime>   // Để in ngày tháng
#include <commdlg.h>

using namespace std;

// Hàm hỗ trợ in ngày tháng từ TimeStamp
void PrintTimeStamp(DWORD timeStamp) {
    time_t rawTime = (time_t)timeStamp;
    char buffer[26];
    ctime_s(buffer, sizeof(buffer), &rawTime);
    wcout << L"\tTime Stamp: " << timeStamp << L" (" << buffer << L")"; // buffer có sẵn xuống dòng
}

// Hàm chính để phân tích
// Hàm chính để phân tích
void AnalyzePE(const wchar_t* filePath) {
    wcout << L"---------------------------------------------------" << endl;
    wcout << L"DANG PHAN TICH FILE: " << filePath << endl;
    wcout << L"---------------------------------------------------" << endl;

    // KHAI BÁO BIẾN Ở ĐẦU ĐỂ TRÁNH LỖI GOTO
    HANDLE hFile = NULL;
    HANDLE hMap = NULL;
    LPVOID lpBase = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;

    // Danh sách tên thư mục (Khai báo luôn ở đây)
    const char* dirNames[] = {
        "Export", "Import", "Resource", "Exception", "Security",
        "Basereloc", "Debug", "Architecture", "GlobalPtr", "TLS",
        "LoadConfig", "BoundImport", "IAT", "DelayImport", "COM"
    };

    // 1. MỞ FILE
    hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { wcout << L"Loi: Khong mo duoc file." << endl; return; }

    // 2. TẠO MAPPING
    hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { wcout << L"Loi: Khong tao duoc Mapping." << endl; CloseHandle(hFile); return; }

    // 3. MAP VÀO RAM
    lpBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!lpBase) { wcout << L"Loi: MapView failed." << endl; CloseHandle(hMap); CloseHandle(hFile); return; }

    // --- BẮT ĐẦU PARSE ---

    // A. DOS HEADER
    pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        wcout << L"[-] File nay khong phai la PE (Thieu MZ)." << endl;
        goto Cleanup; // Giờ thì goto thoải mái vì biến đã khai báo hết ở trên rồi
    }
    wcout << L"[+] DOS HEADER" << endl;
    wcout << L"\tMagic: " << hex << pDosHeader->e_magic << L" (MZ)" << endl;
    wcout << L"\tOffset to NT Header (e_lfanew): 0x" << hex << pDosHeader->e_lfanew << endl;

    // B. NT HEADERS
    pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + pDosHeader->e_lfanew);

    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        wcout << L"[-] Loi: NT Signature khong phai la PE (0x4550)." << endl;
        goto Cleanup;
    }
    wcout << L"\n[+] NT HEADERS" << endl;
    wcout << L"\tSignature: 0x" << hex << pNtHeaders->Signature << L" (PE)" << endl;

    // C. FILE HEADER
    wcout << L"\n[+] FILE HEADER" << endl;
    wcout << L"\tMachine: 0x" << hex << pNtHeaders->FileHeader.Machine << (pNtHeaders->FileHeader.Machine == 0x8664 ? L" (x64)" : L" (x86)") << endl;
    wcout << L"\tNumber of Sections: " << dec << pNtHeaders->FileHeader.NumberOfSections << endl;
    PrintTimeStamp(pNtHeaders->FileHeader.TimeDateStamp);
    wcout << L"\tSize of Optional Header: 0x" << hex << pNtHeaders->FileHeader.SizeOfOptionalHeader << endl;
    wcout << L"\tCharacteristics: 0x" << hex << pNtHeaders->FileHeader.Characteristics << endl;

    // D. OPTIONAL HEADER
    wcout << L"\n[+] OPTIONAL HEADER" << endl;
    wcout << L"\tMagic: 0x" << hex << pNtHeaders->OptionalHeader.Magic << (pNtHeaders->OptionalHeader.Magic == 0x20B ? L" (PE64)" : L" (PE32)") << endl;
    wcout << L"\tAddress Of Entry Point: 0x" << hex << pNtHeaders->OptionalHeader.AddressOfEntryPoint << endl;
    wcout << L"\tImage Base: 0x" << hex << pNtHeaders->OptionalHeader.ImageBase << endl;
    wcout << L"\tSection Alignment: 0x" << hex << pNtHeaders->OptionalHeader.SectionAlignment << endl;
    wcout << L"\tFile Alignment: 0x" << hex << pNtHeaders->OptionalHeader.FileAlignment << endl;

    // E. DATA DIRECTORIES
    wcout << L"\n[+] DATA DIRECTORIES" << endl;

    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        DWORD rva = pNtHeaders->OptionalHeader.DataDirectory[i].VirtualAddress;
        DWORD size = pNtHeaders->OptionalHeader.DataDirectory[i].Size;

        if (size > 0) {
            wcout << L"\tIndex " << setw(2) << i << L" | RVA: 0x" << setw(8) << hex << rva
                << L" | Size: 0x" << setw(6) << size;
            if (i < 15) wcout << L" (" << dirNames[i] << L")";
            wcout << endl;
        }
    }

    // F. SECTION HEADERS
    pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    wcout << L"\n[+] SECTION HEADERS (" << dec << pNtHeaders->FileHeader.NumberOfSections << L" sections)" << endl;
    wcout << L"Name\t\tVirtAddr\tVirtSize\tRawAddr \tRawSize" << endl;
    wcout << L"----\t\t--------\t--------\t--------\t-------" << endl;

    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        char name[9] = { 0 };
        memcpy(name, pSectionHeader->Name, 8);

        wcout << name << L"\t\t"
            << L"0x" << hex << pSectionHeader->VirtualAddress << L"\t"
            << L"0x" << hex << pSectionHeader->Misc.VirtualSize << L"\t"
            << L"0x" << hex << pSectionHeader->PointerToRawData << L"\t"
            << L"0x" << hex << pSectionHeader->SizeOfRawData << endl;

        pSectionHeader++;
    }

Cleanup:
    if (lpBase) UnmapViewOfFile(lpBase);
    if (hMap) CloseHandle(hMap);
    if (hFile) CloseHandle(hFile);
}

// Hàm bật cửa sổ chọn file
bool OpenFileDialog(WCHAR* buffer, DWORD bufferSize) {
    OPENFILENAMEW ofn;       // Cấu trúc dữ liệu cho hộp thoại
    ZeroMemory(&ofn, sizeof(ofn)); // Xóa sạch bộ nhớ để tránh rác

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL; // Không cần cửa sổ cha
    ofn.lpstrFile = buffer; // Nơi lưu đường dẫn file chọn được
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = bufferSize;

    // Bộ lọc file: Chỉ hiện .exe, .dll, .sys hoặc tất cả
    ofn.lpstrFilter = L"PE Files (*.exe;*.dll;*.sys)\0*.exe;*.dll;*.sys\0All Files (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL; // Mặc định mở thư mục nào (NULL = gần nhất)
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

    // Gọi hàm của Windows để hiện cửa sổ
    if (GetOpenFileNameW(&ofn) == TRUE) {
        return true; // Người dùng đã chọn file và bấm OK
    }
    return false; // Người dùng bấm Cancel
}

int wmain(int argc, wchar_t* argv[]) {
    WCHAR filePath[MAX_PATH] = { 0 }; // Biến chứa đường dẫn file

    // Hỏi người dùng muốn làm gì
    wcout << L"Ban co muon chon file PE de phan tich khong? (Y/N): ";
    wchar_t choice;
    wcin >> choice;

    if (choice == 'y' || choice == 'Y') {
        wcout << L"Dang mo hop thoai chon file..." << endl;

        // Gọi hàm mở hộp thoại
        if (OpenFileDialog(filePath, MAX_PATH)) {
            // Nếu chọn được file thì phân tích
            AnalyzePE(filePath);
        }
        else {
            wcout << L"Ban da huy chon file." << endl;
        }
    }
    else {
        // Nếu lười thì dùng mặc định Notepad
        AnalyzePE(L"C:\\Windows\\System32\\notepad.exe");
    }

    system("pause");
    return 0;
}