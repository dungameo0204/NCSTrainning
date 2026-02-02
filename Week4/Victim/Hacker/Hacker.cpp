// hacker.cpp
#include <windows.h>
#include <iostream>
#include <string>

using namespace std;

int main() {
    wstring inputPath;
    wcout << L"Keo tha file Victim vao day hoac nhap duong dan: ";

    // Dùng getline để nhận cả dấu cách (nếu đường dẫn có khoảng trắng)
    getline(wcin, inputPath);

    // Xử lý nế đường dẫn bị dính dấu ngoặc kép "" (do copy path)
    if (inputPath.size() >= 2 && inputPath.front() == L'"' && inputPath.back() == L'"') {
        inputPath = inputPath.substr(1, inputPath.size() - 2);
    }

    const wchar_t* filePath = inputPath.c_str();

    // 1. Mở file quyền Đọc + Ghi
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        cout << "Loi: Khong tim thay file victim.exe (phai de cung thu muc)" << endl;
        return 1;
    }

    // 2. Tạo Mapping quyền Read/Write
    HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (!hMap) { cout << "Loi mapping." << endl; return 1; }

    // 3. Map vào RAM
    LPVOID lpBase = MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, 0);
    if (!lpBase) { cout << "Loi view." << endl; return 1; }

    // 4. Tìm NT Header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { cout << "File khong hop le." << endl; return 1; }

    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + dosHeader->e_lfanew);

    // 5. In thông tin cũ
    cout << "Entry Point hien tai: 0x" << hex << ntHeader->OptionalHeader.AddressOfEntryPoint << endl;

    // 6. Nhập địa chỉ hàm Secret (RVA) mà victim.exe đã tiết lộ
    DWORD newEntryPoint;
    cout << "Nhap RVA cua ham Secret (so Hex ma victim da in ra): ";
    cin >> hex >> newEntryPoint;

    // 7. GHI ĐÈ ENTRY POINT !!!
    ntHeader->OptionalHeader.AddressOfEntryPoint = newEntryPoint;

    // 8. Lưu và dọn dẹp
    FlushViewOfFile(lpBase, 0);
    UnmapViewOfFile(lpBase);
    CloseHandle(hMap);
    CloseHandle(hFile);

    cout << "HACK THANH CONG! Hay mo file victim.exe len xem thu." << endl;
    return 0;
}