#include <windows.h>
#include <iostream>
#include <string>
#include <fcntl.h> 
#include <io.h>

using namespace std;

// Hàm Ghi Registry (Giữ nguyên)
void SetRegistryValue(HKEY hKeyRoot, LPCWSTR subKey, LPCWSTR valueName, LPCWSTR data) {
    HKEY hKey;
    LSTATUS status = RegCreateKeyExW(hKeyRoot, subKey, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
        NULL, &hKey, NULL);
    if (status == ERROR_SUCCESS) {
        RegSetValueExW(hKey, valueName, 0, REG_SZ,
            (BYTE*)data, (wcslen(data) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }
}

int main() {
    _setmode(_fileno(stdout), _O_U16TEXT);

    wcout << L"=== TOOL HACK MENU CHUOT PHAI (.MP3) ===" << endl;

   
    wstring basePath = L"Software\\Classes\\SystemFileAssociations\\.mp3\\shell\\HackMP3";

    // BƯỚC 1: Tạo dòng chữ hiện trên Menu
    wcout << L"[1] Dang them Menu..." << endl;
    SetRegistryValue(HKEY_CURRENT_USER, basePath.c_str(), NULL, L">> XEM LOI BAI HAT (NOTEPAD) <<");

    // BƯỚC 2: Gán lệnh mở Notepad
    wstring commandPath = basePath + L"\\command";

    wcout << L"[2] Dang gan lenh chay..." << endl;
    // Vẫn dùng Notepad để mở file nhạc
    SetRegistryValue(HKEY_CURRENT_USER, commandPath.c_str(), NULL, L"notepad.exe \"%1\"");

    wcout << L"\n[XONG] Hay ra ngoai Desktop, chuot phai vao 1 file .MP3 bat ky!" << endl;

    // --- DỌN DẸP ---
    wcout << L"\nNhan Enter de xoa bo (Rollback)...";
    getchar();

    RegDeleteKeyW(HKEY_CURRENT_USER, commandPath.c_str());
    RegDeleteKeyW(HKEY_CURRENT_USER, basePath.c_str());
    wcout << L"[CLEAN] Da xoa dau vet." << endl;

    return 0;
}