#include <windows.h>
#include <iostream>
#include <string>
#include <fcntl.h> 
#include <io.h>

using namespace std;

// Hàm hỗ trợ Set Registry (Hỗ trợ ghi vào HKLM)
void HijackApp(LPCWSTR targetApp, LPCWSTR fakeApp) {
    HKEY hKey;
    wstring keyPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";
    keyPath += targetApp; // Ví dụ: ...\notepad.exe

    // Mở hoặc tạo Key tên là "notepad.exe" trong IFEO
    LSTATUS status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
        NULL, &hKey, NULL);

    if (status == ERROR_SUCCESS) {
        // Tạo giá trị "Debugger"
        // Windows mặc định hiểu: Nếu có biến Debugger, hãy chạy cái Debugger này thay vì app chính.
        status = RegSetValueExW(hKey, L"Debugger", 0, REG_SZ,
            (BYTE*)fakeApp, (wcslen(fakeApp) + 1) * sizeof(wchar_t));

        if (status == ERROR_SUCCESS) {
            wcout << L"[THANH CONG] Da hack xong: " << targetApp << endl;
        }
        else {
            wcout << L"[LOI] Khong ghi duoc gia tri Debugger." << endl;
        }
        RegCloseKey(hKey);
    }
    else {
        wcout << L"[LOI] Khong tao duoc Key. (BAN DA CHAY QUYEN ADMIN CHUA?)" << endl;
    }
}

void RestoreApp(LPCWSTR targetApp) {
    wstring keyPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";
    keyPath += targetApp;

    // Xóa Key notepad.exe đi là xong
    LSTATUS status = RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyPath.c_str());
    if (status == ERROR_SUCCESS) {
        wcout << L"[KHOI PHUC] Da tra lai binh thuong cho: " << targetApp << endl;
    }
    else {
        wcout << L"[LOI] Khong xoa duoc Key (Hoac da xoa roi)." << endl;
    }
}

int main() {
    _setmode(_fileno(stdout), _O_U16TEXT);

    wcout << L"=== TOOL LAM LOAN CHUC NANG WINDOWS (IFEO) ===" << endl;
    wcout << L"Luu y: Code nay phai chay bang 'Run as Administrator'" << endl;

    // Kịch bản: Khi mở Notepad -> Sẽ bật Calculator
    LPCWSTR nanNhan = L"notepad.exe";
    LPCWSTR keMaoDanh = L"C:\\Windows\\System32\\calc.exe";
    // Mẹo: Bạn có thể thay calc.exe bằng đường dẫn file mp3 (nhưng phải thông qua trình nghe nhạc)
    // Ví dụ: L"wmplayer.exe \"D:\\Nhac\\BaiHat.mp3\""

    wcout << L"\n[1] Dang tien hanh thay doi Registry..." << endl;
    HijackApp(nanNhan, keMaoDanh);

    wcout << L"\n>>> THU NGHIEM NGAY: Hay mo Start Menu -> Go Notepad -> Enter." << endl;
    wcout << L">>> Ban se thay may tinh (Calculator) hien len thay vi Notepad!" << endl;

    wcout << L"\nNhan Enter de khoi phuc (Rollback)...";
    getchar();

    RestoreApp(nanNhan);

    return 0;
}