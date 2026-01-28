#include <windows.h>
#include <iostream>
#include <fcntl.h> 
#include <io.h>

using namespace std;

// Hàm hỗ trợ: Ghi số nguyên (DWORD) vào Registry
// Khác với bài trước (ghi chuỗi), bài này ta ghi số (0 hoặc 1)
void SetRegistryDWORD(HKEY hKeyRoot, LPCWSTR subKey, LPCWSTR valueName, DWORD data) {
    HKEY hKey;
    LSTATUS status = RegCreateKeyExW(hKeyRoot, subKey, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
        NULL, &hKey, NULL);

    if (status == ERROR_SUCCESS) {
        // REG_DWORD: Kiểu số nguyên 32-bit
        status = RegSetValueExW(hKey, valueName, 0, REG_DWORD,
            (BYTE*)&data, sizeof(data));

        if (status == ERROR_SUCCESS) {
            wcout << L"[OK] Da set " << valueName << L" = " << data << endl;
        }
        else {
            wcout << L"[LOI] Khong the ghi gia tri!" << endl;
        }
        RegCloseKey(hKey);
    }
    else {
        wcout << L"[LOI] Khong mo duoc Key (Can quyen Admin hoac duong dan sai)" << endl;
    }
}

int main() {
    _setmode(_fileno(stdout), _O_U16TEXT);

    // ĐÂY LÀ ĐỊA CHỈ "YẾU HUYỆT" CỦA WINDOWS
    // Nơi chứa các chính sách cấm/cho phép của hệ thống
    LPCWSTR policyKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    LPCWSTR valueName = L"DisableTaskMgr";

    wcout << L"========== TOOL TEST REGISTRY THAT ==========" << endl;
    wcout << L"Chuc nang: Khoa Task Manager cua Windows\n" << endl;

    // --- BƯỚC 1: KHÓA TASK MANAGER ---
    wcout << L"[1] Dang KHOA Task Manager..." << endl;
    // Ghi số 1 vào DisableTaskMgr
    SetRegistryDWORD(HKEY_CURRENT_USER, policyKey, valueName, 1);

    wcout << L"\n>>> THU THACH: Ban hay thu bam Ctrl + Shift + Esc ngay bay gio!" << endl;
    wcout << L">>> Ban se thay thong bao loi cua Windows." << endl;
    wcout << L"\n(Nhan Enter de mo khoa va khoi phuc...)" << endl;

    // Dừng màn hình để bạn trải nghiệm
    getchar();

    // --- BƯỚC 2: MỞ KHÓA (KHÔI PHỤC) ---
    wcout << L"[2] Dang MO KHOA Task Manager..." << endl;
    // Ghi số 0 (Enable) hoặc Xóa value đi cũng được
    SetRegistryDWORD(HKEY_CURRENT_USER, policyKey, valueName, 0);

    wcout << L"\n[XONG] Da khoi phuc. Ban co the mo lai Task Manager binh thuong." << endl;

    // Xóa luôn cái Value rác để dọn dẹp (Optional)
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, policyKey, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, valueName);
        RegCloseKey(hKey);
        wcout << L"[CLEAN] Da xoa dau vet trong Registry." << endl;
    }

    wcout << L"Nhan Enter de thoat...";
    getchar();
    return 0;
}