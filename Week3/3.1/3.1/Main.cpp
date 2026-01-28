#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

using namespace std;

// --- HÀM 1: GHI (WRITE) ---
// Mục đích: Mở (hoặc tạo) Key -> Ghi dữ liệu -> Đóng lại
void WriteToRegistry(LPCWSTR subKey, LPCWSTR valueName, LPCWSTR content) {
    HKEY hKey; // Biến này để chứa "Thẻ bài" (Handle)

    // BƯỚC 1: Xin Windows cấp "Thẻ bài" để mở cửa Key
    // RegCreateKeyExW: Nếu chưa có thì tạo mới, có rồi thì mở ra.
    long status = RegCreateKeyExW(
        HKEY_CURRENT_USER,      // 1. Nhánh gốc (Nhà của User)
        subKey,                 // 2. Địa chỉ phòng (VD: Software\Demo)
        0, NULL,                // 3. (Mặc định, không quan tâm)
        REG_OPTION_NON_VOLATILE,// 4. Lưu xuống ổ cứng (Tắt máy không mất)
        KEY_ALL_ACCESS,         // 5. Xin Full quyền (Đọc, Ghi, Xóa)
        NULL,
        &hKey,                  // 6. [QUAN TRỌNG] Nếu mở được, Windows nhét Thẻ bài vào đây
        NULL
    );

    if (status == ERROR_SUCCESS) {
        // BƯỚC 2: Ghi dữ liệu vào
        // RegSetValueExW: Hàm chuyên để ghi
        RegSetValueExW(
            hKey,               // 1. Đưa Thẻ bài ra để chứng minh quyền
            valueName,          // 2. Tên biến (VD: "MyName")
            0,                  // 3. (Mặc định)
            REG_SZ,             // 4. Kiểu dữ liệu: Chuỗi văn bản (String)
            (BYTE*)content,     // 5. Nội dung cần ghi (Ép kiểu sang Byte thô)
            (wcslen(content) + 1) * 2 // 6. Kích thước (Tính bằng Byte)
        );

        cout << "[GHI] Xong!" << endl;

        // BƯỚC 3: Trả Thẻ bài
        RegCloseKey(hKey);
    }
}

// --- HÀM 2: ĐỌC (READ) ---
void ReadFromRegistry(LPCWSTR subKey, LPCWSTR valueName) {
    HKEY hKey;
    // Mở Key (Chỉ cần quyền Đọc - KEY_QUERY_VALUE)
    if (RegOpenKeyExW(HKEY_CURRENT_USER, subKey, 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {

        wchar_t buffer[255];   // Cái xô để hứng dữ liệu
        DWORD bufferSize = 255 * 2; // Dung tích cái xô (tính bằng Byte)

        // Hứng dữ liệu vào xô
        RegQueryValueExW(hKey, valueName, NULL, NULL, (BYTE*)buffer, &bufferSize);

        wcout << L"[DOC] Gia tri la: " << buffer << endl;

        RegCloseKey(hKey);
    }
    else {
        cout << "[DOC] Loi: Khong tim thay Key!" << endl;
    }
}

void DeleteFromRegistry(LPCWSTR subKey, LPCWSTR valueName) {
    HKEY hKey;

    // BƯỚC 1: Mở Key để xóa
    // [QUAN TRỌNG]: Muốn xóa, bạn phải xin quyền "GHI" (KEY_SET_VALUE)
    // Nếu chỉ xin KEY_READ thì Windows sẽ cấm xóa.
    long status = RegOpenKeyExW(HKEY_CURRENT_USER, subKey, 0, KEY_SET_VALUE, &hKey);

    if (status == ERROR_SUCCESS) {
        // BƯỚC 2: Gọi lệnh xóa
        // RegDeleteValueW: Xóa một giá trị cụ thể
        status = RegDeleteValueW(hKey, valueName);

        if (status == ERROR_SUCCESS) {
            wcout << L"[XOA] Da xoa thanh cong gia tri: " << valueName << endl;
        }
        else {
            wcout << L"[XOA] Loi: Khong xoa duoc (hoac da bi xoa tu truoc)!" << endl;
        }

        // BƯỚC 3: Trả thẻ bài
        RegCloseKey(hKey);
    }
    else {
        wcout << L"[XOA] Loi: Khong tim thay Key de vao xoa!" << endl;
    }
}

int main() {
    // Để in tiếng Việt/Unicode ra màn hình console
    // (Nếu không có dòng này, wcout có thể không hiện gì)
    // Cần thêm header <fcntl.h> và <io.h> nếu code cũ chưa có
    // _setmode(_fileno(stdout), _O_U16TEXT); 

    LPCWSTR myPath = L"Software\\BaiTap3_1";
    LPCWSTR myVar = L"HocSinh";

    wcout << L"--- 1. GHI ---" << endl;
    // (Giả sử bạn đã copy hàm WriteToRegistry từ bài trước)
    // WriteToRegistry(myPath, myVar, L"Nguyen Van A");

    wcout << L"\n--- 2. DOC LAN 1 ---" << endl;
    // (Giả sử bạn đã copy hàm ReadFromRegistry từ bài trước)
    // ReadFromRegistry(myPath, myVar);

    wcout << L"\n--- 3. XOA ---" << endl;
    DeleteFromRegistry(myPath, myVar);

    wcout << L"\n--- 4. DOC LAN 2 (Kiem chung) ---" << endl;
    // ReadFromRegistry(myPath, myVar); 
    // -> Lúc này nó sẽ báo lỗi "Khong tim thay"

    system("pause");
    return 0;
}