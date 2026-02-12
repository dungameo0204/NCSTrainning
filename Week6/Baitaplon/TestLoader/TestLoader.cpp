#include <windows.h>
#include <iostream>
#include <string>

// Định nghĩa kiểu con trỏ hàm (Function Pointer) khớp với bên DLL
// Phải khớp từng tham số và kiểu trả về!
typedef int(__stdcall* FnScanFile)(const wchar_t*);
typedef bool(__stdcall* FnInit)();

using namespace std;

int main() {
    // 1. Load file DLL lên bộ nhớ
    // Lưu ý: File DLL phải nằm cùng thư mục với file EXE này, hoặc phải ghi đường dẫn tuyệt đối.
    // Mẹo: Khi code xong, hãy copy file ScannerEngine.dll ném vào chỗ TestLoader.exe
    HMODULE hDll = LoadLibrary(L"ScannerEngine.dll");

    if (hDll == NULL) {
        cout << "Loi: Khong tim thay file ScannerEngine.dll!" << endl;
        system("pause");
        return 1;
    }
    cout << "[+] Da load DLL thanh cong!" << endl;

    // 2. Lấy địa chỉ hàm (Map hàm từ DLL vào biến con trỏ hàm)
    FnInit MyEngineInit = (FnInit)GetProcAddress(hDll, "EngineInitialize");
    FnScanFile MyScanFile = (FnScanFile)GetProcAddress(hDll, "EngineScanFile");

    if (!MyEngineInit || !MyScanFile) {
        cout << "Loi: Khong tim thay ham trong DLL!" << endl;
        system("pause");
        FreeLibrary(hDll);
        return 1;
    }

    // 3. Chạy thử
    MyEngineInit(); // Gọi hàm Init

    // Test case 1: File sạch
    const wchar_t* file1 = L"C:\\Windows\\System32\\notepad.exe";
    cout << "Scanning: Notepad.exe -> Result: " << MyScanFile(file1) << " (Mong doi: 0)" << endl;

    // Test case 2: File bẩn giả lập
    const wchar_t* file2 = L"D:\\Games\\hack_tool.virus";
    cout << "Scanning: hack_tool.virus -> Result: " << MyScanFile(file2) << " (Mong doi: 1)" << endl;

    // 4. Dọn dẹp
    FreeLibrary(hDll); // Nhả DLL ra khỏi bộ nhớ
    cout << "Da unload DLL." << endl;

    system("pause");
    return 0;
}