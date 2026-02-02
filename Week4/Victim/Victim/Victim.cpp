// victim.cpp -> Compile ra victim.exe
#include <windows.h>
#include <iostream>

using namespace std;

// Đây là hàm BÍ MẬT (được giấu trong file nhưng main không gọi)
// Chúng ta dùng các hàm C cơ bản (printf) thay vì cout để tránh crash 
// khi bỏ qua quá trình khởi tạo CRT chuẩn.
void SecretGoodbye() {
    printf("\n=========================================\n");
    printf("   HA HA HA! BAN DA BI HACK!\n");
    printf("   GOODBYE WORLD !!!\n");
    printf("=========================================\n");
    system("pause"); // Thoát luôn, không cho chạy linh tinh nữa
}

int main() {
    // Lấy địa chỉ cơ sở (Base Address) của chương trình trong RAM
    HMODULE hModule = GetModuleHandle(NULL);

    // Tính toán RVA (Relative Virtual Address) của hàm Secret
    // RVA = Địa chỉ thật trong RAM - Địa chỉ cơ sở
    DWORD rvaSecret = (DWORD)((BYTE*)&SecretGoodbye - (BYTE*)hModule);

    cout << "--- CHUONG TRINH HELLO NORMAL ---" << endl;
    cout << "Toi la chuong trinh hien lanh, toi in ra: HELLO WORLD!" << endl;
    cout << "\n[THONG TIN MAT CHO HACKER]" << endl;
    cout << "RVA cua ham SecretGoodbye la: " << hex << rvaSecret << endl;
    cout << "Hay nho con so nay de hack toi!" << endl;

    system("pause");
    return 0;
}