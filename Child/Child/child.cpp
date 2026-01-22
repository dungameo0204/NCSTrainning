// Con.cpp - Chương trình bị sai vặt
#include <iostream>
#include <windows.h>
#include <fcntl.h>
#include <io.h>

using namespace std;

// int argc: Số lượng tham số
// wchar_t* argv[]: Mảng chứa các tham số
int wmain(int argc, wchar_t* argv[]) {
    _setmode(_fileno(stdout), _O_U16TEXT);

    wcout << L"\n[CON] Chao bo! Con da duoc sinh ra." << endl;
    wcout << L"[CON] PID cua con la: " << GetCurrentProcessId() << endl;

    // In ra các tham số được cha truyền cho
    wcout << L"[CON] Bo gui cho con " << argc << L" tham so:" << endl;
    for (int i = 0; i < argc; i++) {
        wcout << L"   - Tham so " << i << L": " << argv[i] << endl;
    }

    wcout << L"[CON] Con dang gia vo lam viec cham chi trong 10 giay..." << endl;
    Sleep(10000); // Ngủ 3 giây

    wcout << L"[CON] Xong viec, con di ngu day! (Exit Code: 99)" << endl;

    // Trả về Exit Code 99 (số nào cũng được, để cha check)
    return 99;
}