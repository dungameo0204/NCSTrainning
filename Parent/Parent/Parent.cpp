#include <windows.h>
#include <iostream>
#include <fcntl.h>
#include <io.h>
#include <string>

using namespace std;

int main() {
    _setmode(_fileno(stdout), _O_U16TEXT);

    // 1. Chuẩn bị thông tin cho 2 con
    // Bạn có thể dùng chung file Child.exe nhưng truyền tham số khác nhau
    wchar_t cmd1[] = L"D:\\NCSTrainning\\Project\\Trainning\\Child\\x64\\Debug\\Child.exe\ đứa đầu tiên"; // Con A 
    wchar_t cmd2[] = L"D:\\NCSTrainning\\Project\\rainning\\Child\\x64\\Debug\\Child.exe\ thằng thứ hai"; // Con B 

    STARTUPINFOW si1, si2;
    PROCESS_INFORMATION pi1, pi2;

    // Xóa trắng bộ nhớ cho cả 2 bộ struct
    ZeroMemory(&si1, sizeof(si1)); si1.cb = sizeof(si1);
    ZeroMemory(&si2, sizeof(si2)); si2.cb = sizeof(si2);
    ZeroMemory(&pi1, sizeof(pi1));
    ZeroMemory(&pi2, sizeof(pi2));

    wcout << L"[CHA] Dang tao 2 process con cung luc..." << endl;

    // 2. Gọi CreateProcess lần 1
    if (!CreateProcessW(NULL, cmd1, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si1, &pi1)) {
        wcout << L"Loi tao Con A: " << GetLastError() << endl;
        return 1;
    }

    // 3. Gọi CreateProcess lần 2 ngay lập tức
    if (!CreateProcessW(NULL, cmd2, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si2, &pi2)) {
        wcout << L"Loi tao Con B: " << GetLastError() << endl;
        return 1;
    }

    wcout << L"[CHA] Ca 2 con dang chay song song." << endl;

    // 4. CHO ĐỢI CẢ HAI (Dùng mảng Handle)
    HANDLE hChildren[2];
    hChildren[0] = pi1.hProcess;
    hChildren[1] = pi2.hProcess;

    wcout << L"[CHA] Dang doi ca 2 hoan thanh..." << endl;

    // WaitForMultipleObjects: Đợi nhiều đối tượng cùng lúc
    // 2: Số lượng handle
    // hChildren: Mảng các handle
    // TRUE: Đợi TẤT CẢ xong mới chạy tiếp (FALSE là chỉ cần 1 đứa xong là chạy tiếp)
    // INFINITE: Đợi vô tận
    WaitForMultipleObjects(2, hChildren, TRUE, INFINITE);

    // 5. Lấy kết quả
    DWORD exitA, exitB;
    GetExitCodeProcess(pi1.hProcess, &exitA);
    GetExitCodeProcess(pi2.hProcess, &exitB);

    wcout << L"\n--- TONG KET ---" << endl;
    wcout << L"Con A thoat voi ma: " << exitA << endl;
    wcout << L"Con B thoat voi ma: " << exitB << endl;

    // 6. Dọn dẹp (4 cái handle)
    CloseHandle(pi1.hProcess); CloseHandle(pi1.hThread);
    CloseHandle(pi2.hProcess); CloseHandle(pi2.hThread);

    wcout << L"Nhan Enter de thoat...";
    getchar();
    return 0;
}