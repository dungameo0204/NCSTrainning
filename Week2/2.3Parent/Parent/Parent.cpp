#include <windows.h>
#include <iostream>
#include <string>

using namespace std;

int main() {
    HANDLE hRead, hWrite;
    SECURITY_ATTRIBUTES sa;

    // Cấu hình bảo mật để cho phép kế thừa Handle
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    // 1. Tạo Đường Ống (Pipe)
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        cout << "Loi tao Pipe!" << endl;
        return 1;
    }

    // Đảm bảo Cha KHÔNG cho kế thừa đầu đọc (con chỉ cần đầu ghi)
    // Giúp tránh kẹt Pipe khi Con tắt
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite; // Cắm đường ống vào họng Con (Output)
    si.hStdError = hWrite;  // Cắm luôn cả đường lỗi
    // Lưu ý: Ta KHÔNG gán hStdInput, để mặc kệ nó (Con sẽ tự lo bằng freopen)

    ZeroMemory(&pi, sizeof(pi));

    // Sửa đường dẫn cho đúng file Child.exe của bạn
    char cmdLine[] = "D:\\NCSTrainning\\Project\\Trainning\\Week2\\2.3Child\\x64\\Debug\\Child.exe\ ";

    cout << "[CHA] Dang bat Con va nghe len..." << endl;

    // 2. Tạo Process Con
    // Quan trọng: Phải có CREATE_NEW_CONSOLE để Con có cửa sổ riêng mà gõ phím
    if (CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE,
        CREATE_NEW_CONSOLE,
        NULL, NULL, &si, &pi))
    {
        // Quan trọng: Sau khi tạo Con xong, Cha phải đóng đầu GHI của mình lại.
        // Nếu không, Cha sẽ cứ cầm đầu ghi và tưởng là vẫn còn người gửi tin -> Đợi mãi mãi.
        CloseHandle(hWrite);

        // 3. Vòng lặp nhận tin nhắn
        char buffer[1024];
        DWORD bytesRead;

        // ReadFile sẽ dừng lại chờ cho đến khi có dữ liệu từ Pipe bắn sang
        while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead != 0) {
            buffer[bytesRead] = '\0'; // Ngắt chuỗi
            cout << "[CHA nhan duoc]: " << buffer << endl;
        }

        cout << "\n[CHA] Con da ngat ket noi (Pipe broken)." << endl;

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hRead);
    }
    else {
        cout << "Loi CreateProcess: " << GetLastError() << endl;
    }

    system("pause");
    return 0;
}