#include <iostream>
#include <windows.h>
#include <string>

using namespace std;

int main() {
    // [CHIÊU THỨC QUAN TRỌNG NHẤT]
    // Vì Cha đã chiếm dụng stdin/stdout chuẩn để làm đường ống,
    // nên ta phải ép chương trình kết nối lại với Bàn Phím (CONIN$) của cửa sổ mới.
    FILE* fp;
    freopen_s(&fp, "CONIN$", "r", stdin);

    // Gửi lời chào (sẽ bay về Cha)
    cout << "[CON] Ket noi thanh cong! Toi dang san sang." << endl;

    // Xả nước ngay lập tức để Cha nhận được
    fflush(stdout);

    string msg;
    while (true) {
        // 1. Nhập dữ liệu từ bàn phím (Nhờ dòng freopen ở trên mới nhập được)
        // Lệnh này sẽ dừng màn hình Con lại chờ bạn gõ
        getline(cin, msg);

        // Kiểm tra nếu gõ "exit" thì thoát
        if (msg == "exit") break;

        // 2. Gửi sang cho Cha (thông qua stdout đã bị redirect vào Pipe)
        cout << msg << endl;

        // 3. Đẩy dữ liệu đi ngay (Quan trọng!)
        fflush(stdout);
    }

    return 0;
}