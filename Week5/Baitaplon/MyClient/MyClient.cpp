#include <windows.h>
#include <iostream>
#include <string>
#include <sstream>
#include "Protocol.h"

using namespace std;

// Hàm gửi lệnh SCAN
void CmdScan(HANDLE hPipe, wstring path) {
    PacketHeader header = { MSG_SCAN_REQ, sizeof(PayloadScanReq) };
    PayloadScanReq req;
    req.priority = 0; // Default Normal
    req.timeoutMs = 5000;
    wcscpy_s(req.filePath, path.c_str());

    DWORD written;
    WriteFile(hPipe, &header, sizeof(header), &written, NULL);
    WriteFile(hPipe, &req, sizeof(req), &written, NULL);

    // Nhận vé
    PacketHeader respH;
    PayloadScanResp resp;
    ReadFile(hPipe, &respH, sizeof(respH), &written, NULL);
    ReadFile(hPipe, &resp, sizeof(resp), &written, NULL);

    wcout << L"[Client] >> Da gui lenh Scan. Job ID: " << resp.jobId << endl;
}

// Hàm gửi lệnh QUERY
// --- NÂNG CẤP HÀM QUERY ĐỂ HIỂN THỊ KẾT QUẢ FOLDER ---
void CmdQuery(HANDLE hPipe, int id) {
    PacketHeader header = { MSG_QUERY_JOB, sizeof(PayloadQueryJob) };
    PayloadQueryJob req = { id };

    DWORD written;
    WriteFile(hPipe, &header, sizeof(header), &written, NULL);
    WriteFile(hPipe, &req, sizeof(req), &written, NULL);

    // Nhận phản hồi
    PacketHeader respH;
    PayloadJobStatus resp;
    DWORD read;
    ReadFile(hPipe, &respH, sizeof(respH), &read, NULL);
    ReadFile(hPipe, &resp, sizeof(resp), &read, NULL);

    // --- HIỂN THỊ ĐẸP MẮT ---
    wcout << L"\r[Status] Batch " << id << L": ";

    if (resp.status == 1) { // RUNNING
        // Vẽ thanh tiến độ đơn giản
        wcout << L"RUNNING... " << resp.progress << L"% | " << resp.message;
    }
    else if (resp.status == 2) { // COMPLETED
        wcout << L"FINISHED!" << endl;
        wcout << L"------------------------------------------------" << endl;

        if (resp.result == 2) { // Có Virus
            // Nếu muốn màu mè thì dùng SetConsoleTextAttribute, ở đây mình dùng text cho đơn giản
            wcout << L" [!!!] KET QUA: PHAT HIEN NGUY HIEM (INFECTED) [!!!]" << endl;
            wcout << L" => Chi tiet: " << resp.message << endl; // Ví dụ: "Done. Virus: 5"
            wcout << L" => Khuyen nghi: Xoa ngay thu muc nay!" << endl;
        } else if (resp.result == 1) { // Nghi ngờ
            wcout << L" [??] KET QUA: NGHI NGO (SUSPICIOUS)" << endl;
            wcout << L" => Chi tiet: " << resp.message << endl;
            wcout << L" => Khuyen nghi: Kiem tra ky truoc khi su dung." << endl;
		}
        else { // An toàn
            wcout << L" [OK] KET QUA: AN TOAN (CLEAN)" << endl;
            wcout << L" => Khong phat hien moi de doa nao." << endl;
        }
        wcout << L"------------------------------------------------" << endl;
    }
    else if (resp.status == 3) {
        wcout << L"CANCELLED (Da huy bo)." << endl;
    }
    else {
        wcout << L"PENDING (Dang xep hang...)" << endl;
    }
}

// Hàm gửi lệnh CANCEL
void CmdCancel(HANDLE hPipe, int id) {
    PacketHeader header = { MSG_CANCEL_JOB, sizeof(PayloadCancelJob) };
    PayloadCancelJob req = { id };
    DWORD written;
    WriteFile(hPipe, &header, sizeof(header), &written, NULL);
    WriteFile(hPipe, &req, sizeof(req), &written, NULL);

    // Nhận xác nhận (Đọc bỏ qua)
    PacketHeader respH; PayloadScanResp resp;
    ReadFile(hPipe, &respH, sizeof(respH), &written, NULL);
    ReadFile(hPipe, &resp, sizeof(resp), &written, NULL);

    wcout << L"[Client] >> Da gui lenh Cancel Job " << id << endl;
}

int main() {
    HANDLE hPipe = CreateFile(L"\\\\.\\pipe\\AvScanPipe", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) return 1;

    wcout << L"=== ANTIVIRUS CLI COMMANDER ===" << endl;
    wcout << L"Commands:" << endl;
    wcout << L"  scan <path>   : Gui file quet" << endl;
    wcout << L"  query <id>    : Xem trang thai Job" << endl;
    wcout << L"  cancel <id>   : Huy Job" << endl;
    wcout << L"===============================" << endl;

    // Vòng lặp nhập lệnh
    string line;
    while (true) {
        cout << "> ";
        getline(cin, line);
        if (line == "exit") break;

        // Phân tích cú pháp đơn giản (scan D:\file.exe)
        stringstream ss(line);
        string cmd, arg;
        ss >> cmd >> arg;

        if (cmd == "scan") {
            // Chuyển arg sang wstring
            wstring wpath(arg.begin(), arg.end());
            CmdScan(hPipe, wpath);
        }
        else if (cmd == "query") {
            CmdQuery(hPipe, stoi(arg));
        }
        else if (cmd == "cancel") {
            CmdCancel(hPipe, stoi(arg));
        }
    }

    CloseHandle(hPipe);
    return 0;
}