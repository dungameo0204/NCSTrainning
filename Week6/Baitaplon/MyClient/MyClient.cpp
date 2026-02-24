#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <io.h>     
#include <fcntl.h>  
#include "Protocol.h" 

using namespace std;

HANDLE g_hPipe = INVALID_HANDLE_VALUE;
uint32_t g_ClientSeqId = 0;
uint32_t g_CurrentSessionId = 0;    // [MỚI] Lưu Session ID để resume
uint32_t g_LastReceivedSeq = 0;     // [MỚI] Lưu Sequence ID cuối cùng nhận được

void SetColor(int color) { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color); }

bool SendPacket(MessageType type, const void* data, size_t size) {
    if (g_hPipe == INVALID_HANDLE_VALUE) return false;
    uint32_t checksum = CalculateChecksum(data, size) ;
    // Gửi SessionID hiện tại trong header
    PacketHeader header = { PACKET_MAGIC, PROTOCOL_VERSION, (uint16_t)type, (uint32_t)size, ++g_ClientSeqId, g_CurrentSessionId, checksum };
    DWORD w;
    if (!WriteFile(g_hPipe, &header, sizeof(header), &w, NULL)) return false;
    if (size > 0 && !WriteFile(g_hPipe, data, (DWORD)size, &w, NULL)) return false;
    return true;
}

bool ReadFull(void* buffer, size_t size) {
    size_t totalRead = 0; char* charBuf = (char*)buffer;
    while (totalRead < size) {
        DWORD bytesRead = 0;
        if (!ReadFile(g_hPipe, charBuf + totalRead, (DWORD)(size - totalRead), &bytesRead, NULL) || bytesRead == 0) return false;
        totalRead += bytesRead;
    }
    return true;
}

bool ReceivePacket(PacketHeader& outHeader, vector<uint8_t>& outPayload) {
    if (!ReadFull(&outHeader, sizeof(PacketHeader))) return false;
    if (outHeader.magic != PACKET_MAGIC) return false;

    // [MỚI] Cập nhật Seq ID
    g_LastReceivedSeq = outHeader.sequenceId;

    if (outHeader.payloadSize > 0) {
        outPayload.resize(outHeader.payloadSize);
        if (!ReadFull(outPayload.data(), outHeader.payloadSize)) return false;
    }
    else outPayload.clear();
    return true;
}

bool ConnectToPipe() {
    // Chỉ thử kết nối Pipe, chưa gửi Hello/Resume
    g_hPipe = CreateFile(L"\\\\.\\pipe\\AvScanPipe", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    return (g_hPipe != INVALID_HANDLE_VALUE);
}

// [MỚI] Hàm tái kết nối thông minh
bool TryReconnect() {
    SetColor(14); wcout << L"\n [!] Mat ket noi! Dang thu ket noi lai (Timeout 10s)..." << endl; SetColor(7);
    CloseHandle(g_hPipe); g_hPipe = INVALID_HANDLE_VALUE;

    for (int i = 1; i <= 10; i++) {
        wcout << L" -> Thu lan " << i << L"... ";
        if (ConnectToPipe()) {
            // Kết nối Pipe thành công -> Gửi lệnh RESUME
            PayloadResume resumePkt = { g_CurrentSessionId, g_LastReceivedSeq };
            if (SendPacket(MSG_RESUME, &resumePkt, sizeof(resumePkt))) {
                SetColor(10); wcout << L"Thanh cong! Dang dong bo lai..." << endl; SetColor(7);
                return true;
            }
        }
        wcout << L"That bai." << endl;
        Sleep(1000); // Chờ 1s thử lại
    }
    SetColor(12); wcout << L" [X] Khong the ket noi lai. Huy tac vu." << endl; SetColor(7);
    return false;
}

bool Handshake() {
    if (!ConnectToPipe()) return false;

    PayloadHello hello = { GetCurrentProcessId(), 2, "Admin" };
    if (!SendPacket(MSG_HELLO, &hello, sizeof(hello))) return false;

    PacketHeader h; vector<uint8_t> b;
    if (ReceivePacket(h, b) && h.type == MSG_WELCOME) {
        auto* welcome = reinterpret_cast<PayloadWelcome*>(b.data());
        g_CurrentSessionId = welcome->sessionId; // [MỚI] Lưu Session ID
        SetColor(10); wcout << L"\n[CONNECTED] Service Ready! SessionID: " << g_CurrentSessionId << endl; SetColor(7);
        return true;
    }
    return false;
}

int main() {
    _setmode(_fileno(stdout), _O_U16TEXT); _setmode(_fileno(stdin), _O_U16TEXT);

    SetColor(11);
    wcout << L"==============================================" << endl;
    wcout << L"   MY ANTIVIRUS CLIENT (RESUME SUPPORT)       " << endl;
    wcout << L"==============================================" << endl;
    SetColor(7);

    // Vòng lặp kết nối ban đầu
    while (true) {
        if (Handshake()) break;
        wcout << L"Waiting for Service..." << endl;
        if (!WaitNamedPipe(L"\\\\.\\pipe\\AvScanPipe", 2000)) Sleep(1000);
    }

    wstring line, cmd, arg;
    while (true) {
        SetColor(14); wcout << L"\nAV-Shell> "; SetColor(7);
        getline(wcin, line);
        if (line.empty()) continue;

        size_t spacePos = line.find(L' ');
        cmd = (spacePos != wstring::npos) ? line.substr(0, spacePos) : line;
        arg = (spacePos != wstring::npos) ? line.substr(spacePos + 1) : L"";

        if (cmd == L"exit") break;
        else if (cmd == L"cls") system("cls");
        else if (cmd == L"scan") {
            if (arg.empty()) continue;
            PayloadScanReq req; req.priority = 1; req.timeoutMs = 5000;
            wcsncpy_s(req.filePath, arg.c_str(), 259);

            if (SendPacket(MSG_SCAN_REQ, &req, sizeof(req))) {
                PacketHeader h; vector<uint8_t> b;

                // Nhận phản hồi bắt đầu
                if (ReceivePacket(h, b) && h.type == MSG_SCAN_RESP) {
                    wcout << L" -> Scan Started..." << endl;

                    // VÒNG LẶP NHẬN DỮ LIỆU (CÓ RECONNECT)
                    while (true) {
                        if (!ReceivePacket(h, b)) {
                            // [MỚI] Nếu nhận lỗi -> Gọi Reconnect
                            if (TryReconnect()) {
                                continue; // Reconnect thành công -> Tiếp tục vòng lặp nhận
                            }
                            else {
                                break; // Reconnect thất bại -> Thoát
                            }
                        }

                        if (h.type == MSG_FLOW_CONTROL) {
                            auto* pfc = reinterpret_cast<PayloadFlowControl*>(b.data());
                            SetColor(14); wcout << L" [!] SERVER BUSY: Dropped " << pfc->droppedCount << L" packets." << endl; SetColor(7);
                            continue;
                        }

                        if (h.type == MSG_JOB_STATUS) {
                            auto* status = reinterpret_cast<PayloadJobStatus*>(b.data());
                            wcout << L" -> " << status->message << endl;
                            if (status->result == 2) {
                                SetColor(12); wcout << L"    [!!!] VIRUS: " << status->threatList << endl; SetColor(7);
                            }
                            if (status->status == 2) {
                                SetColor(10); wcout << L" -> Job Finished." << endl; SetColor(7);
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    CloseHandle(g_hPipe);
    return 0;
}