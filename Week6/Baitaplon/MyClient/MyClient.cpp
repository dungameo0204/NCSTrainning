#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <io.h>     
#include <fcntl.h>  
#include <fstream>  
#include <mutex>    
#include <cstdlib>  
#include <thread>   
#include <chrono>    // [MỚI] Thư viện thời gian để tính Rate Limit
#include <algorithm> // [MỚI] Dùng để chuyển chuỗi sang chữ thường
#include "Protocol.h" 

using namespace std;

// ==========================================
// BIẾN TOÀN CỤC & POLICY
// ==========================================
HANDLE g_hPipe = INVALID_HANDLE_VALUE;
uint32_t g_ClientSeqId = 0;
uint32_t g_CurrentSessionId = 0;
uint32_t g_LastReceivedSeq = 0;

std::mutex g_SendMutex;
std::wofstream g_logFile;
bool g_IsScanning = false;

// [MỚI] Cấu hình Policy & Anti-Spam
std::chrono::steady_clock::time_point g_LastScanTime; // Lưu thời gian lần quét cuối
const int RATE_LIMIT_SECONDS = 5; // Khoảng cách tối thiểu giữa 2 lần quét (giây)

// ==========================================
// HÀM KIỂM TRA POLICY (DENY LIST)
// ==========================================
bool IsPathAllowed(std::wstring path) {
    // Chuyển đường dẫn về chữ thường để so sánh cho chuẩn
    std::transform(path.begin(), path.end(), path.begin(), ::towlower);

    // Danh sách đen (Deny List)
    std::vector<std::wstring> denyList = {
        L"c:\\windows\\system32",
        L"c:\\$recycle.bin",
        L"c:\\$mfedeeprem"  // Thư mục của McAfee (nếu có)
    };

    for (const auto& deniedPath : denyList) {
        // Nếu đường dẫn người dùng nhập VÀO bắt đầu bằng các thư mục cấm
        if (path.find(deniedPath) == 0) {
            return false; // Bị cấm!
        }
    }
    return true; // Hợp lệ
}

// ==========================================
// CÁC HÀM TIỆN ÍCH & GIAO TIẾP IPC (Giữ nguyên)
// ==========================================
void SetColor(int color) { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color); }

bool SendPacket(MessageType type, const void* data, size_t size) {
    std::lock_guard<std::mutex> lock(g_SendMutex);
    if (g_hPipe == INVALID_HANDLE_VALUE) return false;
    uint32_t checksum = CalculateChecksum(data, size);
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
    g_LastReceivedSeq = outHeader.sequenceId;
    if (outHeader.payloadSize > 0) {
        outPayload.resize(outHeader.payloadSize);
        if (!ReadFull(outPayload.data(), outHeader.payloadSize)) return false;
    }
    else outPayload.clear();
    return true;
}

bool ConnectToPipe() {
    g_hPipe = CreateFile(L"\\\\.\\pipe\\AvScanPipe", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    return (g_hPipe != INVALID_HANDLE_VALUE);
}

bool TryReconnect() {
    SetColor(14); wcout << L"\n [!] Mat ket noi! Dang thu ket noi lai (Timeout 10s)..." << endl; SetColor(7);
    if (g_hPipe != INVALID_HANDLE_VALUE) { CloseHandle(g_hPipe); g_hPipe = INVALID_HANDLE_VALUE; }
    for (int i = 1; i <= 10; i++) {
        wcout << L" -> Thu lan " << i << L"... ";
        if (ConnectToPipe()) {
            PayloadResume resumePkt = { g_CurrentSessionId, g_LastReceivedSeq };
            if (SendPacket(MSG_RESUME, &resumePkt, sizeof(resumePkt))) {
                SetColor(10); wcout << L"Thanh cong! Dang dong bo lai..." << endl; SetColor(7);
                return true;
            }
        }
        wcout << L"That bai." << endl;
        Sleep(1000);
    }
    SetColor(12); wcout << L" [X] Khong the ket noi lai. Huy tac vu." << endl; SetColor(7);
    return false;
}

bool Handshake() {
    if (!ConnectToPipe()) return false;
    PayloadHello hello; ZeroMemory(&hello, sizeof(hello));
    hello.processId = GetCurrentProcessId();
    if (!SendPacket(MSG_HELLO, &hello, sizeof(hello))) {
        CloseHandle(g_hPipe); g_hPipe = INVALID_HANDLE_VALUE; return false;
    }
    PacketHeader h; vector<uint8_t> b;
    if (ReceivePacket(h, b)) {
        if (h.type == MSG_WELCOME) {
            auto* welcome = reinterpret_cast<PayloadWelcome*>(b.data());
            g_CurrentSessionId = welcome->sessionId;
            SetColor(10); wcout << L"\n[CONNECTED] Service Ready! SessionID: " << g_CurrentSessionId << endl; SetColor(7);

            // Khởi tạo thời gian bắt đầu
            g_LastScanTime = std::chrono::steady_clock::now() - std::chrono::hours(1);
            return true;
        }
        else if (h.type == MSG_ERROR) {
            auto* err = reinterpret_cast<PayloadError*>(b.data());
            SetColor(12); wcout << L"\n[!] Bi Service tu choi ket noi. Ly do: " << err->message << endl; SetColor(7);
            Sleep(5000);
        }
    }
    CloseHandle(g_hPipe); g_hPipe = INVALID_HANDLE_VALUE; return false;
}

// ==========================================
// HÀM MAIN
// ==========================================
int main() {
    _setmode(_fileno(stdout), _O_U16TEXT); _setmode(_fileno(stdin), _O_U16TEXT);

    SetColor(11);
    wcout << L"==============================================" << endl;
    wcout << L"   MY ANTIVIRUS CLIENT (POLICY SECURED)       " << endl;
    wcout << L"==============================================" << endl;
    SetColor(7);

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
        else if (cmd == L"drop") {
            SetColor(12); wcout << L"[!] CO TINH DAP ONG NUOC DE TEST RESUME..." << endl; SetColor(7);
            if (g_hPipe != INVALID_HANDLE_VALUE) { CloseHandle(g_hPipe); g_hPipe = INVALID_HANDLE_VALUE; }
            continue;
        }

        else if (cmd == L"scan") {
            if (arg.empty()) continue;

            if (g_IsScanning) {
                SetColor(12); wcout << L"[!] Mot tien trinh quet khac dang chay. Vui long cho!" << endl; SetColor(7);
                continue;
            }

            // ==========================================
            // [MỚI] 1. CHỐNG SPAM (RATE LIMITING)
            // ==========================================
            auto now = std::chrono::steady_clock::now();
            auto elapsedSecs = std::chrono::duration_cast<std::chrono::seconds>(now - g_LastScanTime).count();

            if (elapsedSecs < RATE_LIMIT_SECONDS) {
                SetColor(12);
                wcout << L"[BLOCK] Phat hien Spam! Vui long doi "
                    << (RATE_LIMIT_SECONDS - elapsedSecs) << L" giay nua..." << endl;
                SetColor(7);
                continue; // Chặn không cho gửi lệnh
            }

            // ==========================================
            // [MỚI] 2. KIỂM TRA QUYỀN TRUY CẬP (POLICY)
            // ==========================================
            if (!IsPathAllowed(arg)) {
                SetColor(12);
                wcout << L"[ACCESS DENIED] Thu muc nay duoc bao ve boi Policy. Ban khong the quet!" << endl;
                SetColor(7);
                continue; // Chặn không cho gửi lệnh
            }

            // Nếu vượt qua mọi bài test, cập nhật thời gian quét mới nhất
            g_LastScanTime = std::chrono::steady_clock::now();

            PayloadScanReq req;
            ZeroMemory(&req, sizeof(req));
            req.priority = 1;
            req.timeoutMs = 5000;
            wcsncpy_s(req.filePath, arg.c_str(), 259);

            if (g_logFile.is_open()) g_logFile.close();
            g_logFile.open(L"scan_live.log", std::ios::out | std::ios::trunc);

            if (SendPacket(MSG_SCAN_REQ, &req, sizeof(req))) {
                SetColor(11);
                wcout << L"[+] Da gui lenh quet thu muc: " << arg << endl;
                wcout << L"[+] Dang quet ngam. Chi tiet duoc ghi vao file 'scan_live.log'..." << endl;
                SetColor(7);

                g_IsScanning = true;

                std::thread([arg]() {
                    PacketHeader h; vector<uint8_t> b;
                    int totalThreats = 0;

                    while (true) {
                        if (!ReceivePacket(h, b)) {
                            if (TryReconnect()) continue;
                            else break;
                        }

                        if (h.type == MSG_FLOW_CONTROL) {
                            auto* pfc = reinterpret_cast<PayloadFlowControl*>(b.data());
                            if (g_logFile.is_open()) g_logFile << L"[!] SERVER BUSY: Dropped " << pfc->droppedCount << L" packets.\n";
                            continue;
                        }

                        if (h.type == MSG_JOB_STATUS) {
                            auto* status = reinterpret_cast<PayloadJobStatus*>(b.data());

                            if (status->status == 2) {
                                if (g_logFile.is_open()) g_logFile.flush();

                                SetColor(10);
                                wcout << L"\n\n==========================================" << endl;
                                wcout << L"[V] QUET HOAN TAT (JOB FINISHED)!" << endl;
                                wcout << L"    - Duong dan : " << arg << endl;
                                wcout << L"    - Phat hien : " << totalThreats << L" ma doc" << endl;
                                wcout << L"==========================================" << endl;

                                SetColor(14); wcout << L"\nAV-Shell> "; SetColor(7);
                                break;
                            }
                            else {
                                if (g_logFile.is_open()) {
                                    g_logFile << L" -> " << status->message << L"\n";
                                    if (status->result == 2) {
                                        g_logFile << L"    [!!!] VIRUS: " << status->threatList << L"\n";
                                        totalThreats++;
                                    }
                                }
                            }
                        }
                    }
                    g_IsScanning = false;
                    }).detach();
            }
        }
    }

    if (g_hPipe != INVALID_HANDLE_VALUE) CloseHandle(g_hPipe);
    if (g_logFile.is_open()) g_logFile.close();
    return 0;
}