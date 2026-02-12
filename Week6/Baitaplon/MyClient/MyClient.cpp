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

void SetColor(int color) { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color); }

bool ReadFull(void* buffer, size_t size) {
    size_t totalRead = 0; char* charBuf = (char*)buffer;
    while (totalRead < size) {
        DWORD bytesRead = 0;
        if (!ReadFile(g_hPipe, charBuf + totalRead, (DWORD)(size - totalRead), &bytesRead, NULL) || bytesRead == 0) return false;
        totalRead += bytesRead;
    }
    return true;
}

bool SendPacket(MessageType type, const void* data, size_t size) {
    if (g_hPipe == INVALID_HANDLE_VALUE) return false;
    PacketHeader header = { PACKET_MAGIC, PROTOCOL_VERSION, (uint16_t)type, (uint32_t)size, ++g_ClientSeqId, 0, 0 };
    DWORD w;
    if (!WriteFile(g_hPipe, &header, sizeof(header), &w, NULL)) return false;
    if (size > 0 && !WriteFile(g_hPipe, data, (DWORD)size, &w, NULL)) return false;
    return true;
}

bool ReceivePacket(PacketHeader& outHeader, vector<uint8_t>& outPayload) {
    if (!ReadFull(&outHeader, sizeof(PacketHeader))) return false;
    if (outHeader.magic != PACKET_MAGIC) return false;
    if (outHeader.payloadSize > 0) {
        outPayload.resize(outHeader.payloadSize);
        if (!ReadFull(outPayload.data(), outHeader.payloadSize)) return false;
    }
    else outPayload.clear();
    return true;
}

bool ConnectToService() {
    wcout << L"Connecting to Service..." << endl;
    while (true) {
        g_hPipe = CreateFile(L"\\\\.\\pipe\\AvScanPipe", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (g_hPipe != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_PIPE_BUSY) { Sleep(500); }
        else WaitNamedPipe(L"\\\\.\\pipe\\AvScanPipe", 5000);
    }

    PayloadHello hello = { GetCurrentProcessId(), 2, "Admin" };
    if (!SendPacket(MSG_HELLO, &hello, sizeof(hello))) return false;

    PacketHeader h; vector<uint8_t> b;
    if (ReceivePacket(h, b) && h.type == MSG_WELCOME) {
        SetColor(10); wcout << L"\n[CONNECTED] Service is Ready!" << endl; SetColor(7);
        return true;
    }
    return false;
}

int main() {
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stdin), _O_U16TEXT);

    SetColor(11);
    wcout << L"==============================================" << endl;
    wcout << L"      MY ANTIVIRUS CLIENT (ULTRA CLEAN)       " << endl;
    wcout << L"==============================================" << endl;
    SetColor(7);

    if (!ConnectToService()) {
        SetColor(12); wcout << L"Cannot connect!" << endl; return 1;
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

            // ... (Các phần đầu giữ nguyên)

            if (SendPacket(MSG_SCAN_REQ, &req, sizeof(req))) {
                PacketHeader h; vector<uint8_t> b;
                if (ReceivePacket(h, b) && h.type == MSG_SCAN_RESP) {
                    wcout << L" -> Scan Started..." << endl;
                    while (true) {
                        if (!ReceivePacket(h, b)) break;

                        // [MỚI] XỬ LÝ FLOW CONTROL
                        if (h.type == MSG_FLOW_CONTROL) {
                            auto* pfc = reinterpret_cast<PayloadFlowControl*>(b.data());
                            SetColor(14); // Màu vàng cảnh báo
                            wcout << L" [!] SERVER BUSY: Dropped " << pfc->droppedCount << L" verbose packets." << endl;
                            SetColor(7);
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