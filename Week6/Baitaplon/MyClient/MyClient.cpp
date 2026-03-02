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
#include <chrono>    
#include <algorithm> 
#include <queue>     
#include <map>       
#include <shellapi.h> 
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

std::chrono::steady_clock::time_point g_LastScanTime;
const int RATE_LIMIT_SECONDS = 5;

// ==========================================
// BỘ QUẢN LÝ ĐA NHIỆM (MULTIPLEXER)
// ==========================================
struct ClientJobInfo {
    std::wstring path;
    int totalThreats = 0;
    uint32_t totalFiles = 0;
    uint32_t processedFiles = 0;
    HANDLE hPipeWrite = INVALID_HANDLE_VALUE;
};

std::mutex g_ClientMutex;
std::queue<std::wstring> g_PendingPaths;
std::map<uint32_t, ClientJobInfo> g_ActiveJobs;

void SetColor(int color) { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color); }

// ==========================================
// HÀM TRIỆU HỒI CỬA SỔ CON
// ==========================================
bool SpawnMonitorConsole(uint32_t jobId, const std::wstring& targetPath, HANDLE& outWritePipe) {
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hReadPipe;
    if (!CreatePipe(&hReadPipe, &outWritePipe, &sa, 0)) return false;
    SetHandleInformation(outWritePipe, HANDLE_FLAG_INHERIT, 0);

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    wchar_t cmdLine[512];
    swprintf_s(cmdLine, L"\"%s\" --monitor %u %Iu", exePath, jobId, (size_t)hReadPipe);

    STARTUPINFOW si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));

    if (CreateProcessW(NULL, cmdLine, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hReadPipe);
        return true;
    }
    CloseHandle(hReadPipe);
    CloseHandle(outWritePipe);
    return false;
}

// ==========================================
// CÁC HÀM TIỆN ÍCH & GIAO TIẾP IPC 
// ==========================================
bool IsPathAllowed(std::wstring path) {
    std::transform(path.begin(), path.end(), path.begin(), ::towlower);
    std::vector<std::wstring> denyList = { L"c:\\windows\\system32", L"c:\\$recycle.bin" };
    for (const auto& deniedPath : denyList) { if (path.find(deniedPath) == 0) return false; }
    return true;
}

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
            g_LastScanTime = std::chrono::steady_clock::now() - std::chrono::hours(1);
            return true;
        }
    }
    CloseHandle(g_hPipe); g_hPipe = INVALID_HANDLE_VALUE; return false;
}

// ==========================================
// TRẠM THU PHÁT TRUNG TÂM (MULTIPLEXER)
// ==========================================
void SingleReceiverThread() {
    PacketHeader h; vector<uint8_t> b;

    while (true) {
        DWORD bytesAvail = 0;
        if (g_hPipe == INVALID_HANDLE_VALUE || !PeekNamedPipe(g_hPipe, NULL, 0, NULL, &bytesAvail, NULL)) {
            if (TryReconnect()) continue; else break;
        }
        if (bytesAvail == 0) { std::this_thread::sleep_for(std::chrono::milliseconds(50)); continue; }
        if (!ReceivePacket(h, b)) { if (TryReconnect()) continue; else break; }

        if (h.type == MSG_FLOW_CONTROL) {
            auto* pfc = reinterpret_cast<PayloadFlowControl*>(b.data());

            std::lock_guard<std::mutex> lock(g_ClientMutex);
            for (auto& pair : g_ActiveJobs) {
                if (pair.second.hPipeWrite != INVALID_HANDLE_VALUE) {
                    std::wstring dropMsg = L"    [!] WARNING: SERVER QUA TAI - DROP " + std::to_wstring(pfc->droppedCount) + L" GOI TIN!\n";
                    DWORD w;
                    WriteFile(pair.second.hPipeWrite, dropMsg.c_str(), dropMsg.size() * sizeof(wchar_t), &w, NULL);
                }
            }
            continue;
        }

        if (h.type == MSG_SCAN_RESP) {
            auto* resp = reinterpret_cast<PayloadScanResp*>(b.data());
            std::lock_guard<std::mutex> lock(g_ClientMutex);
            if (!g_PendingPaths.empty()) {
                std::wstring targetPath = g_PendingPaths.front(); g_PendingPaths.pop();
                HANDLE hWrite = INVALID_HANDLE_VALUE;
                SpawnMonitorConsole(resp->jobId, targetPath, hWrite);
                g_ActiveJobs[resp->jobId] = { targetPath, 0, 0, 0, hWrite };
            }
        }
        else if (h.type == MSG_JOB_STATUS) {
            auto* status = reinterpret_cast<PayloadJobStatus*>(b.data());

            std::lock_guard<std::mutex> lock(g_ClientMutex);

            // =================================================================
            // [FIX CỰC MẠNH] ĐỒNG BỘ TRẠNG THÁI: NHẬN DIỆN JOB LẠ TỪ SERVER
            // =================================================================
            if (g_ActiveJobs.find(status->jobId) == g_ActiveJobs.end()) {
                if(status->status == 0 || status->status == 2 || status->status == 3) continue; // Bỏ qua nếu là tin nhắn hệ thống rảnh rỗi

                // Nếu có Job đang chạy mà Client chưa biết -> Bật cửa sổ khôi phục luôn!
                HANDLE hWrite = INVALID_HANDLE_VALUE;
                SpawnMonitorConsole(status->jobId, L"[Khôi phục từ Server]", hWrite);

                g_ActiveJobs[status->jobId] = { L"[Khôi phục từ Server]", 0, status->totalFiles, status->processedFiles, hWrite };

                SetColor(10);
                wcout << L"\n[+] Da khoi phuc tien do cua Job ID: " << status->jobId << endl;
                SetColor(14); wcout << L"AV-Shell> "; SetColor(7);
            }

            auto& job = g_ActiveJobs[status->jobId];
            job.totalFiles = status->totalFiles;
            job.processedFiles = status->processedFiles;
            job.totalThreats = status->totalThreats;
            // NẾU XONG HOẶC BỊ HỦY TỪ SERVER
            if (status->status == 2 || status->status == 3) {
                if (job.hPipeWrite != INVALID_HANDLE_VALUE) {
                    std::wstring finalMsg;

                    if (status->status == 2) {
                        finalMsg = L"\n==========================================\n";
                        finalMsg += L"[V] QUET HOAN TAT!\n";
                        finalMsg += L"    - Tong so file da quet : " + std::to_wstring(job.processedFiles) + L" files\n";
                        finalMsg += L"    - So Virus phat hien   : " + std::to_wstring(job.totalThreats) + L" ma doc\n";
                        finalMsg += L"==========================================\n";
                    }
                    else {
                        finalMsg = L"\n[X] DA HUY TIEN TRINH!\n";
                    }

                    DWORD w;
                    WriteFile(job.hPipeWrite, finalMsg.c_str(), finalMsg.size() * sizeof(wchar_t), &w, NULL);
                    CloseHandle(job.hPipeWrite);
                    job.hPipeWrite = INVALID_HANDLE_VALUE;
                }

                SetColor(status->status == 2 ? 10 : 12);
                wcout << L"\n[Service] Job " << status->jobId << ((status->status == 2) ? L" Hoan tat!" : L" Da Huy!") << endl;
                SetColor(14); wcout << L"AV-Shell> "; SetColor(7);
                g_ActiveJobs.erase(status->jobId);
            }
            // NẾU ĐANG QUÉT
            else {
                if (job.hPipeWrite != INVALID_HANDLE_VALUE) {
                    std::wstring logLine = L" -> " + std::wstring(status->message) + L"\n";
                    DWORD w; WriteFile(job.hPipeWrite, logLine.c_str(), logLine.size() * sizeof(wchar_t), &w, NULL);

                    if (status->result == 2) {
                        std::wstring virusLine = L"    [!!!] VIRUS: " + std::wstring(status->threatList) + L"\n";
                        WriteFile(job.hPipeWrite, virusLine.c_str(), virusLine.size() * sizeof(wchar_t), &w, NULL);
                     
                    }
                }
            }
        }
    }
}

// ==========================================
// HÀM MAIN 
// ==========================================
int main() {
    _setmode(_fileno(stdout), _O_U16TEXT); _setmode(_fileno(stdin), _O_U16TEXT);

    // =========================================================
    // NẾU LÀ CỬA SỔ CON (MÀN HÌNH MONITOR)
    // =========================================================
    int argc; LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argc >= 4 && wcscmp(argv[1], L"--monitor") == 0) {
        std::wstring jobIdStr = argv[2];
        HANDLE hPipe = (HANDLE)_wcstoui64(argv[3], NULL, 10);

        SetConsoleTitleW((L"AV Scanner Progress - Job " + jobIdStr).c_str());
        SetColor(11); wcout << L"==============================================" << endl;
        wcout << L"  MONITORING SCAN PROGRESS (JOB ID: " << jobIdStr << L")" << endl;
        wcout << L"==============================================\n" << endl; SetColor(7);

        wchar_t buf[1024]; DWORD bytesRead;
        while (ReadFile(hPipe, buf, sizeof(buf) - sizeof(wchar_t), &bytesRead, NULL) && bytesRead > 0) {
            buf[bytesRead / sizeof(wchar_t)] = L'\0';
            std::wstring output(buf);

            if (output.find(L"[!!!] VIRUS:") != std::wstring::npos) SetColor(12);
            else if (output.find(L"[!] WARNING: SERVER QUA TAI") != std::wstring::npos) SetColor(14);
            else if (output.find(L"[V] QUET HOAN TAT") != std::wstring::npos) SetColor(10);
            else if (output.find(L"[X] DA HUY") != std::wstring::npos) SetColor(12);
            else SetColor(7);

            wcout << output;
            SetColor(7);
        }

        SetColor(14); wcout << L"\n[*] An phim Enter de dong cua so nay..." << endl;
        wcin.get(); CloseHandle(hPipe); LocalFree(argv); return 0;
    }
    LocalFree(argv);

    // =========================================================
    // NẾU LÀ TRẠM TRUNG TÂM (COMMAND CENTER)
    // =========================================================
    SetConsoleTitleW(L"AV Shell Command Center");
    SetColor(10);
    wcout << L"==============================================" << endl;
    wcout << L"   AV COMMAND CENTER (HOLLYWOOD MODE)         " << endl;
    wcout << L"==============================================" << endl;
    SetColor(7);

    while (true) {
        if (Handshake()) break;
        wcout << L"Waiting for Service..." << endl;
        if (!WaitNamedPipe(L"\\\\.\\pipe\\AvScanPipe", 2000)) Sleep(1000);
    }

    std::thread(SingleReceiverThread).detach();

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

        else if (cmd == L"cancel") {
            if (arg.empty()) continue;
            try {
                uint32_t cancelId = std::stoi(arg);
                PayloadCancelReq req; ZeroMemory(&req, sizeof(req));
                req.jobId = cancelId;

                if (SendPacket(MSG_CANCEL_REQ, &req, sizeof(req))) {
                    SetColor(11); wcout << L"[+] Da gui lenh huy JobID: " << cancelId << endl; SetColor(7);

                    std::lock_guard<std::mutex> lock(g_ClientMutex);
                    if (g_ActiveJobs.find(cancelId) != g_ActiveJobs.end()) {
                        auto& job = g_ActiveJobs[cancelId];

                        if (job.hPipeWrite != INVALID_HANDLE_VALUE) {
                            std::wstring finalMsg = L"\n[X] DA HUY TIEN TRINH (FORCED)!\n";
                            DWORD w; WriteFile(job.hPipeWrite, finalMsg.c_str(), finalMsg.size() * sizeof(wchar_t), &w, NULL);
                            CloseHandle(job.hPipeWrite);
                            job.hPipeWrite = INVALID_HANDLE_VALUE;
                        }

                        SetColor(14); wcout << L"[Client] Dang cho Service xac nhan huy Job " << cancelId << L"..." << endl;
                        //g_ActiveJobs.erase(cancelId);
                    }
                }
            }
            catch (...) { SetColor(12); wcout << L"[!] JobID khong hop le!" << endl; SetColor(7); }
        }

        else if (cmd == L"query") {
            std::lock_guard<std::mutex> lock(g_ClientMutex);
            if (g_ActiveJobs.empty()) {
                SetColor(11); wcout << L"[*] Khong co tien trinh quet nao." << endl; SetColor(7);
            }
            else {
                SetColor(10); wcout << L"\n====== DANH SACH TIEN TRINH ======" << endl;
                for (const auto& pair : g_ActiveJobs) {
                    uint32_t jId = pair.first;
                    const auto& jInfo = pair.second;

                    int percent = (jInfo.totalFiles > 0) ? (jInfo.processedFiles * 100) / jInfo.totalFiles : 0;

                    wcout << L" [Job " << jId << L"] " << jInfo.path << endl;
                    wcout << L"    -> Tien do: " << jInfo.processedFiles << L" / " << jInfo.totalFiles
                        << L" files (" << percent << L"%)" << endl;
                    wcout << L"    -> Virus  : " << jInfo.totalThreats << endl;
                }
                wcout << L"==================================\n" << endl; SetColor(7);
            }
        }

        else if (cmd == L"scan") {
            if (arg.empty()) continue;
            auto now = std::chrono::steady_clock::now();
            auto elapsedSecs = std::chrono::duration_cast<std::chrono::seconds>(now - g_LastScanTime).count();
            if (elapsedSecs < RATE_LIMIT_SECONDS) {
                SetColor(12); wcout << L"[BLOCK] Vui long doi " << (RATE_LIMIT_SECONDS - elapsedSecs) << L"s..." << endl; SetColor(7);
                continue;
            }
            if (!IsPathAllowed(arg)) {
                SetColor(12); wcout << L"[ACCESS DENIED] Thu muc bi cam!" << endl; SetColor(7);
                continue;
            }

            g_LastScanTime = std::chrono::steady_clock::now();
            PayloadScanReq req; ZeroMemory(&req, sizeof(req)); req.priority = 1; req.timeoutMs = 5000;
            wcsncpy_s(req.filePath, arg.c_str(), 259);

            {
                std::lock_guard<std::mutex> lock(g_ClientMutex);
                g_PendingPaths.push(arg);
            }

            if (SendPacket(MSG_SCAN_REQ, &req, sizeof(req))) {
                SetColor(11);
                wcout << L"[+] Da chuyen lenh cho Server: " << arg << endl;
                wcout << L"[+] Dang mo cua so Monitor hien thi tien do..." << endl;
                SetColor(7);
            }
        }
    }

    if (g_hPipe != INVALID_HANDLE_VALUE) CloseHandle(g_hPipe);
    return 0;
}