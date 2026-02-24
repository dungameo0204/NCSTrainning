#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <map>
#include <condition_variable>
#include <filesystem>
#include <atomic> 
#include <algorithm> // Bổ sung thư viện này để dùng std::transform
#include "Protocol.h"    
#include "IPCManager.h"  

namespace fs = std::filesystem;
using namespace std;

// --- GLOBALS ---
SERVICE_STATUS        g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;
IPCManager            g_ipcManager;

// --- DATA STRUCTURES ---
struct JobContext {
    wstring filePath;
};

struct BatchContext {
    int32_t id;
    atomic<int32_t> totalFiles{ 0 };
    atomic<int32_t> processedFiles{ 0 };
    atomic<bool>    isLoadFinished{ false };
    wstring rootPath;
};

mutex g_JobMutex;
condition_variable g_cvQueue;

deque<int32_t> g_BatchOrder;
map<int32_t, deque<JobContext>> g_BatchJobs;
map<int32_t, shared_ptr<BatchContext>> g_AllBatches;
int32_t g_NextBatchId = 5000;

// --- SCANNER ENGINE ---
typedef int(__stdcall* FnScanFile)(const wchar_t*, int, void*);
typedef bool(__stdcall* FnInit)(const wchar_t*);
FnScanFile g_ScanFile = NULL;

bool LoadEngine() {
    wchar_t b[MAX_PATH]; GetModuleFileName(NULL, b, MAX_PATH); wstring p(b);
    SetCurrentDirectory(p.substr(0, p.find_last_of(L"\\/")).c_str());
    HMODULE h = LoadLibrary(L"ScannerEngine.dll");
    if (!h) return false;
    g_ScanFile = (FnScanFile)GetProcAddress(h, "EngineScanFile");
    FnInit init = (FnInit)GetProcAddress(h, "EngineInitialize");
    if (init) init(L"{ \"mode\": \"active\" }");
    return (g_ScanFile != NULL);
}

// --- KIỂM TRA POLICY: DANH SÁCH CẤM ---
bool IsPathDeniedInService(const std::wstring& path) {
    std::wstring lowerPath = path;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

    std::vector<std::wstring> denyList = {
        L"c:\\windows\\system32",
        L"c:\\$recycle.bin",
        L"c:\\$mfedeeprem"
    };

    for (const auto& deniedPath : denyList) {
        if (lowerPath.find(deniedPath) == 0) {
            return true;
        }
    }
    return false;
}

// --- WORKER THREAD (THỢ QUÉT) ---
void WorkerThreadFunc() {
    while (true) {
        JobContext currentJob;
        int32_t batchId = -1;
        shared_ptr<BatchContext> batchCtx;

        {
            unique_lock<mutex> lock(g_JobMutex);
            g_cvQueue.wait(lock, [] { return !g_BatchOrder.empty(); });

            batchId = g_BatchOrder.front();

            if (g_AllBatches.find(batchId) == g_AllBatches.end()) {
                g_BatchOrder.pop_front();
                continue;
            }
            batchCtx = g_AllBatches[batchId];

            if (g_BatchJobs[batchId].empty()) {
                if (batchCtx->isLoadFinished) {
                    g_BatchOrder.pop_front();

                    PayloadJobStatus status = { 0 }; status.jobId = batchId; status.status = 2;
                    wcscpy_s(status.message, L"Scan Finished");

                    lock.unlock();
                    g_ipcManager.Send(MSG_JOB_STATUS, &status, sizeof(status), true);
                    continue;
                }
                else {
                    g_cvQueue.wait(lock);
                    continue;
                }
            }

            currentJob = g_BatchJobs[batchId].front();
            g_BatchJobs[batchId].pop_front();
        }

        int result = g_ScanFile ? g_ScanFile(currentJob.filePath.c_str(), 0, NULL) : 0;

        PayloadJobStatus status = { 0 }; status.jobId = batchId; status.status = 1;
        wcsncpy_s(status.message, currentJob.filePath.c_str(), 255);
        g_ipcManager.Send(MSG_JOB_STATUS, &status, sizeof(status), false);

        if (batchCtx) {
            batchCtx->processedFiles++;
            if (result == 2) {
                wcscpy_s(status.message, L"VIRUS FOUND!"); status.result = 2;
                wcsncpy_s(status.threatList, currentJob.filePath.c_str(), 1000);
                g_ipcManager.Send(MSG_JOB_STATUS, &status, sizeof(status), true);
            }
        }
    }
}

// --- LOADER THREAD (THỢ BỐC VÁC TỐI ƯU CÓ POLICY) ---
void ThreadLoader(int32_t batchId, wstring rootPath) {
    shared_ptr<BatchContext> batchCtx;
    {
        lock_guard<mutex> lock(g_JobMutex);
        if (g_AllBatches.find(batchId) != g_AllBatches.end()) {
            batchCtx = g_AllBatches[batchId];
        }
    }

    if (!batchCtx) return;

    try {
        // Dùng directory_options để an toàn lướt qua các file không có quyền truy cập
        auto options = fs::directory_options::skip_permission_denied;
        fs::recursive_directory_iterator it(rootPath, options);
        fs::recursive_directory_iterator end;
        std::error_code ec; // Bắt lỗi hệ thống để không văng Crash

        while (it != end) {
            try {
                std::wstring currentPath = it->path().wstring();

                // ====================================================
                // 1. KIỂM TRA POLICY: TRÁNH BOM MÌN NGAY TỪ XA
                // ====================================================
                if (IsPathDeniedInService(currentPath)) {
                    // Nếu nó là THƯ MỤC CẤM -> Niêm phong, CẤM CHUI VÀO TRONG!
                    if (it->is_directory(ec)) {
                        it.disable_recursion_pending();
                    }

                    // Nhảy sang file/folder ngang hàng tiếp theo
                    it.increment(ec);
                    continue;
                }

                // ====================================================
                // 2. FILE HỢP LỆ -> GIAO CHO WORKER
                // ====================================================
                if (it->is_regular_file(ec)) {
                    {
                        lock_guard<mutex> lock(g_JobMutex);
                        g_BatchJobs[batchId].push_back({ currentPath });
                        batchCtx->totalFiles++;
                    }
                    g_cvQueue.notify_one();
                }
            }
            catch (...) {
                // Lỗi không đọc được 1 file cụ thể thì kệ nó, âm thầm bỏ qua
            }

            // Tiến tới file tiếp theo (dùng error_code để không bị văng Exception)
            it.increment(ec);
        }
    }
    catch (...) {
        // Lỗi không mở được thư mục gốc
    }

    // --- BÁO CÁO ĐÃ XONG ---
    {
        lock_guard<mutex> lock(g_JobMutex);
        batchCtx->isLoadFinished = true;
    }
    g_cvQueue.notify_all();
}

// --- XỬ LÝ TIN NHẮN TỪ CLIENT ---
void OnClientMessage(uint16_t type, const std::vector<uint8_t>& payload) {
    if (type == MSG_HELLO) {
        PayloadWelcome welcome = { 999, 2, "OK" };
        g_ipcManager.Send(MSG_WELCOME, &welcome, sizeof(welcome), true);
    }
    else if (type == MSG_RESUME) {
        auto resume = reinterpret_cast<const PayloadResume*>(payload.data());
        PayloadJobStatus status = { 0 };
        status.status = 1;
        wcscpy_s(status.message, L"--- CONNECTION RESUMED ---");
        g_ipcManager.Send(MSG_JOB_STATUS, &status, sizeof(status), true);
    }
    else if (type == MSG_SCAN_REQ) {
        auto req = reinterpret_cast<const PayloadScanReq*>(payload.data());

        int32_t batchId;
        {
            lock_guard<mutex> lock(g_JobMutex);
            batchId = g_NextBatchId++;

            auto ctx = make_shared<BatchContext>();
            ctx->id = batchId;
            ctx->rootPath = req->filePath;
            ctx->isLoadFinished = false;

            g_AllBatches[batchId] = ctx;
            g_BatchOrder.push_back(batchId);
        }

        PayloadScanResp resp = { (uint32_t)batchId, true };
        g_ipcManager.Send(MSG_SCAN_RESP, &resp, sizeof(resp), true);

        std::thread(ThreadLoader, batchId, wstring(req->filePath)).detach();
    }
}

// --- SERVICE MAIN ---
void WINAPI ServiceCtrlHandler(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING; SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        g_ipcManager.Stop(); SetEvent(g_ServiceStopEvent);
    }
}

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    g_StatusHandle = RegisterServiceCtrlHandler((argc > 0) ? argv[0] : (LPTSTR)L"MyAvServiceW6", ServiceCtrlHandler);
    if (!g_StatusHandle) return;

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    if (!LoadEngine()) { g_ServiceStatus.dwCurrentState = SERVICE_STOPPED; SetServiceStatus(g_StatusHandle, &g_ServiceStatus); return; }

    for (int i = 0; i < 4; i++) std::thread(WorkerThreadFunc).detach();

    g_ipcManager.SetCallback(OnClientMessage);
    if (g_ipcManager.Initialize()) {
        g_ipcManager.StartListening();
        WaitForSingleObject(g_ServiceStopEvent, INFINITE);
    }
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED; SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

int main() {
    SERVICE_TABLE_ENTRY st[] = { { (LPWSTR)L"", (LPSERVICE_MAIN_FUNCTION)ServiceMain }, { NULL, NULL } };
    StartServiceCtrlDispatcher(st);
    return 0;
}