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
    atomic<bool>    isLoadFinished{ false }; // [FIX] Cờ báo hiệu Loader đã xong việc chưa
    wstring rootPath;
};

mutex g_JobMutex;
condition_variable g_cvQueue;

// Danh sách các Batch đang chờ xử lý
deque<int32_t> g_BatchOrder;
// Map chứa công việc của từng Batch
map<int32_t, deque<JobContext>> g_BatchJobs;
// Map chứa thông tin quản lý Batch
map<int32_t, shared_ptr<BatchContext>> g_AllBatches; // Dùng shared_ptr cho an toàn
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

// --- WORKER THREAD (THỢ QUÉT) ---
void WorkerThreadFunc() {
    while (true) {
        JobContext currentJob;
        int32_t batchId = -1;
        shared_ptr<BatchContext> batchCtx;

        {
            unique_lock<mutex> lock(g_JobMutex);

            // Chờ cho đến khi có Batch ID trong hàng đợi
            g_cvQueue.wait(lock, [] { return !g_BatchOrder.empty(); });

            // Lấy Batch ID đầu tiên (nhưng chưa pop vội)
            batchId = g_BatchOrder.front();

            // Kiểm tra xem Batch này còn tồn tại không (phòng hờ)
            if (g_AllBatches.find(batchId) == g_AllBatches.end()) {
                g_BatchOrder.pop_front();
                continue;
            }
            batchCtx = g_AllBatches[batchId];

            // --- LOGIC QUAN TRỌNG: KHI NÀO THÌ XONG? ---
            if (g_BatchJobs[batchId].empty()) {
                // Nếu hết việc VÀ Loader báo đã xong -> Batch hoàn thành
                if (batchCtx->isLoadFinished) {
                    // Xóa Batch khỏi hàng đợi xử lý
                    g_BatchOrder.pop_front();

                    // Gửi tin báo Finished (CRITICAL = TRUE)
                    PayloadJobStatus status = { 0 }; status.jobId = batchId; status.status = 2;
                    wcscpy_s(status.message, L"Scan Finished");

                    // Mở khóa trước khi gửi mạng để tránh lock lâu
                    lock.unlock();
                    g_ipcManager.Send(MSG_JOB_STATUS, &status, sizeof(status), true);
                    continue;
                }
                else {
                    // Hết việc nhưng Loader CHƯA xong -> Worker tạm ngủ chờ Loader đẩy thêm hàng
                    g_cvQueue.wait(lock);
                    continue; // Quay lại đầu vòng lặp kiểm tra lại
                }
            }

            // Có việc -> Lấy ra làm
            currentJob = g_BatchJobs[batchId].front();
            g_BatchJobs[batchId].pop_front();
        }

        // --- XỬ LÝ SCAN (KHÔNG GIỮ LOCK) ---
        int result = g_ScanFile ? g_ScanFile(currentJob.filePath.c_str(), 0, NULL) : 0;

        // Gửi tin trạng thái "Scanning..." (VERBOSE = FALSE -> CÓ THỂ BỊ DROP)
        PayloadJobStatus status = { 0 }; status.jobId = batchId; status.status = 1;
        wcsncpy_s(status.message, currentJob.filePath.c_str(), 255);
        g_ipcManager.Send(MSG_JOB_STATUS, &status, sizeof(status), false);

        // Cập nhật tiến độ và báo Virus
        if (batchCtx) {
            batchCtx->processedFiles++;

            if (result == 2) {
                wcscpy_s(status.message, L"VIRUS FOUND!"); status.result = 2;
                wcsncpy_s(status.threatList, currentJob.filePath.c_str(), 1000);
                // Tin Virus là quan trọng -> CRITICAL = TRUE
                g_ipcManager.Send(MSG_JOB_STATUS, &status, sizeof(status), true);
            }
        }
        // Worker làm xong 1 file thì quay lại vòng lặp ngay
    }
}

// --- LOADER THREAD (THỢ BỐC VÁC) ---
// --- LOADER THREAD (THỢ BỐC VÁC) - BẢN FIX LỖI BIÊN DỊCH ---
void ThreadLoader(int32_t batchId, wstring rootPath) {
    // Kiểm tra xem Batch còn tồn tại không để tránh Crash
    shared_ptr<BatchContext> batchCtx;
    {
        lock_guard<mutex> lock(g_JobMutex);
        if (g_AllBatches.find(batchId) != g_AllBatches.end()) {
            batchCtx = g_AllBatches[batchId];
        }
    }

    if (!batchCtx) return; // Batch đã bị hủy

    try {
        // [FIX] Bỏ 'options' đi để tương thích với C++ cũ
        // Chỉ dùng iterator mặc định
        for (auto& entry : fs::recursive_directory_iterator(rootPath)) {
            try {
                if (fs::is_regular_file(entry)) {
                    {
                        lock_guard<mutex> lock(g_JobMutex);
                        g_BatchJobs[batchId].push_back({ entry.path().wstring() });
                        batchCtx->totalFiles++;
                    }
                    // Hú Worker dậy làm việc ngay
                    g_cvQueue.notify_one();
                }
            }
            catch (...) {
                // Bỏ qua file lỗi (Access Denied v.v...)
                continue;
            }
        }
    }
    catch (...) {
        // Bắt lỗi nếu không mở được thư mục gốc
    }

    // --- BÁO CÁO ĐÃ XONG ---
    {
        lock_guard<mutex> lock(g_JobMutex);
        batchCtx->isLoadFinished = true; // Đánh dấu đã load xong
    }
    g_cvQueue.notify_all(); // Hú tất cả Worker dậy để chốt đơn
}

// --- XỬ LÝ TIN NHẮN TỪ CLIENT ---
void OnClientMessage(uint16_t type, const std::vector<uint8_t>& payload) {
    if (type == MSG_HELLO) {
        PayloadWelcome welcome = { 999, 2, "OK" };
        g_ipcManager.Send(MSG_WELCOME, &welcome, sizeof(welcome), true);
    }
    else if (type == MSG_SCAN_REQ) {
        auto req = reinterpret_cast<const PayloadScanReq*>(payload.data());

        int32_t batchId;
        {
            lock_guard<mutex> lock(g_JobMutex);
            batchId = g_NextBatchId++;

            // Tạo Batch mới
            auto ctx = make_shared<BatchContext>();
            ctx->id = batchId;
            ctx->rootPath = req->filePath;
            ctx->isLoadFinished = false; // Mới vào chưa xong

            g_AllBatches[batchId] = ctx;

            // [FIX] Đẩy Batch ID vào hàng đợi NGAY LẬP TỨC để Worker sẵn sàng
            g_BatchOrder.push_back(batchId);
        }

        PayloadScanResp resp = { (uint32_t)batchId, true };
        g_ipcManager.Send(MSG_SCAN_RESP, &resp, sizeof(resp), true);

        // Chạy Loader ở Background
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

    // Start 4 Worker Threads
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