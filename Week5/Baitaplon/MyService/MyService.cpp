#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <map>
#include <condition_variable>
#include <filesystem>
#include "Protocol.h"
#include <chrono> // Để tính thời gian TTL
#include <unordered_map> // Bảng băm (Hash Map) chuẩn C++
#include <pdh.h>
#pragma comment(lib, "pdh.lib") // Tự động link thư viện PDH

namespace fs = std::filesystem;
using namespace std;

// --- 1. KHAI BÁO SERVICE ---
#define SERVICE_NAME  L"MyAvService"

SERVICE_STATUS        g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;

// --- LOGGING (VÌ KHÔNG CÓ MÀN HÌNH CONSOLE) ---
void WriteLog(string message) {
    ofstream logFile;
    // Ghi log vào ổ C để dễ tìm (Cần Run as Admin mới ghi được)
    logFile.open("C:\\AvService_Log.txt", ios_base::app);
    if (logFile.is_open()) {
        logFile << message << endl;
        logFile.close();
    }
}

// Hàm Log hỗ trợ wstring
void WriteLogW(wstring message) {
    string str(message.begin(), message.end()); // Convert thô
    WriteLog(str);
}

// --- 2. CÁC ĐỊNH NGHĨA DLL & STRUCT ---

typedef void(__stdcall* FnProgressCallback)(int, const wchar_t*);
typedef int(__stdcall* FnScanFile)(const wchar_t*, int, FnProgressCallback);
typedef bool(__stdcall* FnInit)(const wchar_t*);
typedef int(__stdcall* FnGetVersion)();
typedef void(__stdcall* FnShutdown)();

HMODULE g_hDll = NULL;
FnScanFile g_ScanFile = NULL;
FnInit g_EngineInit = NULL;
FnGetVersion g_GetVersion = NULL;
FnShutdown g_EngineShutdown = NULL;

// --- MONITOR SYSTEM VARS ---
PDH_HQUERY g_PdhQuery = NULL;
PDH_HCOUNTER g_PdhCpuTotal, g_PdhDiskQueue, g_PdhRamAvailable;
std::once_flag g_MonitorInitFlag; // Cờ để chỉ init Monitor 1 lần

enum JobState { JOB_PENDING = 0, JOB_RUNNING = 1, JOB_COMPLETED = 2, JOB_CANCELLED = 3 };
enum SystemState { SYS_IDLE, SYS_BUSY, SYS_OVERLOADED };

struct JobContext {
    int32_t id = 0;
    int32_t parentBatchId = 0;
    wstring filePath = L"";
    int32_t status = 0;
    int32_t result = 0;
    int32_t priority = 0;
};

struct BatchContext {
    int32_t id = 0;
    int32_t totalFiles = 0;
    int32_t processedFiles = 0;
    int32_t detectedCount = 0;
    int32_t suspiciousCount = 0;
    bool    isCancelled = false;
    wstring rootPath = L"";
    int32_t status = 0;
};

struct CacheEntry {
    int result; // 0=Safe, 1=Suspicious, 2=Virus
    std::chrono::steady_clock::time_point timestamp; // Thời điểm lưu cache
};

// Cấu hình TTL (Time To Live) và Ngưỡng quá tải
const int CACHE_TTL_SECONDS = 600;
const int CPU_OVERLOAD_THRESHOLD = 95; // CPU > 90% -> Ngất
const int RAM_LOW_THRESHOLD_MB = 50;  // RAM < 200MB -> Ngất
const double DISK_QUEUE_THRESHOLD = 2.0;

// Biến toàn cục quản lý Job & Cache
std::unordered_map<size_t, CacheEntry> g_FileCache;
std::mutex g_CacheMutex;
mutex g_JobMutex;
condition_variable g_cvQueue;
deque<int32_t> g_JobQueue;
map<int32_t, JobContext> g_AllJobs;
map<int32_t, BatchContext> g_AllBatches;
int32_t g_NextJobId = 1;
int32_t g_NextBatchId = 5000;

// --- 3. CÁC HÀM HỖ TRỢ (Monitor, Hash, LoadEngine) ---

// Khởi tạo bộ đếm PDH (Chạy 1 lần lúc đầu)
void InitSystemMonitor() {
    if (PdhOpenQuery(NULL, 0, &g_PdhQuery) == ERROR_SUCCESS) {
        PdhAddCounter(g_PdhQuery, L"\\Processor(_Total)\\% Processor Time", 0, &g_PdhCpuTotal);
        PdhAddCounter(g_PdhQuery, L"\\PhysicalDisk(_Total)\\Current Disk Queue Length", 0, &g_PdhDiskQueue);
        PdhAddCounter(g_PdhQuery, L"\\Memory\\Available MBytes", 0, &g_PdhRamAvailable);
        PdhCollectQueryData(g_PdhQuery); // Collect lần đầu
    }
}

// Hàm lấy trạng thái máy
SystemState GetSystemHealth() {
    if (!g_PdhQuery) return SYS_IDLE;

    PdhCollectQueryData(g_PdhQuery);

    PDH_FMT_COUNTERVALUE cpuVal, diskVal, ramVal;
    PdhGetFormattedCounterValue(g_PdhCpuTotal, PDH_FMT_LONG, NULL, &cpuVal);
    PdhGetFormattedCounterValue(g_PdhDiskQueue, PDH_FMT_DOUBLE, NULL, &diskVal);
    PdhGetFormattedCounterValue(g_PdhRamAvailable, PDH_FMT_LONG, NULL, &ramVal);

    if (cpuVal.longValue > CPU_OVERLOAD_THRESHOLD ||
        diskVal.doubleValue > DISK_QUEUE_THRESHOLD ||
        ramVal.longValue < RAM_LOW_THRESHOLD_MB) {
        return SYS_OVERLOADED;
    }
    if (cpuVal.longValue > 50) return SYS_BUSY;
    return SYS_IDLE;
}

// Hàm băm file (FNV-1a like)
size_t CalculateFileHash(const wstring& path, uintmax_t fileSize, fs::file_time_type fileTime) {
    size_t h1 = std::hash<wstring>{}(path);
    size_t h2 = std::hash<uintmax_t>{}(fileSize);
    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        fileTime - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
    std::time_t tt = std::chrono::system_clock::to_time_t(sctp);
    size_t h3 = std::hash<std::time_t>{}(tt);
    return h1 ^ (h2 << 1) ^ (h3 << 1);
}

bool LoadEngine() {
    WriteLog("[Info] Loading Engine DLL...");
    wchar_t buffer[MAX_PATH];
    GetModuleFileName(NULL, buffer, MAX_PATH);
    wstring exePath(buffer);
    wstring dir = exePath.substr(0, exePath.find_last_of(L"\\/"));
    SetCurrentDirectory(dir.c_str());

    g_hDll = LoadLibrary(L"ScannerEngine.dll");
    if (!g_hDll) {
        WriteLog("[Error] Cannot load ScannerEngine.dll");
        return false;
    }

    g_ScanFile = (FnScanFile)GetProcAddress(g_hDll, "EngineScanFile");
    g_EngineInit = (FnInit)GetProcAddress(g_hDll, "EngineInitialize");
    g_GetVersion = (FnGetVersion)GetProcAddress(g_hDll, "EngineGetVersion");

    if (!g_ScanFile || !g_EngineInit || !g_GetVersion) return false;
    g_EngineInit(L"{ \"mode\": \"active\" }");
    WriteLog("[Info] Engine Loaded Success.");
    return true;
}

bool SendPacket(HANDLE hPipe, int32_t type, const void* data, int32_t size) {
    PacketHeader header = { type, size };
    DWORD written;
    if (!WriteFile(hPipe, &header, sizeof(header), &written, NULL)) return false;
    if (size > 0) WriteFile(hPipe, data, size, &written, NULL);
    return true;
}

void __stdcall OnScanProgress(int percent, const wchar_t* status) {}

// --- 4. WORKER THREAD (TRÁI TIM CỦA SERVICE) ---
void WorkerThreadFunc() {
    // Init Monitor 1 lần duy nhất
    std::call_once(g_MonitorInitFlag, InitSystemMonitor);

    while (true) {
        int32_t jobId = -1;
        int32_t batchId = -1;
        wstring filePath;
        int32_t jobPriority = 0;

        // --- GIAI ĐOẠN 1: LẤY VIỆC (CÓ THROTTLING) ---
        {
            unique_lock<mutex> lock(g_JobMutex);
            g_cvQueue.wait(lock, [] { return !g_JobQueue.empty(); });

            // A. Kiểm tra sức khỏe hệ thống
            SystemState health = GetSystemHealth();

            int peekId = g_JobQueue.front();
            jobPriority = g_AllJobs[peekId].priority;

            // B. Quyết định: Làm hay Nghỉ?
            if (health == SYS_OVERLOADED && jobPriority == 0) {
                lock.unlock(); // Nhả khóa
                std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Ngủ bù
                continue;
            }

            // C. Lấy việc thật sự
            jobId = g_JobQueue.front();
            g_JobQueue.pop_front();

            batchId = g_AllJobs[jobId].parentBatchId;

            // D. Kiểm tra Cancel
            if (g_AllBatches[batchId].isCancelled) {
                g_AllJobs[jobId].status = JOB_CANCELLED;
                g_AllBatches[batchId].processedFiles++;
                continue;
            }

            g_AllJobs[jobId].status = JOB_RUNNING;
            filePath = g_AllJobs[jobId].filePath;
        }

        // --- GIAI ĐOẠN 2: XỬ LÝ (CACHE + SCAN) ---
        int result = 0;
        bool isCacheHit = false;

        try {
            std::error_code ec;
            auto fSize = fs::file_size(filePath, ec);
            auto fTime = fs::last_write_time(filePath, ec);

            if (!ec) {
                size_t fileHash = CalculateFileHash(filePath, fSize, fTime);

                // Check Cache
                {
                    lock_guard<mutex> cacheLock(g_CacheMutex);
                    auto it = g_FileCache.find(fileHash);
                    if (it != g_FileCache.end()) {
                        auto now = std::chrono::steady_clock::now();
                        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.timestamp).count();

                        if (elapsed < CACHE_TTL_SECONDS) {
                            result = it->second.result;
                            isCacheHit = true;
                        }
                        else {
                            g_FileCache.erase(it);
                        }
                    }
                }

                // Nếu Cache Miss -> Scan thật
                if (!isCacheHit) {
                    result = g_ScanFile(filePath.c_str(), 0, OnScanProgress);
                    // Lưu Cache
                    {
                        lock_guard<mutex> cacheLock(g_CacheMutex);
                        CacheEntry entry;
                        entry.result = result;
                        entry.timestamp = std::chrono::steady_clock::now();
                        g_FileCache[fileHash] = entry;
                    }
                }
            }
            else {
                // Lỗi đọc file -> Vẫn thử quét
                result = g_ScanFile(filePath.c_str(), 0, OnScanProgress);
            }
        }
        catch (...) { result = 0; }

        // --- GIAI ĐOẠN 3: CẬP NHẬT TRẠNG THÁI ---
        {
            lock_guard<mutex> lock(g_JobMutex);

            if (g_AllBatches[batchId].isCancelled) {
                g_AllJobs[jobId].status = JOB_CANCELLED;
            }
            else {
                g_AllJobs[jobId].status = JOB_COMPLETED;
                g_AllJobs[jobId].result = result;
                g_AllBatches[batchId].processedFiles++;

                if (result == 2) {
                    g_AllBatches[batchId].detectedCount++;
                    WriteLogW(L"[VIRUS] Found in: " + filePath);
                }
                else if (result == 1) {
                    g_AllBatches[batchId].suspiciousCount++;
                    WriteLogW(L"[SUSPICIOUS] Found in: " + filePath);
                }

                if (isCacheHit) {
                    WriteLogW(L"[CACHE HIT] Skipped: " + filePath); 
                }
            }

            if (g_AllBatches[batchId].processedFiles >= g_AllBatches[batchId].totalFiles) {
                g_AllBatches[batchId].status = JOB_COMPLETED;
                WriteLogW(L"[Batch] FINISHED Batch " + to_wstring(batchId));
            }
        }
    }
}

void InternalAddJob(wstring path, int parentBatchId) {
    int32_t newId = g_NextJobId++;
    JobContext job;
    job.id = newId;
    job.parentBatchId = parentBatchId;
    job.filePath = path;
    job.status = JOB_PENDING;
    job.priority = 0; // Mặc định Low
    g_AllJobs[newId] = job;
    g_JobQueue.push_back(newId);
}

// --- 5. CÁC HÀM XỬ LÝ LỆNH CLIENT ---

void HandleScanRequest(HANDLE hPipe) {
    PayloadScanReq req;
    DWORD read;
    ReadFile(hPipe, &req, sizeof(req), &read, NULL);
    WriteLogW(L"[Cmd] Scan Request: " + wstring(req.filePath));

    int32_t batchId;
    int count = 0;
    {
        lock_guard<mutex> lock(g_JobMutex);
        batchId = g_NextBatchId++;
        BatchContext batch;
        batch.id = batchId;
        batch.rootPath = req.filePath;
        batch.isCancelled = false;
        batch.status = JOB_RUNNING;

        try {
            if (fs::is_directory(req.filePath)) {
                // Tự động bỏ qua lỗi Access Denied để quét sâu
                auto options = fs::directory_options::skip_permission_denied;
                std::error_code ec;
                auto it = fs::recursive_directory_iterator(req.filePath, options, ec);
                auto end = fs::recursive_directory_iterator();

                while (it != end) {
                    if (ec) { it.increment(ec); continue; }
                    const auto& entry = *it;
                    try {
                        if (fs::is_regular_file(entry, ec) && !ec) {
                            InternalAddJob(entry.path().wstring(), batchId);
                            count++;
                        }
                    }
                    catch (...) {}
                    it.increment(ec);
                }
            }
            else {
                InternalAddJob(req.filePath, batchId);
                count = 1;
            }
        }
        catch (...) {}

        batch.totalFiles = count;
        g_AllBatches[batchId] = batch;
    }
    g_cvQueue.notify_all();

    PayloadScanResp resp = { batchId, true };
    SendPacket(hPipe, MSG_SCAN_RESP, &resp, sizeof(resp));
}

void HandleQueryRequest(HANDLE hPipe) {
    PayloadQueryJob req;
    DWORD read;
    ReadFile(hPipe, &req, sizeof(req), &read, NULL);

    PayloadJobStatus resp = { 0 };
    resp.jobId = req.jobId;

    {
        lock_guard<mutex> lock(g_JobMutex);
        if (g_AllBatches.find(req.jobId) != g_AllBatches.end()) {
            BatchContext& b = g_AllBatches[req.jobId];
            resp.status = b.isCancelled ? JOB_CANCELLED : b.status;

            if (b.totalFiles > 0) resp.progress = (b.processedFiles * 100) / b.totalFiles;
            else resp.progress = 100;

            // Logic màu sắc: Virus(2) > Suspicious(1) > Clean(0)
            if (b.detectedCount > 0) resp.result = 2;
            else if (b.suspiciousCount > 0) resp.result = 1;
            else resp.result = 0;

            if (b.isCancelled) wcscpy_s(resp.message, L"Cancelled");
            else if (b.processedFiles < b.totalFiles) {
                wstring msg = L"Scan: " + to_wstring(b.processedFiles) + L"/" + to_wstring(b.totalFiles);
                wcscpy_s(resp.message, msg.c_str());
            }
            else {
                wstring msg = L"Done. Virus: " + to_wstring(b.detectedCount) +
                    L" | Suspicious: " + to_wstring(b.suspiciousCount);
                wcscpy_s(resp.message, msg.c_str());
            }
        }
        else {
            wcscpy_s(resp.message, L"Not Found");
        }
    }
    SendPacket(hPipe, MSG_JOB_STATUS, &resp, sizeof(resp));
}

void HandleCancelRequest(HANDLE hPipe) {
    PayloadCancelJob req;
    DWORD read;
    ReadFile(hPipe, &req, sizeof(req), &read, NULL);
    WriteLogW(L"[Cmd] CANCEL REQUEST for Batch: " + to_wstring(req.jobId));

    {
        lock_guard<mutex> lock(g_JobMutex);
        if (g_AllBatches.find(req.jobId) != g_AllBatches.end()) {
            // 1. Đánh dấu hủy
            g_AllBatches[req.jobId].isCancelled = true;
            g_AllBatches[req.jobId].status = JOB_CANCELLED;

            // 2. --- LOGIC "DỌN RÁC" SIÊU TỐC ---
            // Mục tiêu: Xóa ngay lập tức các Job của Batch này khỏi hàng đợi

            deque<int32_t> cleanQueue; // Hàng đợi mới sạch sẽ
            int removedCount = 0;

            // Duyệt qua hàng đợi hiện tại
            for (int32_t id : g_JobQueue) {
                // Nếu Job thuộc về Batch khác (ví dụ 5002) -> Giữ lại
                if (g_AllJobs[id].parentBatchId != req.jobId) {
                    cleanQueue.push_back(id);
                }
                else {
                    // Nếu thuộc Batch đang hủy -> Vứt đi luôn
                    // Cập nhật trạng thái để sau này Query không bị lỗi
                    g_AllJobs[id].status = JOB_CANCELLED;
                    removedCount++;
                }
            }

            // Tráo hàng đợi: Thay hàng đợi cũ bằng hàng đợi mới đã lọc
            g_JobQueue = std::move(cleanQueue);

            // Cập nhật tiến độ giả (để thanh hiển thị Client chạy full luôn cho đẹp)
            g_AllBatches[req.jobId].processedFiles += removedCount;

            WriteLogW(L"[Fast Cancel] Removed " + to_wstring(removedCount) + L" pending jobs from Queue.");
        }
    }

    // Đánh thức thợ dậy (để thợ thấy hàng đợi thay đổi và làm việc tiếp)
    g_cvQueue.notify_all();

    PayloadScanResp resp = { req.jobId, true };
    SendPacket(hPipe, MSG_SCAN_RESP, &resp, sizeof(resp));
}

// --- 6. SERVICE MAIN FUNCTIONS ---

void ReportServiceStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint) {
    static DWORD dwCheckPoint = 1;
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = dwCurrentState;
    g_ServiceStatus.dwWin32ExitCode = dwWin32ExitCode;
    g_ServiceStatus.dwWaitHint = dwWaitHint;

    if (dwCurrentState == SERVICE_START_PENDING) g_ServiceStatus.dwControlsAccepted = 0;
    else g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    if ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED))
        g_ServiceStatus.dwCheckPoint = 0;
    else g_ServiceStatus.dwCheckPoint = dwCheckPoint++;

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

void WINAPI ServiceCtrlHandler(DWORD dwCtrl) {
    if (dwCtrl == SERVICE_CONTROL_STOP) {
        ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
        SetEvent(g_ServiceStopEvent);
        ReportServiceStatus(g_ServiceStatus.dwCurrentState, NO_ERROR, 0);
    }
}

void ServiceWorkerThread() {
    WriteLog("Worker Started. Loading Engine...");
    if (!LoadEngine()) {
        WriteLog("Load Engine Failed!");
        return;
    }

    WriteLog("Starting Threads...");
    // 4 Worker Threads
    thread t1(WorkerThreadFunc); thread t2(WorkerThreadFunc);
    thread t3(WorkerThreadFunc); thread t4(WorkerThreadFunc);
    t1.detach(); t2.detach(); t3.detach(); t4.detach();

    WriteLog("Creating Pipe...");
    HANDLE hPipe = CreateNamedPipe(L"\\\\.\\pipe\\AvScanPipe",
        PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE) { WriteLog("Create Pipe Failed!"); return; }

    WriteLog("Service Ready! Waiting for Client commands...");

    while (true) {
        if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
            WriteLog("Client Connected.");
            while (true) {
                PacketHeader header;
                DWORD bytesRead;
                if (!ReadFile(hPipe, &header, sizeof(header), &bytesRead, NULL)) break;
                switch (header.type) {
                case MSG_HELLO: break;
                case MSG_SCAN_REQ: HandleScanRequest(hPipe); break;
                case MSG_QUERY_JOB: HandleQueryRequest(hPipe); break;
                case MSG_CANCEL_JOB: HandleCancelRequest(hPipe); break;
                }
            }
            DisconnectNamedPipe(hPipe);
            WriteLog("Client Disconnected.");
        }
        if (WaitForSingleObject(g_ServiceStopEvent, 0) == WAIT_OBJECT_0) {
            WriteLog("Stop Event Received. Exiting Worker.");
            break;
        }
    }
    CloseHandle(hPipe);
}

void WINAPI ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv) {
    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
    if (!g_StatusHandle) return;

    ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_ServiceStopEvent) { ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0); return; }

    ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);
    ServiceWorkerThread();
    ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

int main() {
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        { (LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    if (StartServiceCtrlDispatcher(ServiceTable) == FALSE) {
        cout << "Chuong trinh nay la Windows Service." << endl;
        cout << "Hay cai dat bang lenh: sc create MyAvService binPath= ... start= auto" << endl;
        cout << "Sau do start bang lenh: sc start MyAvService" << endl;
        return 1;
    }
    return 0;
}