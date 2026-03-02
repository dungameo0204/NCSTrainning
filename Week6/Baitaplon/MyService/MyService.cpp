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
#include <algorithm>
#include <unordered_map>
#include <fstream>
#include <codecvt> 
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
	atomic<bool>    isCancelled{ false };

	// [MỚI] GIỎ ĐỰNG DANH SÁCH VIRUS & ĐIỂM SỐ
	mutex threatMutex;
	vector<pair<wstring, float>> infectedFiles;
};

mutex g_JobMutex;
condition_variable g_cvQueue;

deque<int32_t> g_BatchOrder;
map<int32_t, deque<JobContext>> g_BatchJobs;
map<int32_t, shared_ptr<BatchContext>> g_AllBatches;
int32_t g_NextBatchId = 5000;

// ==========================================
// HỆ THỐNG CACHE THÔNG MINH (SMART CACHE)
// ==========================================
struct CacheEntry {
	int result;            // 0: Sạch, 2: Virus
	uintmax_t fileSize;
	long long writeTime;
	float score;           // [MỚI] Lưu thêm điểm Heuristic vào RAM
};

std::unordered_map<std::wstring, CacheEntry> g_ScanCache;
std::mutex g_CacheMutex;
long long g_EngineVersion = 0;

long long GetEngineVersion() {
	try {
		return fs::last_write_time(L"ScannerEngine.dll").time_since_epoch().count();
	}
	catch (...) { return 0; }
}

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

void LoadCacheFromDisk() {
	g_EngineVersion = GetEngineVersion();

	std::wifstream file(L"scan_cache.bin", std::ios::binary);
	if (!file.is_open()) return;

	long long savedEngineVer = 0;
	size_t cacheSize = 0;

	file.read((wchar_t*)&savedEngineVer, sizeof(savedEngineVer));

	if (savedEngineVer != g_EngineVersion) {
		std::cout << "[CACHE] Phat hien Engine moi! Xoa so Cache cu." << std::endl;
		return;
	}

	file.read((wchar_t*)&cacheSize, sizeof(cacheSize));

	for (size_t i = 0; i < cacheSize; i++) {
		size_t pathLen = 0;
		file.read((wchar_t*)&pathLen, sizeof(pathLen));

		std::wstring path; path.resize(pathLen);
		file.read(&path[0], pathLen * sizeof(wchar_t));

		CacheEntry entry;
		file.read((wchar_t*)&entry, sizeof(CacheEntry));

		g_ScanCache[path] = entry;
	}
	std::cout << "[CACHE] Nap thanh cong " << g_ScanCache.size() << " file vao RAM." << std::endl;
}

void SaveCacheToDisk() {
	std::lock_guard<std::mutex> lock(g_CacheMutex);
	std::wofstream file(L"scan_cache.bin", std::ios::binary | std::ios::trunc);
	if (!file.is_open()) return;

	file.write((const wchar_t*)&g_EngineVersion, sizeof(g_EngineVersion));
	size_t cacheSize = g_ScanCache.size();
	file.write((const wchar_t*)&cacheSize, sizeof(cacheSize));

	for (const auto& pair : g_ScanCache) {
		size_t pathLen = pair.first.size();
		file.write((const wchar_t*)&pathLen, sizeof(pathLen));
		file.write(pair.first.c_str(), pathLen * sizeof(wchar_t));
		file.write((const wchar_t*)&pair.second, sizeof(CacheEntry));
	}
	std::cout << "[CACHE] Da luu " << cacheSize << " file xuong o cung." << std::endl;
}

bool IsPathDeniedInService(const std::wstring& path) {
	std::wstring lowerPath = path;
	std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

	std::vector<std::wstring> denyList = {
		L"c:\\windows\\system32",
		L"c:\\$recycle.bin",
		L"c:\\$mfedeeprem"
	};

	for (const auto& deniedPath : denyList) {
		if (lowerPath.find(deniedPath) == 0) return true;
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

			// NẾU HẾT FILE THÌ CHỐT SỔ VÀ BÁO CÁO DANH SÁCH VIRUS
			if (g_BatchJobs[batchId].empty()) {
				if (batchCtx->isLoadFinished) {
					g_BatchOrder.pop_front();

					PayloadJobStatus status = { 0 };
					status.jobId = batchId;
					status.status = 2; // Finished
					status.totalFiles = batchCtx->totalFiles.load();
					status.processedFiles = batchCtx->processedFiles.load();

					// [MỚI] TỔNG HỢP DANH SÁCH MÀ XUẤT RA FILE LOG
					lock_guard<mutex> threatLock(batchCtx->threatMutex);
					status.totalThreats = (uint32_t)batchCtx->infectedFiles.size();
					if (batchCtx->infectedFiles.empty()) {
						wcscpy_s(status.message, L"Scan Finished: Safe! No threats found.");
						status.result = 0;
					}
					else {
						// 1. TẠO FILE BÁO CÁO (LOG FILE)
						wstring logFileName = L"ScanReport_Job" + to_wstring(batchId) + L".txt";

						// Chuyển sang UTF-8 để ghi file txt không bị lỗi font tiếng Việt
						wofstream logFile(logFileName, ios::out | ios::trunc);

						// [FIX LỖI C4996] Ép Visual Studio câm mồm không được báo lỗi Deprecated của C++17
#pragma warning(push)
#pragma warning(disable: 4996)
						logFile.imbue(locale(locale::empty(), new codecvt_utf8<wchar_t>));
#pragma warning(pop)

						if (logFile.is_open()) {
							logFile << L"==========================================================\n";
							logFile << L"            BÁO CÁO QUÉT MÃ ĐỘC (HEURISTIC ENGINE)        \n";
							logFile << L"==========================================================\n";
							logFile << L"Thư mục gốc : " << batchCtx->rootPath << L"\n";
							logFile << L"Tổng số file: " << batchCtx->processedFiles.load() << L" files\n";
							logFile << L"Phát hiện   : " << batchCtx->infectedFiles.size() << L" THREATS!\n";
							logFile << L"----------------------------------------------------------\n";

							// Ghi toàn bộ danh sách virus vào file
							for (const auto& threat : batchCtx->infectedFiles) {
								logFile << L"[Điểm: " << fixed << setprecision(1) << threat.second << L"] -> " << threat.first << L"\n";
							}
							logFile << L"==========================================================\n";
							logFile.close();
						}

						// 2. NHÉT PREVIEW VÀO THREAT LIST GỬI CHO CLIENT (Giới hạn 900 ký tự để không tràn)
						swprintf(status.message, 255, L"Phat hien %zu VIRUS! Đa luu file: %s", batchCtx->infectedFiles.size(), logFileName.c_str());
						status.result = 2;

						wstring aggregateList = L"";
						for (const auto& threat : batchCtx->infectedFiles) {
							wchar_t line[512];
							swprintf(line, 512, L"[%.1f diem] %s\n", threat.second, threat.first.c_str());

							// Nếu vẫn còn chỗ trong gói tin IPC thì nhét tiếp
							if (aggregateList.length() + wcslen(line) < 900) {
								aggregateList += line;
							}
							else {
								// Nếu đầy rồi thì chèn câu nhắc người dùng mở file Log ra xem
								aggregateList += L"\n... (Và nhiều file khác. Mở file " + logFileName + L" để xem toàn bộ!)";
								break;
							}
						}
						wcsncpy_s(status.threatList, aggregateList.c_str(), 1000);
					}

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

		if (batchCtx->isCancelled) continue;

		int result = 0;
		bool needScan = true;
		uintmax_t currentSize = 0;
		long long currentTime = 0;
		float currentScore = 0.0f; // [MỚI] Hứng điểm từ DLL

		try {
			currentSize = fs::file_size(currentJob.filePath);
			currentTime = fs::last_write_time(currentJob.filePath).time_since_epoch().count();

			std::lock_guard<std::mutex> cacheLock(g_CacheMutex);
			auto it = g_ScanCache.find(currentJob.filePath);

			if (it != g_ScanCache.end()) {
				if (it->second.fileSize == currentSize && it->second.writeTime == currentTime) {
					result = it->second.result;
					currentScore = it->second.score; // Kéo điểm từ RAM ra
					needScan = false;
				}
			}
		}
		catch (...) {}

		// 2. GỌI DLL QUÉT
		if (needScan) {
			// [MỚI] Truyền con trỏ &currentScore vào tham số thứ 3
			result = g_ScanFile ? g_ScanFile(currentJob.filePath.c_str(), 0, &currentScore) : 0;

			std::lock_guard<std::mutex> cacheLock(g_CacheMutex);
			g_ScanCache[currentJob.filePath] = { result, currentSize, currentTime, currentScore };
		}

		// 3. XỬ LÝ NẾU TÓM ĐƯỢC VIRUS
		PayloadJobStatus status = { 0 };
		status.jobId = batchId;
		status.status = 1; // Scanning
		wcsncpy_s(status.message, currentJob.filePath.c_str(), 255);

		if (batchCtx) {
			batchCtx->processedFiles++;

			status.totalFiles = batchCtx->totalFiles.load();
			status.processedFiles = batchCtx->processedFiles.load();
			{
				lock_guard<mutex> threatLock(batchCtx->threatMutex);
				status.totalThreats = (uint32_t)batchCtx->infectedFiles.size();
			}

			if (result == 2) {
				// Nhét vào giỏ rác của mẻ quét hiện tại
				{
					lock_guard<mutex> threatLock(batchCtx->threatMutex);
					batchCtx->infectedFiles.push_back({ currentJob.filePath, currentScore });
					status.totalThreats = (uint32_t)batchCtx->infectedFiles.size();
				}

				wcscpy_s(status.message, L"VIRUS FOUND!");
				status.result = 2;
				// Báo động trực tiếp file này về Client
				swprintf(status.threatList, 1000, L"[%.1f diem] %s", currentScore, currentJob.filePath.c_str());
				g_ipcManager.Send(MSG_JOB_STATUS, &status, sizeof(status), true);
			}
			else {
				g_ipcManager.Send(MSG_JOB_STATUS, &status, sizeof(status), false);
			}
		}
	}
}

// --- LOADER THREAD ---
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
		auto options = fs::directory_options::skip_permission_denied;
		fs::recursive_directory_iterator it(rootPath, options);
		fs::recursive_directory_iterator end;
		std::error_code ec;

		while (it != end) {
			if (batchCtx->isCancelled) break;
			try {
				std::wstring currentPath = it->path().wstring();

				if (IsPathDeniedInService(currentPath)) {
					if (it->is_directory(ec)) it.disable_recursion_pending();
					it.increment(ec);
					continue;
				}

				if (it->is_regular_file(ec)) {
					int currentTotal = 0;
					{
						lock_guard<mutex> lock(g_JobMutex);
						g_BatchJobs[batchId].push_back({ currentPath });
						batchCtx->totalFiles++;
						currentTotal = batchCtx->totalFiles.load();
					}
					g_cvQueue.notify_one();

					if (currentTotal % 2000 == 0) {
						PayloadJobStatus status = { 0 };
						status.jobId = batchId;
						status.status = 1;
						status.totalFiles = currentTotal;
						status.processedFiles = batchCtx->processedFiles.load();
						wcscpy_s(status.message, L"... [He thong] Dang gom file vao hang doi ...");
						g_ipcManager.Send(MSG_JOB_STATUS, &status, sizeof(status), false);
					}
				}
			}
			catch (...) {}
			it.increment(ec);
		}
	}
	catch (...) {}

	{
		lock_guard<mutex> lock(g_JobMutex);
		batchCtx->isLoadFinished = true;
	}
	g_cvQueue.notify_all();
}

// --- XỬ LÝ TIN NHẮN TỪ CLIENT ---
void OnClientMessage(uint16_t type, const std::vector<uint8_t>& payload) {
	if (type == MSG_HELLO || type == MSG_RESUME) {

		// 1. Nếu là Client mới bật lên, gửi lệnh Welcome trước
		if (type == MSG_HELLO) {
			PayloadWelcome welcome = { 999, 2, "OK" };
			g_ipcManager.Send(MSG_WELCOME, &welcome, sizeof(welcome), true);
		}

		// 2. [TÍNH NĂNG MỚI] ĐỒNG BỘ HÓA TRẠNG THÁI QUÉT
		lock_guard<mutex> lock(g_JobMutex);
		bool hasActiveJob = false;

		// Lục tìm trong danh sách các mẻ quét xem có thằng nào đang chạy dở không
		for (const auto& pair : g_AllBatches) {
			auto batchCtx = pair.second;

			// Điều kiện đang chạy: Chưa bị Cancel VÀ (Chưa nạp xong file HOẶC chưa quét xong file)
			if (!batchCtx->isCancelled &&
				(!batchCtx->isLoadFinished || batchCtx->processedFiles.load() < batchCtx->totalFiles.load())) {

				// Gói ghém tiến độ hiện tại ném về cho UI
				PayloadJobStatus status = { 0 };
				status.jobId = batchCtx->id;
				status.status = 1; // 1 = Đang chạy
				status.totalFiles = batchCtx->totalFiles.load();
				status.processedFiles = batchCtx->processedFiles.load();
				{
					lock_guard<mutex> threatLock(batchCtx->threatMutex);
					status.totalThreats = (uint32_t)batchCtx->infectedFiles.size();
				}
				swprintf(status.message, 255, L"[He thong] Da khoi phuc tien do quet (%d/%d files)...",
					status.processedFiles, status.totalFiles);

				g_ipcManager.Send(MSG_JOB_STATUS, &status, sizeof(status), true);
				hasActiveJob = true;
			}
		}

		// Nếu người dùng bấm Resume nhưng hệ thống đang rảnh rỗi (quét xong rồi)
		if (!hasActiveJob && type == MSG_RESUME) {
			PayloadJobStatus status = { 0 };
			status.status = 0; // 0 = Rảnh rỗi
			wcscpy_s(status.message, L"--- HE THONG DANG RANH ROI ---");
			g_ipcManager.Send(MSG_JOB_STATUS, &status, sizeof(status), true);
		}
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
	else if (type == MSG_CANCEL_REQ) {
		auto req = reinterpret_cast<const PayloadCancelReq*>(payload.data());
		uint32_t cancelId = req->jobId;

		lock_guard<mutex> lock(g_JobMutex);
		if (g_AllBatches.find(cancelId) != g_AllBatches.end()) {
			g_AllBatches[cancelId]->isCancelled = true;
			g_BatchJobs[cancelId].clear();

			PayloadJobStatus status = { 0 };
			status.jobId = cancelId;
			status.status = 3; // CANCELLED
			wcscpy_s(status.message, L"Scan Cancelled by User");
			g_ipcManager.Send(MSG_JOB_STATUS, &status, sizeof(status), true);

			g_cvQueue.notify_all();
		}
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

	if (!LoadEngine()) {
		g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
		return;
	}
	LoadCacheFromDisk();
	for (int i = 0; i < 4; i++) std::thread(WorkerThreadFunc).detach();

	g_ipcManager.SetCallback(OnClientMessage);
	if (g_ipcManager.Initialize()) {
		g_ipcManager.StartListening();
		WaitForSingleObject(g_ServiceStopEvent, INFINITE);
		SaveCacheToDisk();
	}
	g_ServiceStatus.dwCurrentState = SERVICE_STOPPED; SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

int main() {
	SERVICE_TABLE_ENTRY st[] = { { (LPWSTR)L"", (LPSERVICE_MAIN_FUNCTION)ServiceMain }, { NULL, NULL } };
	StartServiceCtrlDispatcher(st);
	return 0;
}