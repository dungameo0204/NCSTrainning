// ScannerEngine.cpp : Core xử lý quét virus
#include "pch.h" // Giữ nguyên nếu Project có, nếu không thì xóa dòng này
#include <windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>

using namespace std;

// --- ĐỊNH NGHĨA KẾT QUẢ ---
#define SCAN_RESULT_SAFE        0
#define SCAN_RESULT_SUSPICIOUS  1
#define SCAN_RESULT_MALICIOUS   2
#define SCAN_RESULT_ERROR       -1

// --- ĐỊNH NGHĨA CALLBACK ---
// Callback function: Nhận % tiến độ (0-100) và thông báo trạng thái
typedef void(__stdcall* FnProgressCallback)(int percent, const wchar_t* status);

// --- BIẾN TOÀN CỤC CỦA ENGINE ---
bool g_IsInitialized = false;
int g_EngineVersion = 20260202; // Version YYYYMMDD
wstring g_Config = L"";

// --- HÀM HỖ TRỢ (PRIVATE) ---

// Giả lập tính Entropy (Độ hỗn loạn dữ liệu)
// Trong thực tế: Phải đọc file, tính tần suất xuất hiện byte.
// Demo: Random hoặc dựa vào kích thước file để giả vờ.
bool SimulateHighEntropy(long long fileSize) {
    // Giả vờ: Nếu kích thước file chia hết cho 7 thì coi như bị mã hóa/nén (Entropy cao)
    return (fileSize % 7 == 0);
}

// Lấy kích thước file
long long GetFileSizeMy(const wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad))
        return -1;
    LARGE_INTEGER size;
    size.HighPart = fad.nFileSizeHigh;
    size.LowPart = fad.nFileSizeLow;
    return size.QuadPart;
}

// Kiểm tra đuôi file
bool CheckExtension(const wstring& path, const vector<wstring>& badExts) {
    size_t dotPos = path.rfind(L'.');
    if (dotPos == wstring::npos) return false;

    wstring ext = path.substr(dotPos);
    // Chuyển về chữ thường
    transform(ext.begin(), ext.end(), ext.begin(), towlower);

    for (const auto& bad : badExts) {
        if (ext == bad) return true;
    }
    return false;
}

// --- CÁC API EXPORT RA NGOÀI ---

extern "C" __declspec(dllexport) int __stdcall EngineGetVersion() {
    return g_EngineVersion;
}

extern "C" __declspec(dllexport) bool __stdcall EngineInitialize(const wchar_t* configJson) {
    // Giả lập load config từ JSON
    if (configJson) g_Config = configJson;

    // Giả lập khởi tạo Database mất 1 chút thời gian
    Sleep(500);
    g_IsInitialized = true;
    return true;
}

extern "C" __declspec(dllexport) void __stdcall EngineShutdown() {
    g_IsInitialized = false;
    g_Config = L"";
}

// API chính: Quét file
// Tham số:
// - path: Đường dẫn file
// - options: Bitmask tùy chọn (để mở rộng sau này)
// - callback: Hàm để Engine báo cáo tiến độ về cho Service
extern "C" __declspec(dllexport) int __stdcall EngineScanFile(
    const wchar_t* path,
    int options,
    FnProgressCallback callback
) {
    if (!g_IsInitialized) return SCAN_RESULT_ERROR;
    if (path == NULL) return SCAN_RESULT_ERROR;

    wstring wsPath(path);
    long long fileSize = GetFileSizeMy(wsPath);

    if (fileSize == -1) {
        if (callback) callback(100, L"Error: File not found or Access Denied");
        return SCAN_RESULT_ERROR;
    }

    // --- BÁO CÁO TIẾN ĐỘ: BẮT ĐẦU ---
    if (callback) callback(10, L"Analyzing header...");


    // --- HỆ THỐNG TÍNH ĐIỂM (SEVERITY SCORING) ---
    int severityScore = 0;
    vector<wstring> reasons;

    // RULE 1: Nếu file nằm ngoài ổ C:\ -> Nghi ngờ cao (Theo đề bài severity = HIGH)
    // Chuyển path về chữ hoa để so sánh ổ đĩa
    wchar_t driveLetter = towupper(wsPath[0]);
    if (driveLetter != L'C') {
        severityScore += 5; // Cộng 5 điểm (Mức cao)
        reasons.push_back(L"File not in C: drive (+5)");
    }

    if (callback) callback(30, L"Checking extensions...");


    // RULE 2: Extension nguy hiểm
    vector<wstring> riskyExts = { L".exe", L".dll", L".sys", L".js", L".vbs", L".ps1" };
    if (CheckExtension(wsPath, riskyExts)) {
        severityScore += 1;
        reasons.push_back(L"Risky extension (+1)");
    }

    if (callback) callback(60, L"Checking file size & entropy...");


    // RULE 3: Kích thước > 50MB
    if (fileSize > 50 * 1024 * 1024) { // 50MB
        severityScore += 1;
        reasons.push_back(L"File size > 50MB (+1)");
    }

    // RULE 4: Entropy cao (Giả lập)
    if (SimulateHighEntropy(fileSize)) {
        severityScore += 1;
        reasons.push_back(L"High Entropy (+1)");
    }

    // --- TỔNG KẾT ---
    if (callback) callback(90, L"Finalizing result...");

    int finalResult = SCAN_RESULT_SAFE;

    // Mapping điểm số ra kết quả
    if (severityScore >= 5) {
        finalResult = SCAN_RESULT_MALICIOUS; // > 5 điểm là Độc hại
    }
    else if (severityScore >= 3) {
        finalResult = SCAN_RESULT_SUSPICIOUS; // 3-4 điểm là Nghi ngờ
    }
    else {
        finalResult = SCAN_RESULT_SAFE; // 0-2 điểm là An toàn
    }

    if (callback) {
        // Có thể format chuỗi lý do để gửi về (Demo chỉ báo Done)
        callback(100, L"Scan Finished.");
    }

    return finalResult;
}