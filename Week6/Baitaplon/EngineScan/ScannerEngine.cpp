// File: ScannerEngine.cpp (Project DLL)
#include "pch.h"
#include <windows.h>
#include <string>
#include <algorithm>
#include "PeReader.h"
#include "RuleMatcher.h"

// Xuất hàm này ra ngoài bằng C-Style để không bị lỗi Name Mangling của C++
extern "C" __declspec(dllexport) int __stdcall EngineScanFile(const wchar_t* filePath, int mode, void* reserved) {
    if (!filePath) return 0;

    std::wstring path(filePath);

    // 1. Chỉ quét file PE
    std::wstring ext;
    size_t dotPos = path.find_last_of(L".");
    if (dotPos != std::wstring::npos) {
        ext = path.substr(dotPos + 1);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
    }
    if (ext != L"exe" && ext != L"dll" && ext != L"sys") return 0;

    // 2. Chạy Lõi Heuristic
    PeReader reader;
    if (reader.LoadFile(path) != PeStatus::OK) {
        return 0;
    }

    int scoreA = RuleMatcher::EvaluateGroupA(reader);
    int scoreB = RuleMatcher::EvaluateGroupB(reader);
    int scoreC = RuleMatcher::EvaluateGroupC(reader);
    float scoreD = RuleMatcher::EvaluateGroupD(reader);
    float scoreE = RuleMatcher::EvaluateGroupE(reader);

    float totalScore = (float)(scoreA + scoreB + scoreC) + scoreD + scoreE;
    if (totalScore < 0) totalScore = 0.0f;

    if (reserved != nullptr) {
        *((float*)reserved) = totalScore;
    }

    // 3. Phán Quyết
    if (totalScore >= 4.0f) {
        return 2; // VIRUS FOUND!
    }

    return 0; // SAFE
}

// Bác có thể giữ lại cái hàm Init rỗng này để tương thích với Service
extern "C" __declspec(dllexport) bool __stdcall EngineInitialize(const wchar_t* configJson) {
    return true; // Khởi tạo thành công
}