#include <iostream>
#include <iomanip>
#include <string>
#include <filesystem>
#include <io.h>     
#include <fcntl.h>  
#include "RuleMatcher.h"
#include "PeReader.h"

using namespace std;
namespace fs = std::filesystem;

// [ĐÃ SỬA] Đổi string thành wstring
wstring BoolToStr(bool val) { return val ? L"[X] YES" : L"[ ] NO"; }

void AnalyzeSingleFile(const wstring& filePath) {
    PeReader reader;
    wcout << L"\n===================================================================" << endl;
    wcout << L"[*] DANG DOC FILE: " << filePath << endl;

    PeStatus status = reader.LoadFile(filePath);

    if (status != PeStatus::OK) {
        wcout << L"[-] BO QUA! Khong phai file PE hoac bi loi. Ma loi: " << (int)status << endl;
        return;
    }

    const PeMetaData& meta = reader.GetMetaData();

    wcout << left << setw(18) << L"Machine:" << L"0x" << hex << meta.machine;
    if (meta.machine == 0x8664) wcout << L" (AMD64)" << endl;
    else if (meta.machine == 0x014C) wcout << L" (i386)" << endl;
    else wcout << L" (Unknown)" << endl;

    wcout << left << setw(18) << L"Subsystem:" << L"0x" << hex << meta.subsystem << dec << endl;
    wcout << left << setw(18) << L"Section Count:" << meta.sectionCount << endl;

    wcout << L"\n--- BO FLAGS ---" << endl;
    wcout << left << setw(15) << L"Is DLL:" << BoolToStr(meta.isDll)
        << L" | Is Driver: " << BoolToStr(meta.isDriver)
        << L" | Is .NET: " << BoolToStr(meta.isManaged) << endl;

    wcout << left << setw(15) << L"Is Signed:" << BoolToStr(meta.isSigned)
        << L" | Has Debug: " << BoolToStr(meta.hasDebug)
        << L" | Has Rich: " << BoolToStr(meta.hasRichHeader) << endl;

    // [MỚI THÊM] In tóm tắt thông tin Nhóm C (Danh bạ IAT/Export)
    wcout << L"\n--- DANH BA IAT & EXPORT (NHOM C) ---" << endl;
    wcout << left << setw(18) << L"TLS Callbacks:" << BoolToStr(meta.hasTlsCallbacks)
        << L" | Delay Import: " << BoolToStr(meta.hasDelayImport) << endl;
    wcout << left << setw(18) << L"Tong so API:" << meta.imports.size() << L" ham"
        << L" | Ham Export:   " << meta.exportCount << L" ham" << endl;

    const auto& sections = reader.GetSections();
    wcout << L"\n--- SECTION TABLE ---" << endl;
    wcout << left << setw(10) << L"Name"
        << setw(12) << L"V.Size"
        << setw(12) << L"R.Size"
        << L"Characteristics" << endl;
    wcout << L"----------------------------------------------------" << endl;

    for (const auto& sec : sections) {
        wstring wName(sec.name, sec.name + strlen(sec.name));

        wcout << left << setw(10) << wName
            << L"0x" << setw(10) << hex << sec.virtualSize
            << L"0x" << setw(10) << sec.rawSize
            << L"0x" << sec.characteristics << dec << endl;
    }


    wcout << L"\n====================================================" << endl;
    wcout << L"            KẾT QUẢ QUÉT HEURISTIC TOÀN DIỆN        " << endl;
    wcout << L"====================================================" << endl;

    // Chấm điểm từng nhóm
    int scoreA = RuleMatcher::EvaluateGroupA(reader);
    int scoreB = RuleMatcher::EvaluateGroupB(reader);
    int scoreC = RuleMatcher::EvaluateGroupC(reader); // [MỚI THÊM] Gọi Nhóm C
    float scoreD = RuleMatcher::EvaluateGroupD(reader);
    float scoreE = RuleMatcher::EvaluateGroupE(reader);

    wcout << left << setw(25) << L"[+] Điểm số Nhóm A:" << scoreA << L" điểm (Header & Cấu trúc)" << endl;
    wcout << left << setw(25) << L"[+] Điểm số Nhóm B:" << scoreB << L" điểm (Entropy & Các phòng)" << endl;
    wcout << left << setw(25) << L"[+] Điểm số Nhóm C:" << scoreC << L" điểm (API & Hành vi)" << endl;
    wcout << left << setw(25) << L"[+] Nhóm D:" << scoreD << L" điểm (Resources & Tàng hình)" << endl;
    wcout << left << setw(25) << L"[+] Nhóm E:" << scoreE << L" điểm (Authenticode Trust)" << endl;
    
    float totalScore = (float)(scoreA + scoreB + scoreC) + scoreD + scoreE;
    wcout << L"----------------------------------------------------" << endl;
    wcout << left << setw(25) << L"[*] TỔNG ĐIỂM HEURISTIC:" << fixed << setprecision(1) << totalScore << L"/10" << endl;

    // Tinh chỉnh lại logic kết luận vì giờ max điểm có thể lên tới > 10 điểm
    if (totalScore >= 4) {
        wcout << L"    => [!!!] BÁO ĐỘNG ĐỎ: PHÁT HIỆN MÃ ĐỘC / RANSOMWARE / PACKER!" << endl;
    }
    else if (totalScore >= 2) {
        wcout << L"    => [?] ĐÁNG NGHI NGỜ: File có hành vi bất thường, cần theo dõi." << endl;
    }
    else {
        wcout << L"    => [OK] File an toàn, chuẩn mực." << endl;
    }
    wcout << L"====================================================" << endl;
}

int main() {
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stdin), _O_U16TEXT);

    wcout << L"==============================================" << endl;
    wcout << L"        PE PARSER TEST LAB (INTERACTIVE)      " << endl;
    wcout << L"==============================================" << endl;

    while (true) {
        wcout << L"\n[?] Nhap duong dan File hoac Thu muc (nhap 'exit' de thoat): ";
        wstring inputPath;
        getline(wcin, inputPath);

        if (inputPath == L"exit" || inputPath == L"quit") break;
        if (inputPath.empty()) continue;

        if (inputPath.front() == L'"' && inputPath.back() == L'"') {
            inputPath = inputPath.substr(1, inputPath.length() - 2);
        }

        try {
            if (fs::is_regular_file(inputPath)) {
                AnalyzeSingleFile(inputPath);
            }
            else if (fs::is_directory(inputPath)) {
                wcout << L"\n[*] Phat hien THU MUC. Bat dau quet toan bo file PE..." << endl;
                int count = 0;

                auto options = fs::directory_options::skip_permission_denied;
                for (const auto& entry : fs::directory_iterator(inputPath, options)) {
                    if (entry.is_regular_file()) {
                        wstring ext = entry.path().extension().wstring();
                        // Hàm towlower để đảm bảo bắt được đuôi .EXE viết hoa
                        transform(ext.begin(), ext.end(), ext.begin(), ::towlower);

                        if (ext == L".exe" || ext == L".dll" || ext == L".sys") {
                            AnalyzeSingleFile(entry.path().wstring());
                            count++;
                        }
                    }
                }
                wcout << L"\n[+] Da phan tich " << count << L" file PE trong thu muc." << endl;
            }
            else {
                wcout << L"[-] Duong dan khong ton tai hoac khong hop le!" << endl;
            }
        }
        catch (const fs::filesystem_error& e) {
            wcout << L"[-] Loi truy cap thu muc/file: Vui long kiem tra lai quyen Administrator." << endl;
        }
    }

    return 0;
}