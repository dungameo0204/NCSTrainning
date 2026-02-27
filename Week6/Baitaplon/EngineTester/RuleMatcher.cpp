#include "RuleMatcher.h"
#include <unordered_set>
#include <string>

// Công thức toán học thao tác bit (Bitwise) cực nhanh để check Power of Two
bool RuleMatcher::IsPowerOfTwo(DWORD x) {
    return (x != 0) && ((x & (x - 1)) == 0);
}

int RuleMatcher::EvaluateGroupA(const PeReader& reader) {
    int score = 0;
    const PeMetaData& meta = reader.GetMetaData();

    // ==========================================
    // LUẬT 1: TimeDateStamp quá cũ / 0 / Tương lai (+1)
    // ==========================================
    // Giới hạn: Cũ hơn năm 2000 (0x386D4380) hoặc sau năm 2035 (0x7A4F2F00)
    DWORD ts = meta.timeDateStamp;
    if (ts == 0 || ts < 0x386D4380 || ts > 0x7A4F2F00) {
        score += 1;
    }

    // ==========================================
    // LUẬT 2: EntryPoint nằm ngoài mọi Section (+2)
    // ==========================================
    // Nếu EntryPoint != 0 mà hàm RvaToFileOffset không dịch được ra ổ cứng -> Nó đang lơ lửng ngoài không gian!
    DWORD ep = meta.entryPointRva;
    if (ep != 0 && reader.RvaToFileOffset(ep) == 0) {
        score += 2;
    }

    // ==========================================
    // LUẬT 3: Alignment dị thường (+1)
    // ==========================================
    // Bắt buộc phải là lũy thừa của 2. Và FileAlignment chuẩn thường là 512, SectionAlignment >= FileAlignment.
    DWORD sa = meta.sectionAlignment;
    DWORD fa = meta.fileAlignment;
    if (!IsPowerOfTwo(sa) || !IsPowerOfTwo(fa) || fa < 512 || sa < fa) {
        score += 1;
    }

    // ==========================================
    // LUẬT 4: NumberOfRvaAndSizes sai hoặc Directory trỏ ra ngoài file (+2)
    // ==========================================
    // Quá 16 thư mục là dấu hiệu File PE bị chỉnh sửa thủ công bậy bạ
    if (meta.numberOfRvaAndSizes > 16) {
        score += 1;
    }
    else {
        bool dirOutOfBounds = false;
        DWORD copyCount = min(meta.numberOfRvaAndSizes, (DWORD)16);

        for (DWORD i = 0; i < copyCount; i++) {
            // [CÚ LỪA KINH ĐIỂN CỦA PE]: Thư mục Security (Chữ ký - Index 4) KHÔNG PHẢI LÀ RVA! 
            // Nó là địa chỉ vật lý (Raw Offset). Nên không được đưa nó vào hàm RvaToFileOffset để soi.
            if (i == IMAGE_DIRECTORY_ENTRY_SECURITY) continue;

            DWORD dirRva = meta.dataDirs[i].VirtualAddress;
            if (dirRva != 0) {
                // Nếu RVA != 0 mà không map được về ổ cứng -> Trỏ ra ngoài file!
                if (reader.RvaToFileOffset(dirRva) == 0) {
                    dirOutOfBounds = true;
                    break;
                }
            }
        }
        if (dirOutOfBounds) score += 2;
    }

    return score;
}

int RuleMatcher::EvaluateGroupB(const PeReader& reader) {
    int score = 0;
    const auto& sections = reader.GetSections();
    const PeMetaData& meta = reader.GetMetaData();

    // ==========================================
    // LUẬT 5: "Section count" bất thường (> 12) -> +1
    // ==========================================
    if (meta.sectionCount > 12) {
        score += 1;
    }

    bool hasWeirdName = false;
    bool hasWX = false;
    bool hasHighEntropy = false;

    std::unordered_set<std::string> seenNames;
    DWORD maxRawEnd = 0; // Để đo xem file có Overlay (Rác ở cuối file) không

    for (const auto& sec : sections) {
        // ==========================================
        // LUẬT 1: Tên Section kỳ dị -> +1
        // ==========================================
        std::string name(sec.name);
        if (name.empty()) {
            hasWeirdName = true; // Tên rỗng (Rất hay gặp ở UPX packer)
        }
        else {
            for (char c : name) {
                // Nếu chứa ký tự không in được (ngoài vùng ASCII chuẩn)
                if (c < 32 || c > 126) {
                    if (c != 0) { hasWeirdName = true; break; } // Bỏ qua ký tự Null '\0'
                }
            }
            // Kiểm tra trùng lặp tên (VD: Có tận 2 phòng cùng tên .text)
            if (seenNames.find(name) != seenNames.end()) {
                hasWeirdName = true;
            }
            seenNames.insert(name);
        }

        // ==========================================
        // LUẬT 2: Quyền WX (Vừa Ghi vừa Thực thi) -> +2
        // ==========================================
        bool isWritable = (sec.characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        bool isExecutable = (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

        if (isWritable && isExecutable) {
            hasWX = true; // Tử huyệt của mã độc nằm đây!
        }

        // ==========================================
        // LUẬT 3: Entropy cao vượt ngưỡng (> 7.4) -> +1
        // ==========================================
        // Chỉ đo entropy các phòng chứa Code (Executable). Nếu code mà bị nén/mã hóa thì entropy sẽ > 7.4
        if (isExecutable && sec.rawSize > 0) {
            double entropy = reader.CalculateEntropy(sec.rawAddress, sec.rawSize);
            if (entropy > 7.4) {
                hasHighEntropy = true;
            }
        }

        // --- Tìm điểm kết thúc thực tế của các Sections trên ổ cứng ---
        if (sec.rawAddress + sec.rawSize > maxRawEnd) {
            maxRawEnd = sec.rawAddress + sec.rawSize;
        }
    }

    // Cộng điểm tổng kết vòng lặp
    if (hasWeirdName) score += 1;
    if (hasWX) score += 2;
    if (hasHighEntropy) score += 1;

    // ==========================================
    // LUẬT 4: Có Overlay (Dữ liệu rác bám đuôi file)
    // ==========================================
    DWORD fileSize = reader.GetFileSize();
    if (maxRawEnd > 0 && fileSize > maxRawEnd) {
        DWORD overlaySize = fileSize - maxRawEnd;

        // Cú lừa tinh tế: Chữ ký điện tử (Authenticode) CŨNG LÀ OVERLAY!
        // Nếu file CÓ chữ ký, ta tha thứ cho cái overlay nhỏ. Nhưng nếu to bất thường thì vẫn chém!
        if (overlaySize > 1024 * 1024) { // Lớn hơn 1MB -> Chắc chắn có nhét cái gì đó
            score += 2;
        }
        else if (overlaySize > 1024) {   // Lớn hơn 1KB
            // Nếu không có chữ ký mà lại có đuôi rác -> Cộng 1 điểm
            if (!meta.isSigned) {
                score += 1;
            }
        }
    }

    return score;
}

int RuleMatcher::EvaluateGroupC(const PeReader& reader) {
    int score = 0;
    const PeMetaData& meta = reader.GetMetaData();

    // ==========================================
    // LUẬT 1: Thái Thượng Hoàng TLS Callbacks (+2)
    // ==========================================
    // Hàm TLS chạy TRƯỚC CẢ HÀM MAIN. Bọn virus cực thích nhét mã tàng hình vào đây
    // để tắt Antivirus trước khi chương trình chính kịp chạy!
    if (meta.hasTlsCallbacks) {
        score += 2;
    }

    // ==========================================
    // LUẬT 2: Export bất thường (+1)
    // ==========================================
    // File .exe bình thường rất hiếm khi Export hàm ra ngoài (vì nó không phải DLL).
    // Hoặc DLL mà export tới hàng ngàn hàm rác -> Bọn Packer xả rác làm mù Antivirus.
    if (!meta.isDll && meta.exportCount > 0) {
        score += 1;
    }
    else if (meta.exportCount > 500) {
        score += 1;
    }

    // ==========================================
    // LUẬT 3 & 4: Dò API Nguy hiểm (Imports Blacklist)
    // ==========================================
    bool hasProcessInject = false;
    bool hasPersistence = false;
    bool hasNetwork = false;
    bool hasCrypto = false;

    for (const std::string& api : meta.imports) {
        // Nhóm 1: Process/Thread Injection (Tiêm mã độc vào RAM thằng khác)
        if (api == "CreateRemoteThread" || api == "WriteProcessMemory" ||
            api == "VirtualAllocEx" || api == "OpenProcess" || api == "SetWindowsHookExA") {
            hasProcessInject = true;
        }
        // Nhóm 2: Persistence (Đào rễ ăn sâu vào máy để khởi động cùng Windows)
        else if (api == "RegSetValueExA" || api == "RegSetValueExW" ||
            api == "CreateServiceA" || api == "CreateServiceW") {
            hasPersistence = true;
        }
        // Nhóm 3: Network (Tải lén payload hoặc kết nối máy chủ C&C của Hacker)
        else if (api.find("WinHttp") == 0 || api.find("InternetOpen") == 0 ||
            api.find("WSAStartup") == 0 || api == "URLDownloadToFileA") {
            hasNetwork = true;
        }
        // Nhóm 4: Crypto/Obfuscation (Mã hóa tống tiền Ransomware)
        else if (api.find("CryptEncrypt") == 0 || api.find("BCryptEncrypt") == 0 ||
            api == "IsDebuggerPresent") {
            hasCrypto = true;
        }
    }

    // Cộng điểm theo nhóm (Tối đa +4 điểm nếu gom đủ 4 họ API rủi ro)
    int apiScore = 0;
    if (hasProcessInject) apiScore += 1;
    if (hasPersistence) apiScore += 1;
    if (hasNetwork) apiScore += 1;
    if (hasCrypto) apiScore += 1;

    // LUẬT BỔ SUNG: Nếu có Delay-Import + Gọi API rủi ro -> Bọn hacker đang cố tình giấu IAT
    if (meta.hasDelayImport && apiScore > 0) {
        score += 1;
    }

    score += apiScore;
    return score;
}


float RuleMatcher::EvaluateGroupD(const PeReader& reader) {
    float score = 0.0f;
    const PeMetaData& meta = reader.GetMetaData();

    // ==========================================
    // LUẬT 1: Vô danh tiểu tốt (Thiếu VersionInfo) -> +1
    // ==========================================
    // App xịn đéo bao giờ quên khai báo CompanyName, Copyright. Bọn giấu mặt thường lười ghi cái này!
    if (!meta.hasVersionInfo) {
        score += 1.0f;
    }

    // ==========================================
    // LUẬT 2: File Giao diện (GUI) mà tàng hình -> +0.5 mỗi tội
    // ==========================================
    // Nếu là phần mềm có cửa sổ (Subsystem == 2) thì bắt buộc phải có Icon và Manifest để hiển thị trên Windows.
    // Nếu GUI mà không có Icon -> Ám muội, muốn ẩn mình!
    if (meta.subsystem == 2) {
        if (!meta.hasIcon) score += 0.5f;
        if (!meta.hasManifest) score += 0.5f;
    }

    // ==========================================
    // LUẬT 3: Ổ chứa giấu Payload (RCDATA kích thước lớn + Entropy cao) -> +1
    // ==========================================
    // RCDATA (Resource Custom Data) thường dùng để chứa font chữ hoặc file config nhỏ.
    // Nếu nó chứa cục data to đùng và bị mã hóa -> 99% là Drop/Payload của Malware!
    if (meta.hasRcData) {
        for (const auto& sec : reader.GetSections()) {
            std::string name(sec.name);
            // Soi thẳng vào phòng .rsrc
            if (name == ".rsrc" || name == ".rdata") {
                // Nếu phòng to hơn 50KB (đáng ngờ)
                if (sec.rawSize > 50 * 1024) {
                    double ent = reader.CalculateEntropy(sec.rawAddress, sec.rawSize);
                    // RCDATA bình thường có entropy thấp, nếu > 7.4 thì chắc chắn bị mã hóa/nén.
                    if (ent > 7.4) {
                        score += 1.0f;
                        break;
                    }
                }
            }
        }
    }

    return score;
}

float RuleMatcher::EvaluateGroupE(const PeReader& reader) {
    float score = 0.0f;
    const PeMetaData& meta = reader.GetMetaData();

    // ==========================================
    // LUẬT 1: Tội ác tày trời - CHỮ KÝ GIẢ MẠO / BỊ PHÁ (SIGNED_INVALID) -> +2
    // ==========================================
    // Nghĩa là Hacker đã lấy một file xịn của Microsoft/Google, sau đó lén nhét mã độc vào.
    // Việc nhét mã độc làm thay đổi cấu trúc file, khiến chữ ký điện tử bị hỏng (Bad Digest).
    if (meta.sigStatus == SignatureStatus::SIGNED_INVALID) {
        score += 2.0f;
    }

    // ==========================================
    // LUẬT 2: File trôi nổi - KHÔNG CÓ CHỮ KÝ (UNSIGNED) -> +0.5
    // ==========================================
    // Không có chữ ký chưa chắc là virus (có thể do ae dev nghèo không có tiền mua chứng chỉ).
    // Nhưng về mặt Heuristic policy, ta vẫn đánh nhẹ 0.5 điểm rủi ro.
    else if (meta.sigStatus == SignatureStatus::UNSIGNED) {
        score += 0.5f;
    }

    // ==========================================
    // LUẬT 3 (Demo): LỪA ĐẢO CẤU TRÚC SECURITY DIRECTORY -> +1
    // ==========================================
    // Trong Data Directories (Nhóm A), thư mục số 4 (Security) có khai báo dữ liệu.
    // NHƯNG hàm WinVerifyTrust của hệ điều hành lại bảo "Đéo có chữ ký nào cả" (UNSIGNED).
    // -> Bọn Packer/Malware đã can thiệp thô bạo vào Header làm đứt gãy cấu trúc chữ ký!
    DWORD secRva = meta.dataDirs[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
    bool hasSecurityDir = (secRva != 0);

    if (hasSecurityDir && meta.sigStatus == SignatureStatus::UNSIGNED) {
        score += 1.0f;
    }

    // THƯỞNG: Nếu chữ ký HỢP LỆ (SIGNED_VALID) -> Thưởng điểm trừ (Giảm rủi ro)
    if (meta.sigStatus == SignatureStatus::SIGNED_VALID) {
        score -= 1.0f; // Tin tưởng Microsoft/Google, giảm tổng điểm xuống!
    }

    return score;
}