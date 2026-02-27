#pragma once
#include <windows.h>
#include <winnt.h>
#include <string>
#include <vector>

// Các mã trạng thái theo chuẩn đồ án
enum class PeStatus {
    OK = 0,
    FILE_NOT_FOUND,
    ACCESS_DENIED,
    MALFORMED_PE,    // File bị cắt, Header sai (DOS, NT Magic)
    STRUCT_CORRUPT   // RVA ngoài vùng, Section Table tràn file
};
// Thêm 3 trạng thái chữ ký
enum class SignatureStatus {
    UNKNOWN,
    UNSIGNED,           // Không có chữ ký
    SIGNED_VALID,       // Có chữ ký và HỢP LỆ (Hàng xịn)
    SIGNED_INVALID      // Có chữ ký nhưng BỊ LỖI / GIẢ MẠO (Cực kỳ nguy hiểm)
};

// Cấu trúc lưu 11 thông số bác yêu cầu
struct PeMetaData {
    WORD machine;
    WORD subsystem;
    bool isDll;
    bool isDriver;
    bool isManaged;  // .NET
    bool isSigned;   // Có Security Directory
    bool hasDebug;
    bool hasRichHeader;
    DWORD entryPointRva;
    ULONGLONG imageBase;
    WORD sectionCount;
    DWORD timeDateStamp;
    DWORD sectionAlignment;
    DWORD fileAlignment;
    DWORD numberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY dataDirs[16];

    // [BỔ SUNG NHÓM C]
    std::vector<std::string> imports;      // Danh sách các hàm API bị gọi
    bool hasTlsCallbacks = false;          // Cờ báo hiệu có TLS (Thái thượng hoàng)
    bool hasDelayImport = false;           // Cờ báo hiệu có Delay-Load API
    DWORD exportCount = 0;                 // Số lượng hàm Export ra ngoài

    // [BỔ SUNG NHÓM D] - Resources & Version
    bool hasVersionInfo = false;
    bool hasIcon = false;
    bool hasManifest = false;
    bool hasRcData = false;      // Có chứa cục RCDATA nào không?

    // [NHÓM E] chữ ký số (Authenticode)
    SignatureStatus sigStatus = SignatureStatus::UNKNOWN;
};

// Cấu trúc nội bộ lưu Section
struct SectionInfo {
    char name[9];
    DWORD virtualAddress;
    DWORD virtualSize;
    DWORD rawAddress;
    DWORD rawSize;
    DWORD characteristics;
};

class PeReader {
public:
    PeReader();
    ~PeReader();

    PeStatus LoadFile(const std::wstring& filePath);
    void Unload();

    DWORD RvaToFileOffset(DWORD rva) const;

    // Lấy thông tin đã parse
    const PeMetaData& GetMetaData() const { return m_meta; }
    const std::vector<SectionInfo>& GetSections() const { return m_sections; }
    DWORD GetFileSize() const { return m_fileSize; } // Lấy kích thước file để tính Overlay
    double CalculateEntropy(DWORD offset, DWORD size) const; // Vũ khí tối thượng

private:
    HANDLE m_hFile;
    HANDLE m_hMapping;
    LPBYTE m_data;
    DWORD m_fileSize;

    bool m_is64Bit;
    PeMetaData m_meta;
    std::vector<SectionInfo> m_sections;

    // Các hàm nội bộ
    bool IsValidOffset(DWORD offset, DWORD size) const;
    PeStatus ParseHeaders();
    PeStatus ParseSections(DWORD sectionTableOffset);
    bool CheckRichHeader(DWORD e_lfanew);

    // Thêm hàm xác thực chữ ký bằng WinAPI
    SignatureStatus VerifyCertificate(const std::wstring& filePath);
};