
#pragma once
#include <windows.h>
#include <string>
#include <vector>

// Các mã lỗi khi Parse PE
enum class PeStatus {
    OK = 0,
    FILE_NOT_FOUND,
    ACCESS_DENIED,
    FILE_TOO_SMALL,         // File nhỏ hơn cả DOS Header
    INVALID_DOS_HEADER,     // Không có Magic 'MZ'
    INVALID_NT_HEADER,      // Không có Magic 'PE\0\0'
    INVALID_PE_ARCH,        // Không phải PE32 hay PE32+
    MALFORMED_HEADER,       // e_lfanew trỏ ra ngoài file (File rác/cắt cụt)
    STRUCT_CORRUPT          // Cấu trúc bên trong bị hỏng
};
struct SectionInfo {
    char name[9]; // Tên section (tối đa 8 ký tự + null)
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

    // Hàm chính: Load file và Parse Header
    PeStatus LoadFile(const std::wstring& filePath);

    // Dọn dẹp
    void Unload();

    // Getters
    bool IsLoaded() const { return m_data != nullptr; }
    bool Is64Bit() const { return m_is64Bit; }
    DWORD GetFileSize() const { return m_fileSize; }

    // Truy xuất Header an toàn (trả về nullptr nếu chưa load)
    PIMAGE_DOS_HEADER GetDosHeader() const { return m_dosHeader; }
    PIMAGE_NT_HEADERS32 GetNtHeader32() const { return m_ntHeader32; }
    PIMAGE_NT_HEADERS64 GetNtHeader64() const { return m_ntHeader64; }
    PIMAGE_FILE_HEADER GetFileHeader() const; // Chung cho cả 32/64
    // Trả về 0 nếu RVA không hợp lệ
    DWORD RvaToFileOffset(DWORD rva) const;

    // [MỚI] Lấy danh sách Section
    const std::vector<SectionInfo>& GetSections() const { return m_sections; }

private:
    // Kiểm tra xem vùng nhớ [offset, offset + size] có nằm gọn trong file không?
    bool IsValidOffset(size_t offset, size_t size) const;
    std::vector<SectionInfo> m_sections;

    // Hàm nội bộ để parse section table
    void ParseSections();

private:
    HANDLE m_hFile;
    HANDLE m_hMapping;
    LPBYTE m_data;          // Con trỏ gốc (Base Address của file trong RAM)
    DWORD  m_fileSize;

    bool   m_is64Bit;

    // Các con trỏ trỏ vào nội dung bên trong m_data
    PIMAGE_DOS_HEADER   m_dosHeader;
    PIMAGE_NT_HEADERS32 m_ntHeader32;
    PIMAGE_NT_HEADERS64 m_ntHeader64;
};


