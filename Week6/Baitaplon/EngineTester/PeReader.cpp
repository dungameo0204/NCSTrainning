#include "PeReader.h"

PeReader::PeReader()
    : m_hFile(INVALID_HANDLE_VALUE), m_hMapping(NULL), m_data(nullptr),
    m_fileSize(0), m_is64Bit(false),
    m_dosHeader(nullptr), m_ntHeader32(nullptr), m_ntHeader64(nullptr)
{
}

PeReader::~PeReader() {
    Unload();
}

void PeReader::Unload() {
    if (m_data) { UnmapViewOfFile(m_data); m_data = nullptr; }
    if (m_hMapping) { CloseHandle(m_hMapping); m_hMapping = NULL; }
    if (m_hFile != INVALID_HANDLE_VALUE) { CloseHandle(m_hFile); m_hFile = INVALID_HANDLE_VALUE; }

    m_fileSize = 0;
    m_dosHeader = nullptr;
    m_ntHeader32 = nullptr;
    m_ntHeader64 = nullptr;
}

bool PeReader::IsValidOffset(size_t offset, size_t size) const {
    if (!m_data || m_fileSize == 0) return false;
    // Kiểm tra tràn số và giới hạn file
    if (offset + size < offset) return false; // Tràn số (Integer overflow check)
    if (offset + size > m_fileSize) return false; // Vượt quá file
    return true;
}

PeStatus PeReader::LoadFile(const std::wstring& filePath) {
    Unload(); // Reset trước khi load mới

    // 1. Mở file (Chỉ đọc)
    m_hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (m_hFile == INVALID_HANDLE_VALUE) {
        return (GetLastError() == ERROR_ACCESS_DENIED) ? PeStatus::ACCESS_DENIED : PeStatus::FILE_NOT_FOUND;
    }

    // 2. Lấy kích thước
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(m_hFile, &fileSize)) {
        CloseHandle(m_hFile); m_hFile = INVALID_HANDLE_VALUE;
        return PeStatus::ACCESS_DENIED; // Hoặc mã lỗi khác tùy ý
    }

    // Ép kiểu về DWORD (Vì ta chỉ xử lý file PE thường, hiếm khi quá 4GB)
    m_fileSize = (DWORD)fileSize.QuadPart;

    if (m_fileSize < sizeof(IMAGE_DOS_HEADER)) {
        CloseHandle(m_hFile); m_hFile = INVALID_HANDLE_VALUE;
        return PeStatus::FILE_TOO_SMALL;
    }

    // 3. Map vào RAM
    m_hMapping = CreateFileMappingW(m_hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!m_hMapping) return PeStatus::ACCESS_DENIED;

    m_data = (LPBYTE)MapViewOfFile(m_hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!m_data) return PeStatus::ACCESS_DENIED;

    // --- BẮT ĐẦU PARSE THỦ CÔNG ---

    // 4. Parse DOS Header
    // Không cần check IsValidOffset vì đã check fileSize < sizeof(DOS) ở trên
    m_dosHeader = (PIMAGE_DOS_HEADER)m_data;

    // Kiểm tra Magic Number 'MZ' (Mark Zbikowski)
    if (m_dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return PeStatus::INVALID_DOS_HEADER;
    }

    // 5. Tìm NT Headers
    // e_lfanew chứa offset dẫn tới NT Header. Đây là chỗ malware hay fake để gây crash.
    // Phải kiểm tra xem e_lfanew có trỏ ra ngoài file không.
    if (!IsValidOffset(m_dosHeader->e_lfanew, sizeof(IMAGE_NT_HEADERS32))) {
        return PeStatus::MALFORMED_HEADER;
    }

    // Tính địa chỉ NT Header
    PIMAGE_NT_HEADERS32 tempNt32 = (PIMAGE_NT_HEADERS32)(m_data + m_dosHeader->e_lfanew);

    // 6. Kiểm tra Magic 'PE\0\0'
    if (tempNt32->Signature != IMAGE_NT_SIGNATURE) {
        return PeStatus::INVALID_NT_HEADER;
    }

    // 7. Xác định Architecture (32 vs 64)
    // Dựa vào OptionalHeader.Magic: 0x10B (32bit), 0x20B (64bit)
    if (tempNt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        m_is64Bit = false;
        m_ntHeader32 = tempNt32;
        m_ntHeader64 = nullptr;
    }
    else if (tempNt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        // Kiểm tra lại bounds cho struct 64 bit (nó to hơn 32 bit một chút)
        if (!IsValidOffset(m_dosHeader->e_lfanew, sizeof(IMAGE_NT_HEADERS64))) {
            return PeStatus::MALFORMED_HEADER;
        }
        m_is64Bit = true;
        m_ntHeader32 = nullptr;
        m_ntHeader64 = (PIMAGE_NT_HEADERS64)tempNt32;
    }
    else {
        return PeStatus::INVALID_PE_ARCH; // ROM image hoặc dạng lạ
    }

    // 8. Parse Section Table
    ParseSections();

    return PeStatus::OK;
}

PIMAGE_FILE_HEADER PeReader::GetFileHeader() const {
    if (!m_data) return nullptr;
    // FileHeader nằm giống nhau ở cả struct 32 và 64
    if (m_is64Bit && m_ntHeader64) return &m_ntHeader64->FileHeader;
    if (!m_is64Bit && m_ntHeader32) return &m_ntHeader32->FileHeader;
    return nullptr;
}

void PeReader::ParseSections() {
    m_sections.clear();

    // 1. Tìm vị trí bắt đầu của Section Table
    // Nó nằm ngay sau NT Header (FileHeader + OptionalHeader)
    PIMAGE_SECTION_HEADER pSection = nullptr;
    WORD numberOfSections = 0;

    if (m_is64Bit) {
        // IMAGE_FIRST_SECTION là macro tính toán địa chỉ section đầu tiên
        pSection = IMAGE_FIRST_SECTION(m_ntHeader64);
        numberOfSections = m_ntHeader64->FileHeader.NumberOfSections;
    }
    else {
        pSection = IMAGE_FIRST_SECTION(m_ntHeader32);
        numberOfSections = m_ntHeader32->FileHeader.NumberOfSections;
    }

    // 2. Duyệt qua từng section
    for (WORD i = 0; i < numberOfSections; i++) {
        // Kiểm tra an toàn bộ nhớ
        if (!IsValidOffset((LPBYTE)&pSection[i] - m_data, sizeof(IMAGE_SECTION_HEADER))) {
            break; // Header bị cụt -> Dừng lại
        }

        SectionInfo info;
        // Copy tên (tối đa 8 ký tự, không nhất thiết có null ở cuối nên phải xử lý kỹ)
        memset(info.name, 0, 9);
        memcpy(info.name, pSection[i].Name, 8);

        info.virtualAddress = pSection[i].VirtualAddress;
        info.virtualSize = pSection[i].Misc.VirtualSize;
        info.rawAddress = pSection[i].PointerToRawData;
        info.rawSize = pSection[i].SizeOfRawData;
        info.characteristics = pSection[i].Characteristics;

        m_sections.push_back(info);
    }
}

DWORD PeReader::RvaToFileOffset(DWORD rva) const {
    // Duyệt qua tất cả section để xem RVA thuộc về section nào
    for (const auto& sec : m_sections) {
        // Kiểm tra xem RVA có nằm trong khoảng [VirtualAddress, VirtualAddress + VirtualSize] không
        if (rva >= sec.virtualAddress && rva < sec.virtualAddress + sec.virtualSize) {

            // Công thức thần thánh:
            // Offset = RVA - VirtualAddress + RawAddress
            DWORD offset = rva - sec.virtualAddress + sec.rawAddress;

            // Kiểm tra kỹ lại xem offset tính ra có nằm trong vùng Raw Data không
            // (Đề phòng trường hợp VirtualSize > RawSize - section chứa biến chưa khởi tạo)
            if (offset >= sec.rawAddress && offset < sec.rawAddress + sec.rawSize) {
                return offset;
            }
        }
    }
    return 0; // Không tìm thấy hoặc RVA invalid
}