#include "pch.h"
#include "PeReader.h"
#include <cmath>
#include <wintrust.h>
#include <softpub.h>
#pragma comment(lib, "wintrust.lib")

PeReader::PeReader() : m_hFile(INVALID_HANDLE_VALUE), m_hMapping(NULL), m_data(nullptr), m_fileSize(0), m_is64Bit(false) {
    ZeroMemory(&m_meta, sizeof(PeMetaData));
}

PeReader::~PeReader() {
    Unload();
}

void PeReader::Unload() {
    if (m_data) { UnmapViewOfFile(m_data); m_data = nullptr; }
    if (m_hMapping) { CloseHandle(m_hMapping); m_hMapping = NULL; }
    if (m_hFile != INVALID_HANDLE_VALUE) { CloseHandle(m_hFile); m_hFile = INVALID_HANDLE_VALUE; }
    m_fileSize = 0;
    m_sections.clear();
    ZeroMemory(&m_meta, sizeof(PeMetaData));
}

bool PeReader::IsValidOffset(DWORD offset, DWORD size) const {
    if (!m_data || m_fileSize == 0) return false;
    if (offset + size < offset) return false; // Chống Integer Overflow
    if (offset + size > m_fileSize) return false; // Vượt quá EOF
    return true;
}

PeStatus PeReader::LoadFile(const std::wstring& filePath) {
    Unload();

    m_hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (m_hFile == INVALID_HANDLE_VALUE) return PeStatus::FILE_NOT_FOUND;

    LARGE_INTEGER fs;
    if (!GetFileSizeEx(m_hFile, &fs)) return PeStatus::ACCESS_DENIED;
    m_fileSize = (DWORD)fs.QuadPart;

    if (m_fileSize < sizeof(IMAGE_DOS_HEADER)) return PeStatus::MALFORMED_PE;

    m_hMapping = CreateFileMappingW(m_hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!m_hMapping) return PeStatus::ACCESS_DENIED;

    m_data = (LPBYTE)MapViewOfFile(m_hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!m_data) return PeStatus::ACCESS_DENIED;

    // [NHÓM E] Kiểm tra chữ ký điện tử ngay sau khi đọc xong Header
    m_meta.sigStatus = VerifyCertificate(filePath);
    return ParseHeaders();
}

// ==========================================
// TỰ PARSE BẰNG CON TRỎ (NO API)
// ==========================================
PeStatus PeReader::ParseHeaders() {
    // 1. DOS Header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)m_data;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return PeStatus::MALFORMED_PE; // Bắt buộc là MZ

    // 2. Kiểm tra Rich Header (Nằm giữa DOS và NT Header)
    m_meta.hasRichHeader = CheckRichHeader(dosHeader->e_lfanew);

    // 3. NT Header
    DWORD e_lfanew = dosHeader->e_lfanew;
    // Kiểm tra cấu trúc có bị cắt xén (Truncated) không
    if (!IsValidOffset(e_lfanew, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))) return PeStatus::MALFORMED_PE;

    // Đọc Magic "PE\0\0"
    DWORD* ntSignature = (DWORD*)(m_data + e_lfanew);
    if (*ntSignature != IMAGE_NT_SIGNATURE) return PeStatus::MALFORMED_PE;

    // Đọc File Header
    PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)(m_data + e_lfanew + 4);
    m_meta.machine = fileHeader->Machine;
    m_meta.sectionCount = fileHeader->NumberOfSections;
    m_meta.isDll = (fileHeader->Characteristics & IMAGE_FILE_DLL) != 0;
    m_meta.timeDateStamp = fileHeader->TimeDateStamp;

    // 4. Optional Header (Phân biệt 32bit và 64bit) sizeof(IMAGE_FILE_HEADER) là kích thuocs file header: 20 bytes
    DWORD optHeaderOffset = e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER);
    if (!IsValidOffset(optHeaderOffset, sizeof(WORD))) return PeStatus::MALFORMED_PE;

    WORD* optMagic = (WORD*)(m_data + optHeaderOffset);
    DWORD dataDirCount = 0;
    PIMAGE_DATA_DIRECTORY dataDirs = nullptr;

    if (*optMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (!IsValidOffset(optHeaderOffset, sizeof(IMAGE_OPTIONAL_HEADER32))) return PeStatus::MALFORMED_PE;
        PIMAGE_OPTIONAL_HEADER32 opt32 = (PIMAGE_OPTIONAL_HEADER32)(m_data + optHeaderOffset);

        m_is64Bit = false;
        m_meta.entryPointRva = opt32->AddressOfEntryPoint;
        // địa chỉ RAM yêu thích xin được cấp phát chương trình
        m_meta.imageBase = opt32->ImageBase;
        //subsystem là 1 con số, 3 là console, 2 là GUI, 1 là .sys 
        m_meta.subsystem = opt32->Subsystem;
        // Số lượng Data Directories, mặc định là 16
        dataDirCount = opt32->NumberOfRvaAndSizes;
        // mảng Con trỏ đến các Data Directories (Export, Import, Resource, Exception, Security, Debug, v.v.)
        dataDirs = opt32->DataDirectory;
        m_meta.sectionAlignment = opt32->SectionAlignment;
        m_meta.fileAlignment = opt32->FileAlignment;
        m_meta.numberOfRvaAndSizes = opt32->NumberOfRvaAndSizes;
    }
    else if (*optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (!IsValidOffset(optHeaderOffset, sizeof(IMAGE_OPTIONAL_HEADER64))) return PeStatus::MALFORMED_PE;
        PIMAGE_OPTIONAL_HEADER64 opt64 = (PIMAGE_OPTIONAL_HEADER64)(m_data + optHeaderOffset);

        m_is64Bit = true;
        m_meta.entryPointRva = opt64->AddressOfEntryPoint;
        m_meta.imageBase = opt64->ImageBase;
        m_meta.subsystem = opt64->Subsystem;
        dataDirCount = opt64->NumberOfRvaAndSizes;
        dataDirs = opt64->DataDirectory;
        m_meta.sectionAlignment = opt64->SectionAlignment;
        m_meta.fileAlignment = opt64->FileAlignment;
        m_meta.numberOfRvaAndSizes = opt64->NumberOfRvaAndSizes;
    }
    else {
        return PeStatus::MALFORMED_PE; // Magic lạ (ROM, v.v.)
    }

    // 5. Trích xuất cờ theo yêu cầu
    m_meta.isDriver = (m_meta.subsystem == IMAGE_SUBSYSTEM_NATIVE);

    // Kiểm tra Data Directories an toàn
    // "CLR Header" phòng số 14, các phần mềm viết bằng C# hoặc VB.NET.
    if (dataDirCount > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR && dataDirs[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0)
        m_meta.isManaged = true; // .NET C#
    // "Security Directory" phòng số 4, nếu có thì file này đã được ký số (Authenticode)
    if (dataDirCount > IMAGE_DIRECTORY_ENTRY_SECURITY && dataDirs[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress != 0)
        m_meta.isSigned = true;  // Authenticode Signature
    // "Debug Directory" phòng số 6, nếu có thì file này chứa thông tin debug (PDB)
    if (dataDirCount > IMAGE_DIRECTORY_ENTRY_DEBUG && dataDirs[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress != 0)
        m_meta.hasDebug = true;  // Debug info

    // 6. Tính toán vị trí Section Table và Parse nó
    DWORD sectionTableOffset = optHeaderOffset + fileHeader->SizeOfOptionalHeader;

    //Lưu lại tối đa 16 cái Data Directories
    ZeroMemory(m_meta.dataDirs, sizeof(m_meta.dataDirs));
    DWORD copyCount = min(dataDirCount, (DWORD)16);
    if (copyCount > 0 && dataDirs != nullptr) {
        memcpy(m_meta.dataDirs, dataDirs, copyCount * sizeof(IMAGE_DATA_DIRECTORY));
    }

    // ==========================================
    // [NHÓM C] MỔ BỤNG CÁC THƯ MỤC ĐẶC BIỆT
    // ==========================================

   // 1. Check TLS Callbacks (Thái thượng hoàng chạy trước cả hàm main)
    if (m_meta.dataDirs[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0) {
        m_meta.hasTlsCallbacks = true; // Cứ có mặt thư mục này là đánh dấu nguy hiểm (+2 điểm)
    }

    // 2. Check Delay Import (Gọi hàm lén lút lúc đang chạy)
    if (m_meta.dataDirs[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress != 0) {
        m_meta.hasDelayImport = true;
    }

    // 3. Đếm số lượng hàm Export (Bán dưa lê ra ngoài)
    DWORD expRva = m_meta.dataDirs[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (expRva != 0) {
        DWORD expOffset = RvaToFileOffset(expRva);
        if (expOffset != 0) {
            PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(m_data + expOffset);
            m_meta.exportCount = pExport->NumberOfFunctions;
        }
    }

    // 4. ĐỌC DANH BẠ IMPORT (Tìm các hàm API nguy hiểm)
	// địa chỉ khi nạp lên RAM 
    DWORD impRva = m_meta.dataDirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (impRva != 0) {
        DWORD impOffset = RvaToFileOffset(impRva);
        if (impOffset != 0) {
            PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(m_data + impOffset);

            // Lặp qua từng file DLL (như kernel32.dll, user32.dll)
            while (pImport->Name != 0) {
                // Ưu tiên đọc bảng ILT (OriginalFirstThunk), nếu hỏng thì đọc IAT (FirstThunk)
                DWORD thunkRva = pImport->OriginalFirstThunk ? pImport->OriginalFirstThunk : pImport->FirstThunk;
                DWORD thunkOffset = RvaToFileOffset(thunkRva);

                if (thunkOffset != 0) {
                    // Xử lý 64-bit hoặc 32-bit thunks
                    if (m_is64Bit) {
                        PIMAGE_THUNK_DATA64 pThunk = (PIMAGE_THUNK_DATA64)(m_data + thunkOffset);
                        while (pThunk->u1.AddressOfData != 0) {
                            if (!(pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) { // Bỏ qua nếu Import bằng Số (Ordinal)
                                DWORD nameOffset = RvaToFileOffset((DWORD)pThunk->u1.AddressOfData);
                                if (nameOffset != 0) {
                                    PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(m_data + nameOffset);
                                    m_meta.imports.push_back((char*)pName->Name); // Lưu tên hàm (VD: "CreateRemoteThread") vào Balo
                                }
                            }
                            pThunk++;
                        }
                    }
                    else {
                        PIMAGE_THUNK_DATA32 pThunk = (PIMAGE_THUNK_DATA32)(m_data + thunkOffset);
                        while (pThunk->u1.AddressOfData != 0) {
                            if (!(pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)) {
                                DWORD nameOffset = RvaToFileOffset((DWORD)pThunk->u1.AddressOfData);
                                if (nameOffset != 0) {
                                    PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(m_data + nameOffset);
                                    m_meta.imports.push_back((char*)pName->Name);
                                }
                            }
                            pThunk++;
                        }
                    }
                }
                pImport++; // Chuyển sang DLL tiếp theo
            }
        }
    }


    // ==========================================
    // [NHÓM D] MỞ KHÓA KHO TÀI NGUYÊN (RESOURCES)
    // ==========================================
    DWORD resRva = m_meta.dataDirs[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
    if (resRva != 0) {
        DWORD resOffset = RvaToFileOffset(resRva);
        if (resOffset != 0) {
            // Ép khuôn thư mục gốc (Tầng 1 - Loại Tài nguyên), icon, hình ảnh, âm thanh,...
            PIMAGE_RESOURCE_DIRECTORY pResDir = (PIMAGE_RESOURCE_DIRECTORY)(m_data + resOffset);

            // Tổng số cành cây ở tầng 1
            DWORD entryCount = pResDir->NumberOfNamedEntries + pResDir->NumberOfIdEntries;

            // Nhảy qua thư mục gốc để tới danh sách các cành cây
            PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResDir + 1);

            for (DWORD i = 0; i < entryCount; i++) {
                // Kiểm tra nếu ID không phải là chuỗi (NameIsString == 0)
                if (!pEntry[i].NameIsString) {
                    WORD id = pEntry[i].Id; // Mã số nhận diện loại tài nguyên

                    if (id == 3 || id == 14) m_meta.hasIcon = true;     // 3: Icon đơn, 14: Nhóm Icon
                    else if (id == 16) m_meta.hasVersionInfo = true;    // 16: Thông tin Bản quyền / Version
                    else if (id == 24) m_meta.hasManifest = true;       // 24: File cấu hình Manifest
                    else if (id == 10) m_meta.hasRcData = true;         // 10: RCDATA (Dữ liệu thô - MỎ VÀNG CỦA HACKER)
                }
            }
        }
    }

    return ParseSections(sectionTableOffset);
}

PeStatus PeReader::ParseSections(DWORD sectionTableOffset) {
    // Kiểm tra xem Bảng Section có bị tràn khỏi file (STRUCT_CORRUPT) không?
    DWORD tableSize = m_meta.sectionCount * sizeof(IMAGE_SECTION_HEADER);
    if (!IsValidOffset(sectionTableOffset, tableSize)) return PeStatus::STRUCT_CORRUPT;

    PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)(m_data + sectionTableOffset);

    for (WORD i = 0; i < m_meta.sectionCount; i++) {
        SectionInfo info;
        ZeroMemory(info.name, 9);
        memcpy(info.name, pSection[i].Name, 8); // Tên tối đa 8 ký tự, không có Null-term
        //tọa độ trong RAM khi được load vào bộ nhớ, thường là bội số của 0x1000 (Page Size)
        info.virtualAddress = pSection[i].VirtualAddress;
        // Kích thước thực tế của section khi được load vào RAM (có thể khác SizeOfRawData nếu có padding)
        info.virtualSize = pSection[i].Misc.VirtualSize;
        // Địa chỉ vật lý trên đĩa (File Offset) của section này
        info.rawAddress = pSection[i].PointerToRawData;
        // Kích thước của section trên đĩa (File Size), thường là bội số của 0x200 (File Alignment)
        info.rawSize = pSection[i].SizeOfRawData;
        // Các cờ đặc tính của section (Executable, Writable, Readable, v.v.)
        info.characteristics = pSection[i].Characteristics;

        // Nếu khai báo RawData nằm ngoài file -> Cấu trúc hỏng nặng!
        if (info.rawSize > 0 && !IsValidOffset(info.rawAddress, info.rawSize)) {
            return PeStatus::STRUCT_CORRUPT;
        }

        m_sections.push_back(info);
    }
    return PeStatus::OK;
}

// Tìm chữ ký "Rich" (0x68636952) nằm sau DOS header
bool PeReader::CheckRichHeader(DWORD e_lfanew) {
    if (e_lfanew <= sizeof(IMAGE_DOS_HEADER) || e_lfanew > m_fileSize) return false;

    DWORD startOffset = sizeof(IMAGE_DOS_HEADER);
    DWORD searchLimit = e_lfanew - 4; // Bớt đi 4 byte độ dài chữ Rich

    for (DWORD i = startOffset; i <= searchLimit; i++) {
        if (*(DWORD*)(m_data + i) == 0x68636952) { // Ký tự 'R','i','c','h'
            return true;
        }
    }
    return false;
}

// ==========================================
// HÀM XƯƠNG SỐNG: RVA TO FILE OFFSET
// ==========================================
DWORD PeReader::RvaToFileOffset(DWORD rva) const {
    if (rva == 0) return 0;

    for (const auto& sec : m_sections) {
        // Căn chỉnh: RVA phải nằm lọt thỏm trong VirtualAddress của Section
        if (rva >= sec.virtualAddress && rva < sec.virtualAddress + sec.virtualSize) {

            // Công thức: Khoảng cách từ đầu Section + Địa chỉ vật lý trên đĩa
            DWORD offset = rva - sec.virtualAddress + sec.rawAddress;

            // Chống "STRUCT_CORRUPT": Offset tính ra lại bay màu khỏi file!
            if (offset >= sec.rawAddress && offset < sec.rawAddress + sec.rawSize) {
                return offset;
            }
        }
    }
    return 0; // Trả về 0 nghĩa là RVA bị out of range (Lỗi STRUCT_CORRUPT của file)
}


// ==========================================
// THUẬT TOÁN SHANNON ENTROPY (Đo độ lộn xộn)
// ==========================================
double PeReader::CalculateEntropy(DWORD offset, DWORD size) const {
    if (!IsValidOffset(offset, size) || size == 0) return 0.0;

    const uint8_t* pData = m_data + offset;
    int counts[256] = { 0 };

    // 1. Đếm tần suất xuất hiện của từng byte (từ 0x00 đến 0xFF)
    for (DWORD i = 0; i < size; i++) {
        counts[pData[i]]++;
    }

    // 2. Áp dụng công thức Shannon: H = - sum( p * log2(p) )
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

// ==========================================
// [NHÓM E] XÁC THỰC CHỮ KÝ AUTHENTICODE
// ==========================================
SignatureStatus PeReader::VerifyCertificate(const std::wstring& filePath) {
    WINTRUST_FILE_INFO fileData;
    ZeroMemory(&fileData, sizeof(fileData));
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = filePath.c_str();

    WINTRUST_DATA wintrustData;
    ZeroMemory(&wintrustData, sizeof(wintrustData));
    wintrustData.cbStruct = sizeof(wintrustData);
    wintrustData.dwUIChoice = WTD_UI_NONE;               // Quét ngầm, không hiện bảng thông báo
    wintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;  // Tạm bỏ qua check thu hồi (để tăng tốc độ)
    wintrustData.dwUnionChoice = WTD_CHOICE_FILE;
    wintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    wintrustData.pFile = &fileData;

    // Sử dụng Policy kiểm tra file thực thi tiêu chuẩn của Windows
    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // GỌI API THẦN THÁNH
    LONG lStatus = WinVerifyTrust(NULL, &policyGUID, &wintrustData);

    // Dọn dẹp bộ nhớ sau khi quét xong
    wintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &wintrustData);

    // Phân tích kết quả
    if (lStatus == ERROR_SUCCESS) {
        return SignatureStatus::SIGNED_VALID; // Chữ ký xanh rờn, an toàn!
    }
    else if (lStatus == TRUST_E_NOSIGNATURE) {
        return SignatureStatus::UNSIGNED;     // Không hề có chữ ký
    }
    else {
        // TRUST_E_BAD_DIGEST (File bị sửa đổi), CERT_E_EXPIRED (Hết hạn), CERT_E_REVOKED...
        return SignatureStatus::SIGNED_INVALID;
    }
}