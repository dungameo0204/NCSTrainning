#define _CRT_SECURE_NO_WARNINGS // Chống lỗi warning của Visual Studio
#include <stdio.h>
#include <string.h>

// 1. ĐỊNH NGHĨA HEADER
// Dùng pragma pack(1) để ép struct có kích thước chuẩn 12 bytes
// (4 magic + 4 version + 4 dataSize)
#pragma pack(push, 1)
struct FILE_HDR {
    char magic[4];  
    int version;   
    int dataSize;  
};
#pragma pack(pop) 

// 2. HÀM GHI FILE (Write)
void WriteSaveFile(const char* fileName) {
    FILE* f = fopen(fileName, "wb"); 
    if (!f) {
        printf("Loi: Khong tao duoc file %s\n", fileName);
        return;
    }

    struct FILE_HDR header;

    // Giả lập thông số
    memcpy(header.magic, "ZELD", 4); // Chữ ký là "ZELD"
    header.version = 1;
    header.dataSize = 500;

    // Ghi cả khối struct xuống ổ cứng
    fwrite(&header, sizeof(struct FILE_HDR), 1, f);

    // Ghi thêm một ít dữ liệu giả phía sau (Payload)
    char payload[] = "Day la du lieu bi mat cua game...";
    fwrite(payload, strlen(payload), 1, f);

    printf("[WRITE] Da ghi file: %s\n", fileName);
    fclose(f);
}

// 3. HÀM ĐỌC FILE (Read & Validate)
void ReadAndParse(const char* fileName) {
    FILE* f = fopen(fileName, "rb"); // rb = Read Binary
    if (!f) {
        printf("Loi: Khong mo duoc file %s\n", fileName);
        return;
    }

    struct FILE_HDR header;

    // Đọc đúng 12 bytes đầu tiên vào struct
    fread(&header, sizeof(struct FILE_HDR), 1, f);

    // Validate Magic: Kiểm tra xem có đúng là file của mình không
    // (So sánh 4 byte đầu với chữ "ZELD")
    if (memcmp(header.magic, "ZELD", 4) == 0) {
        printf("\n[READ] => FILE HOP LE (Valid)!\n");
        printf("   + Magic:   %c%c%c%c\n", header.magic[0], header.magic[1], header.magic[2], header.magic[3]);
        printf("   + Version: %d\n", header.version);
        printf("   + Data Sz: %d bytes\n", header.dataSize);
    }
    else {
        printf("\n[READ] => FILE LOI HOAC KHONG HO TRO!\n");
        printf("   (Magic nhan duoc: %c%c%c%c)\n", header.magic[0], header.magic[1], header.magic[2], header.magic[3]);
    }

    fclose(f);
}

int main() {
    const char* NAME = "game_save.dat";

    // Bước 1: Tạo file
    WriteSaveFile(NAME);

    // Bước 2: Đọc file
    ReadAndParse(NAME);

    // Bước 3: Thử thách (Hack file)
    // Bạn thử mở file .dat bằng Notepad và sửa chữ ZELD thành cái khác
    // rồi chạy lại chương trình xem nó có báo lỗi không nhé.

    printf("\nNhan Enter de ket thuc...");
    getchar();
    return 0;
}