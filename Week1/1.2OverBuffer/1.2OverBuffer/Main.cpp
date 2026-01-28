#include <stdio.h>
#include <string.h>

// 1. Hàm UnsafeCopy
void UnsafeCopy(char* dst, const char* src) {
    int i = 0;
    // Copy từng ký tự cho đến khi gặp ký tự kết thúc '\0'
    while (src[i] != '\0') {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0'; // Đóng chuỗi
}

// 2. Hàm SafeCopy
void SafeCopy(char* dst, size_t dstSize, const char* src) {
    if (dstSize == 0) return;

    size_t i;
    
    for (i = 0; i < dstSize - 1; i++) {
        if (src[i] == '\0') break; 
        dst[i] = src[i];
    }
    dst[i] = '\0'; //đóng chuỗi
}

int main() {
    // KỊCH BẢN:
    // Ta có một biến secret chứa mật mã quan trọng.
    // Ngay trước nó là một buffer chỉ chứa được 8 ký tự.
    // (Compiler thường xếp các biến stack liền nhau)

    // Giá trị Hex là FFFF (65535)
    char buffer[8];             // Chỉ chứa được 8 byte
    int secret_number = 0xFFFF;
    printf("=== TRUOC KHI COPY ===\n");
    printf("Dia chi buffer: %p\n", (void*)buffer);
    printf("Dia chi secret: %p\n", (void*)&secret_number);
    printf("Gia tri secret: 0x%X\n\n", secret_number);

    // Chuỗi nguồn dài 12 ký tự (Lớn hơn buffer 8)
    const char* long_string = "HackerAttackkkkkkkkkkkkkkkkkkkk";

    // --- TEST 1: SAFE COPY ---
    printf("--- Chay SafeCopy ---\n");
    SafeCopy(buffer, sizeof(buffer), long_string);
    printf("Buffer sau copy: %s\n", buffer); // Chỉ lấy được "HackerA"
    printf("Gia tri secret:  0x%X (Van an toan)\n\n", secret_number);

    // --- TEST 2: UNSAFE COPY ---
    printf("--- Chay UnsafeCopy ---\n");
    printf("Dang copy '%s' (12 bytes) vao buffer (8 bytes)...\n", long_string);

    UnsafeCopy(buffer, long_string);

    printf("Buffer sau copy: %s\n", buffer);
    printf("Gia tri secret:  0x%X (BI THAY DOI!)\n", secret_number);

    printf("\nNhan Enter de ket thuc...");
    getchar();
    return 0;
}