#include <stdio.h>

// Định nghĩa Union
// Tổng kích thước: 4 bytes (Bằng thành viên lớn nhất là int)
union IpConverter {
    unsigned int wholeValue; // 4 bytes: Nhìn dưới dạng 1 số nguyên lớn
    unsigned char parts[4];  // 4 bytes: Nhìn dưới dạng 4 mảnh nhỏ (mảng)
};

int main() {
    union IpConverter ip;

    printf("=== CACH 1: NHAP TUNG PHAN (Human View) ===\n");
    // Ta gán giá trị cho mảng 'parts' (giống như nhập IP: 192.168.1.10)
    ip.parts[0] = 192; // Byte đầu
    ip.parts[1] = 168; // Byte hai
    ip.parts[2] = 1;   // Byte ba
    ip.parts[3] = 10;  // Byte cuối

    // TỰ ĐỘNG biến 'wholeValue' cũng có dữ liệu (vì chung nhà)
    printf("IP: %d.%d.%d.%d\n", ip.parts[0], ip.parts[1], ip.parts[2], ip.parts[3]);
    printf("Gia tri so nguyen (Hex): 0x%X\n", ip.wholeValue);

    printf("\n=== CACH 2: NHAP SO NGUYEN (Machine View) ===\n");
    // Giờ ta sửa thẳng vào biến 'wholeValue'
    // 0x01020304 tương ứng với các byte 01, 02, 03, 04
    ip.wholeValue = 0xA01A8C0;

    printf("Da gan gia tri nguyen lon la: 0x%08X\n", ip.wholeValue);
    printf("Tu dong tach ra thanh: %d.%d.%d.%d\n",
        ip.parts[0], ip.parts[1], ip.parts[2], ip.parts[3]);

    printf("\n=== KIEM TRA BO NHO ===\n");
    printf("Dia chi 'wholeValue': %p\n", (void*)&ip.wholeValue);
    printf("Dia chi 'parts':      %p\n", (void*)ip.parts);
    printf("=> Chung la mot!\n");

    getchar();
    return 0;
}