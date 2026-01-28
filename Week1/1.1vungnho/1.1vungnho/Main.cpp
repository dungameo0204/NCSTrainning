#include <stdio.h>  
#include <stdlib.h> 

// 1. BIẾN GLOBAL:
int g_GlobalVar = 100;

void MemoryLayoutExplorer() {
    // 2. BIẾN STATIC:   
    static int s_StaticVar = 200;
    // 3. BIẾN LOCAL (STACK):
    int l_LocalVar = 300;
    // 4. BIẾN HEAP (CẤP PHÁT ĐỘNG):
    int* p_HeapVar = (int*)malloc(sizeof(int));
    *p_HeapVar = 400;

    printf("=== BAO CAO BO NHO (x64) ===\n");
    printf("1. Global Var Address: %p\n", (void*)&g_GlobalVar);
    printf("2. Static Var Address: %p\n", (void*)&s_StaticVar);
    printf("3. Heap Address:       %p\n", (void*)p_HeapVar);
    printf("4. Local Var (Stack):  %p\n", (void*)&l_LocalVar);

    printf("\n=== SO SANH KHOANG CACH ===\n");

    // Tính khoảng cách giữa Stack và Heap
    long long diff_Stack_Heap =  (char*)p_HeapVar - (char*)&l_LocalVar;

    printf("Khoang cach tu Stack xuong Heap: %lld bytes\n", diff_Stack_Heap);
    // Tính khoảng cách giữa Global và Static
    long long diff_Global_Static = (char*)&s_StaticVar - (char*)&g_GlobalVar;
    printf("Khoang cach Global vs Static:    %lld bytes (Rat gan nhau)\n", diff_Global_Static);

    // Tính khoảng cách giữa Static và Heap
    long long diff_Heap_Static = (char*)&s_StaticVar - (char*)&p_HeapVar;
    printf("Khoang cach Heap vs Static:    %lld bytes", diff_Heap_Static);
    // Dọn dẹp bộ nhớ Heap
    free(p_HeapVar);
}

int main() {
    MemoryLayoutExplorer();
    printf("\nNhan Enter de thoat...");
    getchar();
    return 0;
}