#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <iomanip>
#include <fcntl.h>
#include <io.h>

// Không cần psapi.lib nếu chỉ liệt kê Tên và PID cơ bản
// Nếu muốn lấy RAM thì mới cần psapi.h và #pragma comment

using namespace std;

// --- HÀM TRỢ GIÚP TÍNH THỜI GIAN ---
unsigned long long FileTimeToInt64(const FILETIME& ft) {
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return uli.QuadPart / 10000; // Đổi sang ms
}

// --- CHỨC NĂNG 1: HIỆN DANH SÁCH PROCESS---
void ShowProcessList() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return;
    }

    wcout << L"\n=== DANH SACH PROCESS DANG CHAY ===" << endl;
    wcout << left << setw(8) << L"PID" << L"Ten Process" << endl;
    wcout << L"-----------------------------------" << endl;

    do {
        // Chỉ in ra PID và Tên
        wcout << left << setw(8) << pe32.th32ProcessID
            << pe32.szExeFile << endl;
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    wcout << L"-----------------------------------" << endl;
}

// --- CHỨC NĂNG 2: THREAD CỦA 1 PROCESS ---
void ShowThreadList(DWORD ownerPID) {
    // Chụp ảnh toàn bộ Thread hệ thống
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnap, &te32)) {
        CloseHandle(hThreadSnap);
        return;
    }

    wcout << L"\n>>> DANG SOI PROCESS PID: " << ownerPID << L" <<<" << endl;
    wcout << left << setw(10) << L"TID"
        << left << setw(10) << L"Priority"
        << left << setw(15) << L"CPU Time(ms)"
        << L"Status" << endl;
    wcout << L"--------------------------------------------------" << endl;

    int count = 0;
    bool foundAny = false;

    do {
        // LỌC: Chỉ lấy thread của process này
        if (te32.th32OwnerProcessID == ownerPID) {
            foundAny = true;
            DWORD cpuTimeMs = 0;
            wstring status = L"Running";

            // Mở thread để lấy thông tin thời gian
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
            if (hThread) {
                FILETIME ftCreate, ftExit, ftKernel, ftUser;
                if (GetThreadTimes(hThread, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
                    cpuTimeMs = (DWORD)(FileTimeToInt64(ftKernel) + FileTimeToInt64(ftUser));
                }
                CloseHandle(hThread);
            }
            else {
                status = L"<Access Denied>";
            }

            wcout << left << setw(10) << te32.th32ThreadID
                << left << setw(10) << te32.tpBasePri
                << left << setw(15) << cpuTimeMs
                << status << endl;
            count++;
        }
    } while (Thread32Next(hThreadSnap, &te32));

    if (!foundAny) {
        wcout << L"(Khong tim thay thread nao hoac Process da tat)" << endl;
    }
    else {
        wcout << L"--------------------------------------------------" << endl;
        wcout << L"Tong cong: " << count << L" threads." << endl;
    }

    CloseHandle(hThreadSnap);
}

int main() {
    // Cài đặt in tiếng Việt/Unicode
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stdin), _O_U16TEXT);

    while (true) {
        // Bước 1: Hiện danh sách để chọn
        ShowProcessList();

        // Bước 2: Nhập PID
        wcout << L"\nNhap PID muon soi (Nhap 0 de thoat): ";
        DWORD pid;
        wcin >> pid;

        if (pid == 0) break;

        // Bước 3: Hiện Thread
        ShowThreadList(pid);

        wcout << L"\nNhan Enter de tiep tuc chon Process khac...";
        wcin.ignore();
        wcin.get(); // Dừng màn hình chờ Enter
    }

    return 0;
}