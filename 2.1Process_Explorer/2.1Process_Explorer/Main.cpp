#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <iomanip>
#include <fcntl.h> // Cho _setmode
#include <io.h>    // Cho _setmode
#include <string>  // Để xử lý chuỗi tìm kiếm

#pragma comment(lib, "psapi.lib")

using namespace std;

// Hàm in RAM (MB)
void PrintMemory(DWORD memoryInBytes) {
    double mb = memoryInBytes / (1024.0 * 1024.0);
    wcout << fixed << setprecision(2) << mb << L" MB";
}

// === CHỨC NĂNG 1 & 2: LIỆT KÊ + LỌC THEO TÊN ===
// Tham số 'searchName': Nếu rỗng ("") thì in hết, nếu có chữ thì lọc
void ListProcesses(const wstring& searchName = L"") {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return;
    }

    // In tiêu đề
    wcout << L"\n--- DANH SACH PROCESS ";
    if (!searchName.empty()) wcout << L"(Dang loc: " << searchName << L") ";
    wcout << L"---\n";

    wcout << left << setw(8) << L"PID"
        << left << setw(35) << L"Ten Process"
        << left << setw(15) << L"RAM"
        << L"Duong dan" << endl;
    wcout << L"--------------------------------------------------------------------------------" << endl;

    int count = 0;
    do {
        // --- LOGIC LỌC (FILTER) ---
        // wcsstr: Tìm chuỗi con. Nếu searchName nằm trong szExeFile thì mới in.
        // (Cái này phân biệt hoa thường)
        if (!searchName.empty() && wcsstr(pe32.szExeFile, searchName.c_str()) == NULL) {
            continue; // Bỏ qua vòng lặp nếu tên không khớp
        }

        DWORD ramUsage = 0;
        WCHAR fullPath[MAX_PATH] = L"";

        // Mở process chỉ để đọc thông tin
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
        if (hProcess) {
            PROCESS_MEMORY_COUNTERS pmc;
            if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                ramUsage = pmc.WorkingSetSize;
            }
            if (GetModuleFileNameEx(hProcess, NULL, fullPath, MAX_PATH) == 0) {
                wcscpy_s(fullPath, L"<System>");
            }
            CloseHandle(hProcess);
        }
        else {
            wcscpy_s(fullPath, L"<Access Denied>");
        }

        wcout << left << setw(8) << pe32.th32ProcessID
            << left << setw(35) << pe32.szExeFile;
        PrintMemory(ramUsage);
        wcout << "   " << fullPath << endl;
        count++;

    } while (Process32Next(hSnapshot, &pe32));

    wcout << L"--------------------------------------------------------------------------------" << endl;
    wcout << L"Tim thay: " << count << L" process." << endl;

    CloseHandle(hSnapshot);
}

// === CHỨC NĂNG 3: KILL PROCESS ===
void KillProcessByPID(DWORD pid) {
    // Bước 1: Xin quyền "SÁT THỦ" (PROCESS_TERMINATE)
    // Khác với lúc liệt kê (chỉ cần quyền Đọc), lúc giết cần quyền cao hơn.
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);

    if (hProcess == NULL) {
        wcout << L"ERROR: Khong the mo Process " << pid << L". (Co the do thieu quyen Admin hoac System Process)" << endl;
        return;
    }

    // Bước 2: Ra lệnh chém!
    // 1: Là Exit Code (mã thoát) của process bị giết.
    if (TerminateProcess(hProcess, 1)) {
        wcout << L"SUCCESS: Da diet process " << pid << L" thanh cong!" << endl;
    }
    else {
        wcout << L"FAIL: Lenh TerminateProcess that bai!" << endl;
    }

    // Bước 3: Dọn dẹp
    CloseHandle(hProcess);
}

int main() {
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stdin), _O_U16TEXT); // Để nhập được tiếng Việt/Unicode từ bàn phím nếu cần

    while (true) {
        wcout << L"\n=== TASK MANAGER MINI ===" << endl;
        wcout << L"1. Liet ke toan bo (Refresh)" << endl;
        wcout << L"2. Tim kiem Process (Loc theo ten)" << endl;
        wcout << L"3. Kill Process (Diet theo PID)" << endl;
        wcout << L"0. Thoat" << endl;
        wcout << L"Lua chon cua ban: ";

        int choice;
        wcin >> choice;

        if (choice == 0) break;

        switch (choice) {
        case 1:
            ListProcesses();
            break;
        case 2: {
            wcout << L"Nhap ten can tim (VD: chrome, notepad): ";
            wstring keyword;
            wcin.ignore(); // Xóa bộ đệm bàn phím
            getline(wcin, keyword);
            ListProcesses(keyword);
            break;
        }
        case 3: {
            wcout << L"Nhap PID can diet: ";
            DWORD pid;
            wcin >> pid;
            KillProcessByPID(pid);
            break;
        }
        default:
            wcout << L"Sai lenh!" << endl;
        }
    }

    return 0;
}