#include <windows.h>
#include <iostream>
#include <vector>
#include <iomanip>
#include <string>
#include <fcntl.h>
#include <io.h>

using namespace std;

// Hàm 1: Liệt kê tất cả Service
void ListAllServices() {
    // 1. Mở kết nối đến SCM (Service Control Manager)
    // SC_MANAGER_ENUMERATE_SERVICE: Chỉ xin quyền liệt kê (User thường cũng chạy được)
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);

    if (hSCM == NULL) {
        wcout << L"[LOI] Khong the mo SCM! (Ma loi: " << GetLastError() << L")" << endl;
        return;
    }

    // 2. Hỏi kích thước bộ nhớ cần thiết (Kỹ thuật 2 bước giống Registry)
    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;

    // Gọi lần 1 với buffer NULL để lấy bytesNeeded
    EnumServicesStatusEx(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, NULL, 0,
        &bytesNeeded, &servicesReturned, &resumeHandle, NULL);

    // 3. Cấp phát bộ nhớ
    vector<BYTE> buffer(bytesNeeded);

    // 4. Lấy dữ liệu thật
    LPENUM_SERVICE_STATUS_PROCESS pServices = (LPENUM_SERVICE_STATUS_PROCESS)buffer.data();

    if (EnumServicesStatusEx(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, buffer.data(), bytesNeeded,
        &bytesNeeded, &servicesReturned, &resumeHandle, NULL)) {

        wcout << L"\n--- DANH SACH WINDOWS SERVICES (" << servicesReturned << L") ---" << endl;
        wcout << left << setw(35) << L"Ten Service (Name)"
            << setw(15) << L"Trang thai"
            << L"Ten Hien Thi (Display Name)" << endl;
        wcout << L"---------------------------------------------------------------------------------" << endl;

        for (DWORD i = 0; i < servicesReturned; i++) {
            // Lọc bớt cho đỡ dài, chỉ hiện 50 cái đầu tiên làm mẫu
            if (i >= 50) {
                wcout << L"... (Con nhieu lam nhung dung o day thoi) ..." << endl;
                break;
            }

            wcout << left << setw(35) << pServices[i].lpServiceName;

            if (pServices[i].ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING)
                wcout << setw(15) << L"[RUNNING]";
            else if (pServices[i].ServiceStatusProcess.dwCurrentState == SERVICE_STOPPED)
                wcout << setw(15) << L"[STOPPED]";
            else
                wcout << setw(15) << L"[OTHER]"; // Paused, StartPending...

            // Cắt bớt tên hiển thị nếu dài quá
            wstring displayName = pServices[i].lpDisplayName;
            if (displayName.length() > 40) displayName = displayName.substr(0, 37) + L"...";
            wcout << displayName << endl;
        }
    }
    else {
        wcout << L"[LOI] Khong liet ke duoc service." << endl;
    }

    CloseServiceHandle(hSCM);
}

// Hàm 2: Bật/Tắt Service
void ControlMyService(LPCWSTR serviceName, bool turnOn) {
    // 1. Mở SCM
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS); // Cần quyền cao nhất
    if (!hSCM) {
        wcout << L"[LOI] Can quyen Administrator de Bat/Tat service!" << endl;
        return;
    }

    // 2. Mở Service cụ thể
    SC_HANDLE hService = OpenServiceW(hSCM, serviceName, SERVICE_ALL_ACCESS);
    if (!hService) {
        wcout << L"[LOI] Khong tim thay service: " << serviceName << endl;
        CloseServiceHandle(hSCM);
        return;
    }

    // 3. Thực hiện lệnh
    if (turnOn) {
        // Lệnh START
        if (StartService(hService, 0, NULL)) {
            wcout << L"[OK] Da gui lenh START den: " << serviceName << endl;
        }
        else {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_ALREADY_RUNNING) wcout << L"[INFO] Service dang chay roi!" << endl;
            else wcout << L"[LOI] Start that bai. Ma loi: " << err << endl;
        }
    }
    else {
        // Lệnh STOP
        SERVICE_STATUS status;
        if (ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
            wcout << L"[OK] Da gui lenh STOP den: " << serviceName << endl;
        }
        else {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_NOT_ACTIVE) wcout << L"[INFO] Service dang tat roi!" << endl;
            else wcout << L"[LOI] Stop that bai. Ma loi: " << err << endl;
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
}

int main() {
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stdin), _O_U16TEXT);

    while (true) {
        wcout << L"\n=== SERVICE CONTROLLER ===" << endl;
        wcout << L"1. Liet ke Service" << endl;
        wcout << L"2. Bat (Start) Service" << endl;
        wcout << L"3. Tat (Stop) Service" << endl;
        wcout << L"4. Thoat" << endl;
        wcout << L"Lua chon: ";

        int choice;
        wcin >> choice;

        if (choice == 1) {
            ListAllServices();
        }
        else if (choice == 2 || choice == 3) {
            wcout << L"Nhap TEN SERVICE (ServiceName, khong phai DisplayName): ";
            // Ví dụ: Nhập "wuauserv" (Windows Update) hoặc "Spooler" (Print Spooler)
            wstring name;
            wcin >> name;

            ControlMyService(name.c_str(), (choice == 2));
        }
        else {
            break;
        }
    }
    return 0;
}