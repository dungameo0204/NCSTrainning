#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <tchar.h>

// Link thư viện giao diện
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// --- KHAI BÁO ID CÁC NÚT BẤM ---
#define ID_EDIT_PATH    101
#define ID_BTN_BROWSE   102
#define ID_BTN_SCAN     103
#define ID_BTN_STOP     104
#define ID_BTN_CLEAR    105
#define ID_LIST_RESULT  106

// --- BIẾN TOÀN CỤC ---
HWND hEdit, hList, hBtnScan, hBtnStop, hLabelStatus;
HANDLE hWorkerThread = NULL;
HANDLE hStopEvent = NULL;       // Sự kiện để báo dừng
HANDLE hAppMutex = NULL;        // Mutex chống chạy 2 lần
volatile bool isScanning = false; // Cờ trạng thái

// --- HÀM CHECK FILE PE (LOGIC CỐT LÕI) ---
bool IsPEFile(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    // 1. Đọc DOS Header
    IMAGE_DOS_HEADER dosHeader;
    DWORD bytesRead;
    if (!ReadFile(hFile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead, NULL) || bytesRead != sizeof(IMAGE_DOS_HEADER)) {
        CloseHandle(hFile); return false;
    }

    // Check 'MZ'
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile); return false;
    }

    // 2. Nhảy đến PE Header (dựa vào e_lfanew)
    if (SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        CloseHandle(hFile); return false;
    }

    // 3. Đọc Signature
    DWORD peSignature;
    if (!ReadFile(hFile, &peSignature, sizeof(DWORD), &bytesRead, NULL) || bytesRead != sizeof(DWORD)) {
        CloseHandle(hFile); return false;
    }

    // Check 'PE\0\0'
    if (peSignature != IMAGE_NT_SIGNATURE) {
        CloseHandle(hFile); return false;
    }

    CloseHandle(hFile);
    return true; // Chuẩn hàng PE
}

// --- HÀM QUÉT ĐỆ QUY (CHẠY TRONG THREAD) ---
void ScanRecursive(std::wstring folderPath, int depth) {
    // 1. Kiểm tra tín hiệu STOP từ người dùng
    if (WaitForSingleObject(hStopEvent, 0) == WAIT_OBJECT_0) {
        return; // Dừng ngay lập tức
    }

    // 2. Kiểm tra độ sâu tối đa (Max depth = 10)
    if (depth > 10) return;

    // Thêm ký tự đại diện để tìm tất cả
    std::wstring searchPath = folderPath + L"\\*";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        // Kiểm tra tín hiệu STOP lần nữa trong vòng lặp
        if (WaitForSingleObject(hStopEvent, 0) == WAIT_OBJECT_0) break;

        // Bỏ qua thư mục "." và ".."
        if (wcscmp(findData.cFileName, L".") == 0 || wcscmp(findData.cFileName, L"..") == 0) continue;

        std::wstring fullPath = folderPath + L"\\" + findData.cFileName;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Nếu là thư mục -> Đệ quy
            ScanRecursive(fullPath, depth + 1);
        }
        else {
            // Nếu là file -> Check PE
            if (IsPEFile(fullPath)) {
                // Gửi message về giao diện để thêm vào ListBox (Thread an toàn cơ bản)
                // Lưu ý: PostMessage tốt hơn SendMessage khi gọi từ thread khác
                // Nhưng ở đây để đơn giản ta dùng SendMessage trực tiếp vì ListBox handle này valid.
                SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)fullPath.c_str());
            }
        }

    } while (FindNextFileW(hFind, &findData) != 0);

    FindClose(hFind);
}

// --- HÀM CỦA THREAD ---
DWORD WINAPI ThreadProc(LPVOID lpParam) {
    std::wstring* pPath = (std::wstring*)lpParam;

    // Reset sự kiện Stop
    ResetEvent(hStopEvent);

    SetWindowTextW(hLabelStatus, L"Status: Scanning...");
    EnableWindow(hBtnScan, FALSE); // Disable nút Scan
    EnableWindow(hBtnStop, TRUE);  // Enable nút Stop

    // Bắt đầu quét từ độ sâu 0
    ScanRecursive(*pPath, 0);

    // Dọn dẹp
    delete pPath;
    isScanning = false;

    SetWindowTextW(hLabelStatus, L"Status: Done/Stopped.");
    EnableWindow(hBtnScan, TRUE);
    EnableWindow(hBtnStop, FALSE);
    return 0;
}

// --- XỬ LÝ SỰ KIỆN CỬA SỔ ---
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE:
    {
        // Tạo giao diện thủ công (không cần file .rc)
        CreateWindowW(L"STATIC", L"Path:", WS_CHILD | WS_VISIBLE, 10, 15, 40, 20, hWnd, NULL, NULL, NULL);
        hEdit = CreateWindowW(L"EDIT", L"C:\\Windows\\System32", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 60, 10, 300, 25, hWnd, (HMENU)ID_EDIT_PATH, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Browse...", WS_CHILD | WS_VISIBLE, 370, 10, 80, 25, hWnd, (HMENU)ID_BTN_BROWSE, NULL, NULL);

        hBtnScan = CreateWindowW(L"BUTTON", L"SCAN PE", WS_CHILD | WS_VISIBLE, 10, 50, 100, 30, hWnd, (HMENU)ID_BTN_SCAN, NULL, NULL);
        hBtnStop = CreateWindowW(L"BUTTON", L"STOP", WS_CHILD | WS_VISIBLE | WS_DISABLED, 120, 50, 100, 30, hWnd, (HMENU)ID_BTN_STOP, NULL, NULL);
        CreateWindowW(L"BUTTON", L"CLEAR", WS_CHILD | WS_VISIBLE, 230, 50, 100, 30, hWnd, (HMENU)ID_BTN_CLEAR, NULL, NULL);

        hLabelStatus = CreateWindowW(L"STATIC", L"Status: Ready", WS_CHILD | WS_VISIBLE, 350, 55, 150, 20, hWnd, NULL, NULL, NULL);

        hList = CreateWindowW(L"LISTBOX", NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | LBS_NOTIFY, 10, 90, 460, 350, hWnd, (HMENU)ID_LIST_RESULT, NULL, NULL);

        // Tạo font chữ cho đẹp (tùy chọn)
        HFONT hFont = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
        SendMessage(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessage(hList, WM_SETFONT, (WPARAM)hFont, TRUE);

        // Tạo Event Stop (Manual Reset = TRUE, Initial State = FALSE)
        hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        break;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_BTN_BROWSE:
        {
            BROWSEINFOW bi = { 0 };
            bi.lpszTitle = L"Chon thu muc can quet:";
            LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
            if (pidl != 0) {
                wchar_t path[MAX_PATH];
                if (SHGetPathFromIDListW(pidl, path)) {
                    SetWindowTextW(hEdit, path);
                }
                CoTaskMemFree(pidl);
            }
            break;
        }
        case ID_BTN_SCAN:
        {
            if (isScanning) break;

            // Lấy đường dẫn từ ô Edit
            int len = GetWindowTextLengthW(hEdit);
            if (len == 0) { MessageBox(hWnd, L"Nhap duong dan di!", L"Loi", MB_OK); break; }

            wchar_t* buffer = new wchar_t[len + 1];
            GetWindowTextW(hEdit, buffer, len + 1);
            std::wstring* path = new std::wstring(buffer);
            delete[] buffer;

            // Clear list cũ
            SendMessage(hList, LB_RESETCONTENT, 0, 0);

            // Bắt đầu Thread mới
            isScanning = true;
            // CreateThread(Security, StackSize, Func, Param, Flags, ThreadId)
            hWorkerThread = CreateThread(NULL, 0, ThreadProc, path, 0, NULL);
            break;
        }
        case ID_BTN_STOP:
        {
            if (isScanning) {
                SetEvent(hStopEvent); // Bật cờ Stop -> Thread sẽ đọc được và dừng
            }
            break;
        }
        case ID_BTN_CLEAR:
            SendMessage(hList, LB_RESETCONTENT, 0, 0);
            break;
        }
        break;

    case WM_DESTROY:
        // Dọn dẹp trước khi thoát
        if (isScanning) {
            SetEvent(hStopEvent);
            WaitForSingleObject(hWorkerThread, 2000); // Chờ thread tắt hẳn
        }
        if (hStopEvent) CloseHandle(hStopEvent);
        if (hWorkerThread) CloseHandle(hWorkerThread);
        if (hAppMutex) CloseHandle(hAppMutex); // Nhả Mutex
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// --- MAIN ---
int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {

    // --- BÀI TOÁN 1: SINGLE INSTANCE (MUTEX) ---
    // Tạo một Mutex có tên cố định
    hAppMutex = CreateMutexW(NULL, TRUE, L"MyUniquePEMonitorString");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxW(NULL, L"Chuong trinh dang chay roi! Khong duoc mo cai thu 2.", L"Loi", MB_ICONERROR);
        return 0; // Thoát luôn
    }

    // Đăng ký Class cửa sổ
    WNDCLASSEXW wcex = { 0 };
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.hInstance = hInstance;
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszClassName = L"PEMonitorClass";

    RegisterClassExW(&wcex);

    // Tạo cửa sổ
    HWND hWnd = CreateWindowW(L"PEMonitorClass", L"PE Finder Tool (Bai 4.2)", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, 0, 500, 500, NULL, NULL, hInstance, NULL);

    if (!hWnd) return FALSE;

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    // Vòng lặp message
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}