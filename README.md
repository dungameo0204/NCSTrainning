# Custom Antivirus Service (MyAvService)

Hệ thống quét virus mô hình Client-Server (Windows Service), hỗ trợ đa luồng, caching và tự động điều tiết tài nguyên.

---

## 1. Yêu cầu hệ thống
* **OS:** Windows 10/11 (64-bit).
* **IDE:** Visual Studio 2019 hoặc 2022.
* **Quyền:** Administrator (Bắt buộc để chạy Service).

## 2. Cách tải và Build (Cài đặt)

**Bước 1: Clone mã nguồn**
Mở CMD/Terminal và chạy:
```bash
git clone [https://github.com/dungameo0204/NCSTrainning]([https://github.com/username/MyAvProject.git](https://github.com/dungameo0204/NCSTrainning))
cd MyAvProject
```

**Bước 2: Build Project**
1. Mở file `MyAvProject.sln` bằng Visual Studio.
2. Chuyển cấu hình sang **Release - x64**.
3. Bấm **Build Solution** (`Ctrl + Shift + B`).
4. Kiểm tra thư mục `x64/Release`, đảm bảo có đủ 3 file: `MyService.exe`, `MyClient.exe`, `ScannerEngine.dll`.

---

## 3. Cách chạy thử (Quan trọng)

Vì đây là **Windows Service**, bạn không thể click đúp vào `MyService.exe`. Hãy làm theo các bước sau:

**Bước 1: Đăng ký Service**
Mở **CMD** với quyền **Run as Administrator**, gõ lệnh sau (Sửa lại đường dẫn đúng với máy bạn):

```cmd
sc create MyAvService binPath= "D:\Đường\Dẫn\Tới\MyService.exe" start= auto
```
*(Lưu ý: Bắt buộc phải có dấu cách sau dấu bằng `binPath= `)*

**Bước 2: Khởi động Service**
```cmd
sc start MyAvService
```

**Bước 3: Chạy Client**
Mở CMD, kéo file `MyClient.exe` vào và chạy để ra lệnh.

---

## 4. Các lệnh sử dụng

Tại màn hình Client, bạn có thể gõ các lệnh sau:

* **Quét thư mục:**
  `scan D:\DuLieu` 
  *(Client sẽ trả về một Batch ID, ví dụ: 5000)*

* **Xem tiến độ:**
  `query 5000`
  *(Xem trạng thái %, số lượng virus phát hiện)*

* **Hủy quét:**
  `cancel 5000`
  *(Dừng ngay lập tức)*

---

## ⚠️ Khắc phục lỗi thường gặp

**Lỗi: `LNK1168: cannot open MyService.exe for writing` khi Build**
* **Nguyên nhân:** Service đang chạy ngầm nên khóa file.
* **Cách sửa:** Mở Task Manager -> Tab Details -> Chuột phải `MyService.exe` -> **End Task**. Sau đó Build lại.

**Lỗi: Client bật lên rồi tắt ngay**
* **Cách sửa:** Hãy mở CMD trước, rồi gõ đường dẫn file Client vào để chạy.
