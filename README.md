# SANWAY - Hệ Thống ERP Quản Lý & Xuất Báo Giá PCCC Chuyên Nghiệp

Hệ thống ERP tạo, quản lý sản phẩm, lưu trữ báo giá và xuất PDF chuẩn khổ A4 theo bộ nhận diện thương hiệu **SANWAY** (*Cho mỗi bước tiến thêm vững vàng*).

## 🚀 Tính Năng Chính
- **Bố Cục ERP Sidebar Chuyên Nghiệp**:
  - **Lập Báo Giá & Live Preview**: Giao diện chia đôi màn hình (Split-Screen) — bên trái chọn hạng mục/số lượng, bên phải hiển thị trực tiếp bản xem trước tờ A4 thời gian thực (không cần bấm chuyển tab mới thấy Preview).
  - **Mã Báo Giá Tự Động (`BGSW/YYYY/NNN`)**: Mỗi lần tạo báo giá mới tự động sinh mã kế tiếp (`BGSW/2026/001`, `BGSW/2026/002`...). Bấm **"Tạo & Lưu Báo Giá"** để lưu toàn bộ hồ sơ báo giá vào Database.
  - **Quản Lý Báo Giá (`quotes`)**: Lưu lịch sử tất cả báo giá đã lập, tìm kiếm theo mã `BGSW/...` hoặc tên khách hàng, mở lại để chỉnh sửa, nhân bản sang mã mới, hoặc in/xuất PDF ngay.
  - **Quản Lý Sản Phẩm (`products`)**: Quản lý danh mục 47+ vật tư/thiết bị PCCC gốc, sửa đơn giá chuẩn, đơn vị tính, thêm sản phẩm mới vào danh mục dùng chung.
  - **Cấu Hình & Nhân Sự (`admin`)**: Phân quyền bảo mật bằng mã PIN 4 số trên Backend, quản lý thông tin pháp nhân, con dấu mộc đỏ và logo.

## ☁️ Hướng Dẫn Deploy Lên Vercel & Kết Nối Cloud Database (Vercel KV / Upstash Redis)

Dự án đã được cấu hình sẵn `vercel.json` và Serverless API `/api/index.js` tương thích 100% với **Vercel**.

### Bước 1: Đẩy code lên GitHub và Import vào Vercel
1. Truy cập [vercel.com](https://vercel.com) → **Add New...** → **Project**.
2. Chọn kho lưu trữ (Repository) GitHub của dự án và bấm **Deploy**.

### Bước 2: Gắn Cloud Database miễn phí trên Vercel (Upstash Redis / Vercel KV)
Vì Vercel chạy theo cơ chế Serverless (file tạm `/tmp` sẽ tự xóa khi hàm nghỉ), để lưu vĩnh viễn danh sách **Báo giá (`BGSW/...`)**, **Danh mục sản phẩm** và **Mã PIN nhân sự** trên Cloud:
1. Trong trang quản trị Project trên Vercel, vào tab **Storage** (ở thanh menu trên cùng).
2. Bấm **Create Database** (hoặc **Connect Store**) → Chọn **Upstash** → **Upstash for Redis** (Gói **Free** hoàn toàn miễn phí) → Bấm **Continue** / **Create**.
3. Sau khi tạo xong, bấm **Connect Project** → Chọn Project báo giá SANWAY của bạn → Bấm **Connect**.
   - Vercel sẽ tự động chèn 2 biến môi trường `KV_REST_API_URL` (hoặc `UPSTASH_REDIS_REST_URL`) và `KV_REST_API_TOKEN` (hoặc `UPSTASH_REDIS_REST_TOKEN`) vào Project.
4. Vào tab **Deployments** → Bấm dấu `•••` ở bản Deploy mới nhất → Chọn **Redeploy** để kích hoạt Database.
5. Sau khi Redeploy, trạng thái ở góc dưới Sidebar sẽ hiển thị: **`Cloud DB: Vercel KV (Upstash)`**.

## 💻 Chạy Thử Nghiệm Ở Máy Cá Nhân (Local)
```bash
npm start
# hoặc: node server.js
```
Truy cập: `http://localhost:3000`
