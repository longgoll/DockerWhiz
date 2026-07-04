# DockerWhiz 🐳

**DockerWhiz** là một công cụ giám sát container Docker thời gian thực (Real-time), siêu nhẹ (Memory footprint dưới 10MB RAM) và tự động gửi cảnh báo qua Telegram. Hệ thống được thiết kế theo triết lý tối giản (Zero-dependency, No-Database) và được xây dựng bằng Go kết hợp với giao diện HTML5 thuần (Alpine.js + Tailwind CSS qua CDN).

---

## ✨ Tính năng nổi bật

- **⚡ Real-time Dashboard**: Cập nhật trạng thái và mức tiêu thụ RAM của các container theo thời gian thực sử dụng Server-Sent Events (SSE) thay vì các kết nối WebSocket phức tạp.
- **🛠️ Điều khiển Container trực tiếp**: Khởi động (Start), Dừng (Stop), Khởi động lại (Restart) các container và xem 100 dòng log (nhật ký) mới nhất ngay trên giao diện web.
- **🚨 Cảnh báo qua Telegram**:
  - Gửi thông báo tức thì khi container gặp lỗi đột ngột (`die`, `oom-killed`, `unhealthy`).
  - Gửi thông báo khi bạn thao tác Start/Stop container thủ công hoặc tự động.
  - Cấu hình linh hoạt **Telegram Bot Token** & **Chat ID** trực tiếp trên Dashboard và có nút **Test Connection** để kiểm tra ngay lập tức.
- **📈 Giám sát tài nguyên VPS**: Định kỳ quét tài nguyên CPU, RAM, Disk của máy chủ VPS và gửi cảnh báo qua Telegram khi tài nguyên vượt ngưỡng an toàn (CPU > 90%, RAM trống < 10%, Disk > 85%).
- **🧹 Tự động dọn dẹp hệ thống (Smart Prune)**: Dọn dẹp các container đã dừng, image rác (dangling), network thừa theo lịch trình tự cấu hình, giúp tiết kiệm dung lượng đĩa của VPS.
- **🔒 Bảo mật & Xác thực**:
  - Cơ chế **Setup Mode** khởi tạo mật khẩu admin trong lần chạy đầu tiên. Mật khẩu được băm SHA-256 kèm chuỗi Salt ngẫu nhiên và lưu tại `config.json`.
  - Bảo vệ API với **Session Cookie** và ngăn chặn **CSRF** qua Custom Safety Header (`X-DockerWhiz-Request`).
  - Tích hợp **Login Rate Limiter** tự động chặn IP (Lockout 15 phút) nếu nhập sai mật khẩu quá 5 lần.
- **📦 Siêu nhẹ & Dễ triển khai**: Đóng gói dạng Docker Multi-stage từ base image `scratch`, dung lượng cực nhỏ, chỉ cần mount socket Docker `/var/run/docker.sock`.

---

## 🛠️ Yêu cầu hệ thống

- Docker đã cài đặt trên máy chủ.
- Go (phiên bản 1.24 hoặc mới hơn) nếu biên dịch thủ công từ mã nguồn.

---

## 🚀 Hướng dẫn triển khai nhanh (Quick Start)

### Cách 1: Triển khai bằng Docker (Khuyên dùng)

Bạn có thể chạy DockerWhiz trực tiếp bằng dòng lệnh sau:

```bash
docker run -d \
  --name dockerwhiz \
  -p 8082:8082 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/config.json:/config.json \
  -e CONFIG_PATH=/config.json \
  --restart always \
  longgoll/dockerwhiz:latest
```

*Lưu ý: Hãy chắc chắn file `config.json` có quyền đọc/ghi để DockerWhiz lưu cấu hình mật khẩu và Telegram.*

### Cách 2: Triển khai bằng Docker Compose

Tạo tệp `docker-compose.yml`:

```yaml
version: '3.8'

services:
  dockerwhiz:
    image: longgoll/dockerwhiz:latest
    container_name: dockerwhiz
    ports:
      - "8082:8082"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./config.json:/config.json
    environment:
      - CONFIG_PATH=/config.json
    restart: always
```

Chạy lệnh để khởi động:
```bash
docker compose up -d
```

### Cách 3: Chạy trực tiếp từ mã nguồn Go

1. Cài đặt các gói phụ thuộc (Docker SDK):
   ```bash
   go mod tidy
   ```
2. Chạy ứng dụng:
   ```bash
   go run .
   ```
   Ứng dụng sẽ lắng nghe tại cổng `8082` mặc định (hoặc cấu hình qua biến môi trường `PORT`).

---

## ⚙️ Cấu hình Biến môi trường (Environment Variables)

Bạn có thể tùy chỉnh các cấu hình sau qua biến môi trường khi chạy Docker:

| Biến môi trường | Mặc định | Mô tả |
| :--- | :--- | :--- |
| `DOCKER_SOCKET` | `/var/run/docker.sock` | Đường dẫn đến UNIX socket của Docker Daemon. |
| `PORT` | `8082` | Cổng HTTP mà dịch vụ sẽ lắng nghe. |
| `CONFIG_PATH` | `./config.json` | Đường dẫn lưu trữ tệp cấu hình bảo mật và Telegram. |
| `TELEGRAM_BOT_TOKEN` | *Trống* | Token của Telegram Bot (dùng làm mặc định nếu không cấu hình qua UI). |
| `TELEGRAM_CHAT_ID` | *Trống* | Chat ID nhận thông báo (dùng làm mặc định nếu không cấu hình qua UI). |

---

## 🔒 Hướng dẫn thiết lập ban đầu (Setup Mode)

1. Sau khi khởi chạy DockerWhiz lần đầu, truy cập vào giao diện web qua địa chỉ `http://<IP-cua-ban>:8082`.
2. Hệ thống sẽ hiển thị màn hình **Setup Mode**.
3. Xem log của container để lấy mã **Setup Token** ngẫu nhiên được in ra ở terminal:
   ```bash
   docker logs dockerwhiz
   ```
4. Copy Setup Token, nhập mật khẩu quản trị mong muốn và ấn **Complete Setup**.
5. Đăng nhập và bắt đầu quản lý các container của bạn!

---

## 📂 Cấu trúc thư mục dự án

```plaintext
DockerWhiz/
├── main.go             # Logic Backend chính (kết nối Docker API, SSE stream, cảnh báo Telegram, Smart Prune)
├── sysmon_linux.go     # Module thu thập chỉ số CPU, RAM, Disk trên hệ điều hành Linux
├── sysmon_windows.go   # Module giả lập/thu thập chỉ số trên Windows phục vụ phát triển (Dev)
├── index.html          # Giao diện Frontend Single-Page (SPA) thuần
├── go.mod              # Khai báo Go module
├── Dockerfile          # Cấu hình biên dịch tối ưu (Multi-stage & Scratch build)
├── .gitignore          # Cấu hình bỏ qua các tệp tin biên dịch và cấu hình cục bộ
├── LICENSE             # Tệp tin giấy phép MIT của dự án
└── README.md           # Tài liệu hướng dẫn sử dụng
```

---

## 🤝 Đóng góp dự án

Mọi đóng góp, báo lỗi (issue) hoặc yêu cầu tính năng mới đều được chào đón! Vui lòng tạo Issue hoặc gửi Pull Request trên GitHub repository của dự án.

---

## 📄 Giấy phép

Dự án được phân phối dưới giấy phép MIT License. Xem tệp `LICENSE` để biết thêm chi tiết.
