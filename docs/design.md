Chào bạn, tinh thần làm chủ công nghệ và tối ưu đến từng byte dữ liệu của bạn rất đúng chất "vắt kiệt hiệu năng" VPS.

Tôi xin đặt tên cho dự án này là: DockerWhiz (Sự kết hợp giữa chú cá voi Docker và sự nhanh nhẹn, thông minh của Wizard/Whiz). Hoặc một cái tên đậm chất tối giản hơn: DockerWhiz. Trong bản thiết kế này, chúng ta sẽ dùng tên DockerWhiz nhé.

Dưới đây là bản thiết kế chi tiết (Architectural Design Document) được may đo riêng cho mục tiêu: Siêu nhẹ - Realtime - Tự động cảnh báo.

Bản Thiết Kế Hệ Thống: DockerWhiz
Tiêu chí cốt lõi: Zero-dependency (Không thư viện thừa), Memory footprint dưới 10MB RAM, Sử dụng kiến trúc hướng sự kiện (Event-driven) của năm 2026.

1. Kiến Trúc Tổng Quan (Architecture Overview)
Hệ thống sẽ chạy dưới dạng một container duy nhất, gắn (mount) trực tiếp vào /var/run/docker.sock. Không sử dụng cơ sở dữ liệu (No-Database) để tiết kiệm tài nguyên tuyệt đối.

                  +-----------------------------------+
                  |        Docker Engine Socket       |
                  +-----------------------------------+
                                    |
            +-----------------------+-----------------------+
            | (Lắng nghe /events)                           | (Gọi API /containers/json)
            v                                               v
+-----------------------+                       +-----------------------+
|  Event Watcher (Go)   |                       |   State Provider (Go) |
+-----------------------+                       +-----------------------+
            |                                               |
            | (Nếu Action = die/stop)                       | (Đẩy dữ liệu qua SSE)
            v                                               v
+-----------------------+                       +-----------------------+
| Telegram Notifier API |                       |  Web UI (HTML/SSE)    |
+-----------------------+                       +-----------------------+
            |                                               |
            v (Internet)                                    v (Trình duyệt)
     [Telegram Bot]                                   [Giao diện của bạn]
2. Thiết Kế Các Thành Phần (Component Components)
2.1. Backend Engine (Viết bằng Go 1.26+)
Lý do chọn Go: Quản lý bộ nhớ cực tốt nhờ cơ chế thu gom rác (GC) hiện đại, hỗ trợ Goroutine xử lý bất đồng bộ mà không tốn CPU.

Backend chia làm 2 luồng xử lý chính:

Luồng Dashboard (SSE Server):

Mở một endpoint /api/stream. Trình duyệt của bạn sẽ kết nối vào đây một lần duy nhất qua giao thức Server-Sent Events (SSE).

Cứ mỗi 5 giây (hoặc khi có sự kiện thay đổi), Go sẽ quét nhanh danh sách container và "bắn" chuỗi JSON về trình duyệt. Bạn không cần viết WebSocket phức tạp, SSE chỉ chạy trên HTTP/1 thuần túy, cực kỳ nhẹ.

Luồng Watchdog (Telegram Alerter):

Duy trì một kết nối liên tục (Long-polling nội bộ) đọc từ cli.Events().

Bộ lọc sự kiện (Event Filter): Chỉ quan tâm tới Type == "container" và các Action nằm trong danh sách đen: die, oom-killed, health_status: unhealthy.

Khi kích hoạt, hàm gửi Telegram sẽ chạy ngầm bằng từ khóa go sendTelegram(...) để không làm nghẽn luồng đọc sự kiện.

2.2. Frontend Dashboard (Zero-Build HTML)
Để đạt dung lượng 0KB trên ổ cứng VPS cho frontend, chúng ta sẽ nhúng trực tiếp file HTML vào trong file binary của Go bằng tính năng //go:embed.

UI Framework: Tailwind CSS (nhúng qua CDN link để VPS không phải lưu font/css).

Reactivity: Sử dụng thư viện siêu nhỏ Alpine.js (hoặc viết bằng Javascript thuần) để hứng luồng SSE từ Go và cập nhật vào bảng giao diện.

Giao diện gồm:

1 thẻ tổng số lượng container (Đang chạy / Đã dừng).

1 bảng danh sách đơn giản gồm: Tên Container, Image, Trạng thái (Uptime/Exit code), Lượng RAM tiêu thụ.

2.3. Điều Khiển & Xem Logs Container (Container Control & Logs API)
Để tăng tính tương tác, DockerWhiz cung cấp các API endpoint giúp thực hiện các hành động trực tiếp lên container và đọc nhật ký hoạt động:
- `POST /api/containers/{id}/start`: Khởi động một container đang dừng.
- `POST /api/containers/{id}/stop`: Dừng một container đang chạy (sử dụng thời gian chờ tắt máy mặc định là 10 giây).
- `POST /api/containers/{id}/restart`: Khởi động lại một container.
- `GET /api/containers/{id}/logs`: Lấy 100 dòng nhật ký mới nhất của container.

2.4. Cấu Hình & Kiểm Thử Telegram (Telegram Configuration & Test API)
Nhằm tùy biến cảnh báo linh hoạt ngay trên giao diện mà không cần thiết lập lại biến môi trường hoặc chạy lại container, DockerWhiz cung cấp các API:
- `GET /api/settings/get`: Lấy thông tin cấu hình Telegram hiện tại đang hoạt động trên hệ thống.
- `POST /api/settings`: Cập nhật cấu hình Telegram mới (Bot Token & Chat ID) và lưu trữ lâu dài vào tệp `config.json`.
- `POST /api/settings/test`: Gửi một tin nhắn kiểm tra tức thời đến Telegram Bot để xác thực cấu hình của người dùng trước khi lưu chính thức.

**Cơ chế hoạt động:**
- **Lệnh điều khiển (Start/Stop/Restart):** Các yêu cầu này sau khi đi qua lớp kiểm tra Session Cookie (Authentication) sẽ được chuyển tiếp (forward) trực tiếp dưới dạng HTTP POST tương ứng tới Docker Daemon thông qua UNIX Socket (ví dụ: `POST /containers/{id}/start`). Sau khi thực hiện thành công, Go sẽ phát tín hiệu SSE tức thời để đồng bộ trạng thái giao diện.
- **Lấy Logs:** Khi lấy logs từ UNIX Socket, Docker Engine trả về dữ liệu dưới định dạng phân luồng ghép kênh (multiplexed stream) gồm tiêu đề 8-byte (chỉ thị kênh stdout/stderr và độ dài frame) tiếp nối bởi frame dữ liệu. Backend Go sẽ tự động đọc phân luồng (demux) các gói tin này để trích xuất nội dung văn bản gốc (plain text) sạch sẽ và trả về dưới dạng JSON `{"success": true, "logs": "..."}` cho giao diện.


3. Sơ Đồ Cấu Trúc Thư Mục Dự Án (Folder Tree)
Một dự án tối giản nên cấu trúc cũng gọn gàng nhất có thể:

Plaintext
DockerWhiz/
├── main.go             # Toàn bộ logic Backend (Kết nối Docker, SSE, Telegram)
├── index.html          # Giao diện Frontend duy nhất
├── go.mod              # Khai báo module Go
├── go.sum              # Checksum các gói phụ thuộc (chỉ dùng duy nhất SDK Docker)
└── Dockerfile          # Đóng gói tối ưu hóa bằng hình thức Multi-stage & Scratch
4. Định Dạng Thông Báo Telegram (Payload Design)
Để khi nhìn vào điện thoại bạn biết ngay vấn đề ở đâu mà không cần mở máy tính, tin nhắn Telegram sẽ được định dạng bằng Markdown dạng Rich Text trực quan:

Plaintext
🚨 [DockerWhiz] CẢNH BÁO CONTAINER SẬP
------------------------------------
📦 Container: web-api-production
🖼️ Image: node:20-alpine
🕒 Thời gian: 2026-07-04 16:41:00
❌ Lỗi (Exit Code): 137 (OOM Killed - Hết bộ nhớ VPS)
------------------------------------
🛠️ Hành động đề xuất: Hãy SSH vào và kiểm tra dung lượng RAM bằng lệnh 'free -m'.
5. Bộ Quét Tài Nguyên Hệ Thống (Resource Monitor)
Để cảnh báo sớm trước khi VPS bị sập hoàn toàn, DockerWhiz sẽ tích hợp một bộ quét tài nguyên hệ thống định kỳ.

Cơ chế hoạt động:
- Backend Go chạy một `time.Ticker` chu kỳ 60 giây.
- Thu thập CPU (qua `/proc/stat`), RAM (qua `/proc/meminfo`), và Disk (qua API hệ thống `syscall.Statfs`).
- Chống spam: Dùng các cờ khóa (lock state) để chỉ cảnh báo một lần khi vượt ngưỡng. Tự động gửi thông báo "Hạ nhiệt" và mở khóa khi tài nguyên trở lại mức an toàn.

Ngưỡng cảnh báo (Thresholds):
- CPU: > 90% liên tục trong 2 lần quét.
- RAM: Dung lượng trống (Available) < 10%.
- Disk: Dung lượng đã dùng > 85%.

Định dạng tin nhắn Telegram cảnh báo tài nguyên:
```
⚠️ [DockerWhiz] CẢNH BÁO TÀI NGUYÊN VPS
------------------------------------
🚨 Loại cảnh báo: HẾT BỘ NHỚ RAM
📊 Trạng thái hiện tại: 92.4% đã dùng
📈 RAM trống còn lại: ~760 MB

ℹ️ Container ngốn nhiều RAM nhất hiện tại: mysql-db (450MB)
------------------------------------
🛠️ Hãy kiểm tra lại các tiến trình hoặc cân nhắc nâng cấp gói VPS.
```

6. Cơ Chế Bảo Mật & Xác Thực (Authentication & Security)
Để tránh lộ thông tin hệ thống ra bên ngoài, DockerWhiz sử dụng cơ chế xác thực gọn nhẹ dựa trên Session Cookie:
- **Khởi tạo lần đầu (Setup Mode)**: Khi chưa có mật khẩu nào được thiết lập, hệ thống sẽ yêu cầu người dùng nhập mật khẩu quản trị mới. Mật khẩu này cùng với một chuỗi muối ngẫu nhiên (Salt) sẽ được băm bằng SHA-256 và lưu trữ vào file `config.json` của DockerWhiz.
- **Cấu hình hệ thống**: Ngoài mật khẩu, tệp `config.json` cũng được mở rộng để lưu trữ mã **Telegram Bot Token** và **Telegram Chat ID** khi người dùng thay đổi cấu hình từ bảng quản trị.
- **Đăng nhập (Login)**: Khi truy cập, nếu chưa có Session Cookie hợp lệ, Frontend sẽ hiển thị màn hình đăng nhập. Khi đăng nhập thành công, Backend sẽ cấp một Session ID ngẫu nhiên lưu trong bộ nhớ RAM và trả về Session Cookie (`DockerWhiz_session`).
- **Bảo vệ API**: Tất cả các API bao gồm endpoint SSE `/api/stream` đều được bảo vệ bởi lớp middleware kiểm tra Cookie. Nếu Cookie không hợp lệ, hệ thống trả về lỗi 401 Unauthorized.

7. Kế Hoạch Triển Khai (Milestones)
Chúng ta sẽ đi qua 3 bước cuốn chiếu để bạn hoàn toàn làm chủ code:

Bước 1: Viết file main.go cơ bản để lấy được danh sách Docker và in ra màn hình Terminal.

Bước 2: Thêm luồng lắng nghe sự kiện die và kết nối với Telegram API. (Lúc này bạn có thể thử tắt một container để xem Telegram bắn tin nhắn về).

Bước 3: Viết file index.html, tạo API SSE và đóng gói bằng Dockerfile scratch để đưa lên VPS chạy thực tế.