# Giai đoạn 1: Biên dịch ứng dụng Go
FROM golang:1.26-alpine AS builder

# Cài đặt chứng chỉ CA để gọi HTTPS tới Telegram
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy các file mã nguồn
COPY go.mod ./
COPY *.go ./
COPY index.html ./

# Biên dịch binary dạng static, loại bỏ thông tin debug để giảm kích thước tối đa
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o DockerWhiz .

# Giai đoạn 2: Tạo image siêu nhẹ từ scratch
FROM scratch

# Copy file chứng chỉ bảo mật CA từ stage builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy file binary đã được biên dịch
COPY --from=builder /app/DockerWhiz /DockerWhiz

# Mở cổng HTTP mặc định
EXPOSE 8082

# Chạy DockerWhiz
ENTRYPOINT ["/DockerWhiz"]
