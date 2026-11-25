# 构建阶段
FROM golang:1.27-alpine AS builder

WORKDIR /app

# 复制 go mod 文件
COPY go.mod go.sum ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 构建应用（-trimpath 去掉本机路径，产物可复现）
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o gl-blog .

# 运行阶段
FROM alpine:3.21

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/gl-blog ./gl-blog

# 复制 BG 目录（包含默认背景图片和头像）
COPY --from=builder /app/BG ./BG

# 以非 root 用户运行；data/ 的属主必须是该用户（bind mount 时需在宿主机 chown 10001:10001）
RUN addgroup -S -g 10001 app \
    && adduser -S -u 10001 -G app app \
    && mkdir -p /app/data/posts /app/data/uploads \
    && chown -R app:app /app

USER app

# 暴露端口
EXPOSE 3000

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/ || exit 1

# 运行应用
CMD ["./gl-blog"]
