#!/bin/bash
# Ser1oux-Blog 启动脚本（给 Supervisor 用，失败会写日志）
set -e
cd /www/wwwroot/gl-blog
mkdir -p data logs
export TZ=Asia/Shanghai

# 固定会话密钥：在 /www/wwwroot/gl-blog/secret.env 写入 SESSION_SECRET=<64位随机串>
# 不配置时程序每次重启会随机生成（所有登录态失效），生产环境务必配置
if [ -f secret.env ]; then
  chmod 600 secret.env
  set -a; . ./secret.env; set +a
fi

# 自动选择架构
ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
  BIN="./gl-blog-arm64"
else
  BIN="./gl-blog"
fi

if [ ! -f "$BIN" ]; then
  echo "$(date) ERROR: binary not found: $BIN" >> logs/error.log
  ls -la >> logs/error.log
  exit 1
fi

chmod +x "$BIN" 2>/dev/null || true
echo "$(date) starting $BIN on $(uname -m)" >> logs/run.log
exec "$BIN" >> logs/run.log 2>> logs/error.log
