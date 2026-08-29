#!/bin/bash
echo "===== 系统架构 ====="
uname -a
uname -m
echo "===== 目录内容 ====="
ls -la /www/wwwroot/gl-blog/ 2>/dev/null || ls -la
echo "===== 文件类型 ====="
file ./gl-blog 2>/dev/null || echo "gl-blog 不存在"
file ./gl-blog-arm64 2>/dev/null || echo "gl-blog-arm64 不存在"
echo "===== 权限修复后试跑 ====="
chmod +x ./gl-blog ./gl-blog-arm64 ./start.sh 2>/dev/null || true
mkdir -p data logs
ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
  BIN="./gl-blog-arm64"
else
  BIN="./gl-blog"
fi
echo "将使用: $BIN"
echo "===== 前台试跑 3 秒 ====="
timeout 3 $BIN 2>&1 || true
echo "===== 端口 ====="
ss -lntp | grep 3000 || echo "3000 未监听"
echo "===== 结束，请把以上全部复制发给助手 ====="
