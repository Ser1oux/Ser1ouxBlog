# Ser1oux-Blog

开箱即用的个人博客系统：**Go 单二进制、数据全文件化、不依赖数据库**。

- ✅ 一个可执行文件搞定一切，备份只需要打包一个 `data/` 文件夹
- ✅ 首次启动自带初始化向导，两步就能上线，默认内容完全中性
- ✅ Markdown 写作、评论楼中楼、留言板、站内通知、访问统计、暗色模式、RSS
- ✅ 内置安全加固：全接口限流、XSS 双层防护、会话与 Cookie 加固、上传白名单

基于 GL-Blog 二次开发。下面是从本地体验到生产部署的完整说明。

## 目录

- [1. 环境要求](#1-环境要求)
- [2. 本地体验（3 分钟）](#2-本地体验3-分钟)
- [3. 初始化向导](#3-初始化向导)
- [4. 部署到服务器](#4-部署到服务器)
  - [方式 A：Docker Compose（推荐）](#方式-a-docker-compose推荐)
  - [方式 B：二进制 + systemd + Nginx](#方式-b-二进制--systemd--nginx)
- [5. 配置 HTTPS](#5-配置-https)
- [6. 部署后怎么用](#6-部署后怎么用)
- [7. 更新升级](#7-更新升级)
- [8. 数据与备份](#8-数据与备份)
- [9. 常见问题](#9-常见问题)
- [10. 自定义默认外观](#10-自定义默认外观)
- [11. 二次开发](#11-二次开发)
- [12. 许可](#12-许可)

## 1. 环境要求

| 场景 | 要求 |
|------|------|
| 本地体验 / 二次开发 | [Go](https://go.dev/dl/) 1.21+ |
| Docker 部署 | Docker 和 Docker Compose（无需装 Go） |
| 服务器二进制部署 | 任意 Linux（amd64 / arm64），无需任何运行时依赖 |

## 2. 本地体验（3 分钟）

```bash
git clone https://github.com/Ser1oux/Ser1ouxBlog.git
cd Ser1ouxBlog
go run .
```

浏览器打开 **http://localhost:3000**，会自动进入初始化向导，见下一节。

> 局域网其他设备访问有问题时（如手机连电脑测试），设置环境变量 `COOKIE_SECURE=false` 再启动。

## 3. 初始化向导

首次访问任何页面都会跳转到 `/setup`，两步完成：

1. **设置站点名称** —— 显示在浏览器标题和页头，之后可随时在后台修改
2. **创建管理员账号** —— 用户名 / 邮箱 / 密码，用于登录管理后台

完成后自动登录并进入站点。系统会生成一篇《欢迎使用 Ser1oux-Blog》示例文章（可直接删除），数据全部保存在 `data/` 目录。

## 4. 部署到服务器

### 方式 A：Docker Compose（推荐）

最省事的方式，适合已安装 Docker 的服务器：

```bash
git clone https://github.com/Ser1oux/Ser1ouxBlog.git
cd Ser1ouxBlog
docker compose up -d --build
```

完成后访问 `http://服务器IP:3000` 进入初始化向导。

这条命令做了什么：构建镜像并启动容器、把 `3000` 端口映射到宿主机、数据持久化在 `./data`（容器重建不丢数据）、崩溃自动重启（`unless-stopped`）。

**生产建议**：在 `docker-compose.yml` 的 `environment` 中加一行固定会话密钥（否则每次重建容器所有登录态失效）：

```yaml
    environment:
      - TZ=Asia/Shanghai
      - SESSION_SECRET=换成你自己的64位随机字符串
```

### 方式 B：二进制 + systemd + Nginx

适合传统 VPS / 虚拟主机，资源占用最低。

**第 1 步：编译 Linux 二进制**（在任意装有 Go 的机器上执行）

```bash
# Intel/AMD 服务器
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o gl-blog .

# ARM 服务器（如部分国产云主机、树莓派）
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o gl-blog .
```

**第 2 步：上传到服务器**，目录结构如下（`start.sh` 在仓库 `deploy/` 目录，会自动识别 amd64 / arm64）：

```
/www/wwwroot/gl-blog/
├── gl-blog       # 二进制（ARM 服务器命名為 gl-blog-arm64），chmod +x
├── BG/           # 默认壁纸与图标（仓库内自带，一起上传）
├── start.sh      # 启动脚本（从仓库 deploy/ 目录复制）
├── secret.env    # 下一步生成
└── data/         # 运行后自动生成，全部数据在此
```

**第 3 步：生成会话密钥**（重要，防止重启后所有用户被登出）

```bash
cd /www/wwwroot/gl-blog
echo "SESSION_SECRET=$(openssl rand -hex 32)" > secret.env
chmod 600 secret.env
```

**第 4 步：配置 systemd 守护**（崩溃自动拉起 + 开机自启）

```ini
# /etc/systemd/system/gl-blog.service
[Unit]
Description=Ser1oux-Blog
After=network.target

[Service]
Type=simple
WorkingDirectory=/www/wwwroot/gl-blog
ExecStart=/bin/bash /www/wwwroot/gl-blog/start.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now gl-blog
systemctl status gl-blog     # 确认运行中
```

**第 5 步：Nginx 反向代理**（在站点的 server 块中添加）

```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;        # 限流和 IP 归属地依赖真实 IP
    proxy_set_header X-Forwarded-Proto $scheme;     # HTTPS 识别依赖
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

```bash
nginx -t && nginx -s reload
```

访问你的域名，进入初始化向导即可。

## 5. 配置 HTTPS

推荐用 Let's Encrypt 免费证书（以 Certbot 为例）：

```bash
apt install certbot python3-certbot-nginx    # Debian/Ubuntu
certbot --nginx -d 你的域名
```

Certbot 会自动改写 Nginx 配置并续期。程序侧无需改任何配置（默认按 HTTPS 生成安全 Cookie）。

## 6. 部署后怎么用

管理后台入口：**`/admin`**（用初始化时创建的账号登录）。

| 你想做的事 | 去哪里 |
|-----------|--------|
| 写文章、管理分类标签封面 | 后台 → 文章管理（`/admin/posts`），Markdown 编辑，留空 slug 自动生成，长文自动生成目录 |
| 改站点名称 / 公告 / 壁纸 / 头像 | 后台 → 设置（`/admin/settings`） |
| 填写关于页 | 后台 → 设置 → 关于页 |
| 添加社交链接（GitHub / B站 / 邮箱等） | 后台 → 设置 → 社交链接 |
| 配置邮件通知（评论提醒、找回密码依赖此功能） | 后台 → 设置 → SMTP |
| 管理图片等上传附件 | 后台 → 附件管理（`/admin/files`） |
| 查看留言、回复评论 | 前台留言板 `/guestbook`，文章页评论区（支持楼中楼） |
| 查看访问统计 | 首页侧栏（按日统计 + 近 30 天柱状图） |

## 7. 更新升级

核心原则：**只替换程序，绝不动 `data/`**。

```bash
# 二进制部署
git pull && go build -o gl-blog .    # 本地编译后上传服务器替换
systemctl restart gl-blog

# Docker 部署
git pull && docker compose up -d --build
```

## 8. 数据与备份

- 全部数据（文章、评论、用户、站点配置、上传的图片）都在 `data/` 目录
- **备份 = 打包这个目录**：`tar -czf blog-backup-$(date +%F).tar.gz data/`
- 恢复 = 解压回原位并重启服务
- ⚠️ 不要把 `data/` 提交到 git（已在 `.gitignore` 中），更新程序时不要删除它

## 9. 常见问题

**Q：启动后访问一直跳到 /setup？**
首次部署的正常现象，完成向导即消失。若已完成过向导仍跳转，说明 `data/` 目录被清空或程序无写入权限，检查目录权限（`chown -R` 给运行用户）。

**Q：端口被占用，想换端口？**
设置环境变量 `PORT=8080` 或启动参数 `-port 8080`；Docker 方式改 compose 里的端口映射 `"8080:3000"`。

**Q：服务器重启后所有人都被登出？**
未固定 `SESSION_SECRET`，见第 4 节第 3 步（或 Docker 段的 environment 配置）。

**Q：HTTPS 下一切正常，但 HTTP 测试时无法登录？**
Cookie 默认带 Secure 标记，纯 HTTP 环境请临时设置 `COOKIE_SECURE=false`（仅限本地调试，生产请用 HTTPS）。

**Q：忘记管理员密码？**
登录页点击「找回密码」，用管理员邮箱接收验证码重置（需要先配置过 SMTP）。未配置过 SMTP 时无法自助找回，需停止服务后编辑 `data/metadata.json` 手动处理，或在数据可舍弃时清空 `data/` 重新初始化。

**Q：评论的 IP 归属地显示不准 / 限流把所有人都限了？**
Nginx 少传了真实 IP 头，确认第 4 节方式 B 第 5 步中的 `X-Real-IP` 和 `X-Forwarded-For` 两行都在。

**Q：Docker 容器健康检查失败？**
`docker compose logs gl-blog` 看日志；常见原因是 `data/` 目录权限不对。

## 10. 自定义默认外观

想改"开箱默认值"（而不是部署后在后台改）：

- 默认壁纸：替换 `BG/BG.jpg`；默认头像：`BG/icon.jpg`；备选壁纸在 `BG/backgrounds/`
- 默认公告、分类、标签、示例文章、关于页文案：在 `main.go` 的初始化逻辑中
- 后台「设置」里修改的任何配置，优先级始终高于代码默认值

## 11. 二次开发

```bash
go run .          # 启动开发服务
go test ./...     # 运行测试
```

单二进制 + 文件存储，无数据库、无外部服务依赖，直接读源码即可上手。

## 12. 许可

MIT。版权归属上游 GL-Blog 作者与本仓库改造者，详见 [LICENSE](./LICENSE)。
