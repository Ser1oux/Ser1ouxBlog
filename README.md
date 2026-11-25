# Ser1oux-Blog

开箱即用的个人博客系统：**Go 单二进制、数据全文件化、不依赖数据库**。

- ✅ 一个可执行文件搞定一切，备份只需要打包一个 `data/` 文件夹
- ✅ 首次启动自带初始化向导，两步就能上线，默认内容完全中性
- ✅ Markdown 写作、评论楼中楼、留言板、站内通知、访问统计、暗色模式、RSS
- ✅ 安全默认值：初始化一次性口令、关键接口限流、Markdown 强制 HTML 清洗（DOMPurify）、
  CSP 与安全响应头、上传白名单 + 非图片强制下载、会话版本吊销、文件权限 0600

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
| 本地体验 / 二次开发 | [Go](https://go.dev/dl/) 1.22+（Dockerfile 使用 1.27 构建） |
| Docker 部署 | Docker 和 Docker Compose（无需装 Go） |
| 服务器二进制部署 | 任意 Linux（amd64 / arm64），无需任何运行时依赖 |

### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SESSION_SECRET` | 启动时随机生成 | 会话签名密钥。不设置则每次重启所有登录失效，生产必须固定 |
| `COOKIE_SECURE` | `true` | 设为 `false` 才允许纯 HTTP 登录，仅限本地调试 |
| `TRUST_PROXY` | 关闭 | 设为 `1` 才采信 `X-Real-IP` / `X-Forwarded-For`。**放在 Nginx 后面时必须开启**，否则所有请求都会被当成来自 127.0.0.1 |
| `SITE_URL` | 空 | 邮件里的绝对链接前缀，例如 `https://blog.example.com`；不设则按请求 Host 推断 |
| `PORT` | `3000` | 监听端口（也可用 `-port` 参数） |

> 反向代理信任是安全边界：`TRUST_PROXY` 关闭时，伪造 `X-Forwarded-For` 无法绕过限流；
> 开启后请确保只有可信代理能直连应用端口。

## 2. 本地体验（3 分钟）

```bash
git clone https://github.com/Ser1oux/Ser1ouxBlog.git
cd Ser1ouxBlog
go run .
```

浏览器打开 **http://localhost:3000**，会自动进入初始化向导，见下一节。

> 局域网其他设备访问有问题时（如手机连电脑测试），设置环境变量 `COOKIE_SECURE=false` 再启动。

## 3. 初始化向导

首次启动时，服务端日志会打印一行一次性初始化口令：

```
🔐 站点尚未初始化。请访问 /setup 并填入一次性口令: <64 位随机串>
```

首次访问任何页面都会跳转到 `/setup`，三步完成：

1. **填写初始化口令** —— 只有能看到服务端日志的人才能完成初始化，避免公网端口被抢先注册管理员
2. **设置站点名称** —— 显示在浏览器标题和页头，之后可随时在后台修改
3. **创建管理员账号** —— 用户名 / 邮箱 / 密码（至少 8 位），用于登录管理后台

完成后自动登录并进入站点。系统会生成一篇《欢迎使用 Ser1oux-Blog》示例文章（可直接删除），数据全部保存在 `data/` 目录。

> 口令只在本次启动有效；「重置站点」会清空数据并重新打印一个新口令。
> 如果日志找不到口令，重启一次服务即可。

## 4. 部署到服务器

### 方式 A：Docker Compose（推荐）

最省事的方式，适合已安装 Docker 的服务器：

```bash
git clone https://github.com/Ser1oux/Ser1ouxBlog.git
cd Ser1ouxBlog
mkdir -p data && sudo chown -R 10001:10001 data
docker compose up -d --build
```

容器以非 root 用户（uid 10001）运行，`data/` 是 bind mount，必须在宿主机先把属主改成 10001，
否则启动后会因无写入权限反复跳到 `/setup`。

compose 默认只把端口绑定到 `127.0.0.1:3000`，请在前面放 Nginx/Caddy 并启用 HTTPS（见第 5 节）。
需要局域网直连时把映射改成 `"3000:3000"`。

**生产建议**：在 `docker-compose.yml` 的 `environment` 中至少固定会话密钥：

```yaml
    environment:
      - TZ=Asia/Shanghai
      - SESSION_SECRET=换成你自己的64位随机字符串   # openssl rand -hex 32
      - TRUST_PROXY=1                              # 前面有可信 Nginx/Caddy 时
      - SITE_URL=https://blog.example.com          # 邮件里的绝对链接
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

**第 4 步：创建运行用户并配置 systemd**（不要用 root 跑）

```bash
useradd --system --uid 10001 --home /www/wwwroot/gl-blog --shell /usr/sbin/nologin gl-blog
mkdir -p /www/wwwroot/gl-blog/data /www/wwwroot/gl-blog/logs
chown -R gl-blog:gl-blog /www/wwwroot/gl-blog
```

```ini
# /etc/systemd/system/gl-blog.service
[Unit]
Description=Ser1oux-Blog
After=network.target

[Service]
Type=simple
User=gl-blog
Group=gl-blog
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
journalctl -u gl-blog -n 50  # 首次启动会在这里打印初始化口令
```

**第 5 步：Nginx 反向代理**（在站点的 server 块中添加）

```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

```bash
nginx -t && nginx -s reload
```

> 程序默认**不信任**这些转发头（防止伪造 IP 绕过限流）。放在 Nginx 后面时，
> 必须在启动环境里设置 `TRUST_PROXY=1`，否则限流与 IP 归属地都会把所有人当成 127.0.0.1。
> 在 `secret.env` 里加一行 `export TRUST_PROXY=1` 即可（`start.sh` 会自动加载）。
> 同时确保 3000 端口只监听回环地址，外部无法绕过 Nginx 直连。

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
放在反向代理后面却没开 `TRUST_PROXY=1`。确认第 4 节方式 B 第 5 步的转发头都在，并且启动环境里有 `TRUST_PROXY=1`；
直接暴露在公网（无代理）时不要开，保持默认即可。

**Q：访问 /setup 提示“初始化口令无效”？**
口令在服务端日志里（systemd：`journalctl -u gl-blog`；Docker：`docker compose logs gl-blog`），
形如 `🔐 站点尚未初始化…一次性初始化口令: xxxx`。口令只在当前进程有效，重启后会重新生成。

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
go vet ./...      # 静态检查
go test ./...     # 运行测试（含鉴权边界、上传直出、归档路径等）
```

前端第三方库已经固定在 `public/vendor/`（marked / DOMPurify / EasyMDE / highlight.js / GSAP），
页面不再从公网 CDN 加载脚本；升级时替换该目录下的文件即可，不需要改 HTML。

单二进制 + 文件存储，无数据库；除了 Go 标准库与 gorilla/mux、gorilla/sessions、gomarkdown、x/crypto，没有其它运行时依赖。

## 12. 许可

MIT。版权归属上游 GL-Blog 作者与本仓库改造者，详见 [LICENSE](./LICENSE)。
