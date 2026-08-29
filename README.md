# Ser1oux-Blog

开箱即用的个人博客系统：**Go 单二进制、数据全文件化、不依赖数据库**。克隆 → 编译 → 访问 `/setup` 完成两步向导，就能拥有完全属于你自己的博客。

基于 GL-Blog 二次开发，包含大量功能扩展与安全加固。

## 功能特性

**内容**
- Markdown 写作，分类 / 标签 / 封面管理；未配封面自动生成渐变字卡
- 自定义英文 slug（留空按标题生成，自动查重）
- 文章目录（TOC）自动生成，长文左侧悬浮
- 归档页按年份分组，可折叠
- 站内搜索：标题 / 分类 / 标签 / 正文全文检索 + 关键词高亮
- RSS 订阅 `/rss.xml`，robots.txt 与 sitemap.xml 自动生成

**互动**
- 评论楼中楼回复（两级），禁止回复本人评论
- 站内通知 + SMTP 邮件同步
- 全站留言板 `/guestbook`，评论展示 IP 归属地（多源解析）
- 邮箱或用户名登录，用户名全站唯一
- 注册默认字母头像，个人中心可上传更换

**界面**
- 暗色模式：跟随系统深浅色偏好自动切换
- 访问统计：按日计数，首页近 30 天柱状图
- 响应式布局，移动端适配

**安全（相对上游的加固）**
- 会话密钥环境变量化 / 随机生成，Cookie HttpOnly + SameSite + Secure
- 公开配置接口字段白名单，杜绝敏感信息外泄
- 验证码错误上限销毁；登录 / 注册 / 发码 / 找回密码全接口限流
- 评论、昵称、头像等服务端统一清洗，前后端双层 XSS 防护
- 上传类型白名单 + 文件名净化（防路径穿越）；请求体大小上限
- 并发写入加锁 + 原子落盘；安全响应头 / HSTS；目录列表关闭

## 开箱默认

- 首次启动所有页面自动跳转 `/setup` 向导：设置站点名称、创建管理员账号，完成即自动登录
- 默认内容完全中性：不预置任何作者身份信息，仅含一篇《欢迎使用 Ser1oux-Blog》示例文章
- 默认壁纸 / 头像位于 `BG/` 目录，可直接替换成你自己的

## 快速开始

需要 Go 1.21+。

```bash
go run .
```

默认监听 `http://localhost:3000`，首次访问 `/setup` 完成初始化。

### 生产部署（推荐）

**1. 交叉编译 Linux 单二进制**

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o gl-blog .
```

**2. 上传到服务器**，目录结构：

```
/www/wwwroot/gl-blog/
├── gl-blog       # 二进制，chmod +x
├── BG/           # 默认背景与图标（仓库内自带）
├── start.sh      # 启动脚本（仓库 deploy/ 目录）
├── secret.env    # 会话密钥（自建，见下）
└── data/         # 运行后自动生成，全部数据在此
```

**3. 配置会话密钥**（重要）：

```bash
echo "SESSION_SECRET=$(openssl rand -hex 32)" > secret.env
chmod 600 secret.env
```

**4. systemd 守护**（崩溃自动拉起 + 开机自启）：

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
systemctl daemon-reload && systemctl enable --now gl-blog
```

**5. Nginx 反向代理要点**（HTTPS 由证书层处理）：

```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;        # 限流依赖真实 IP
    proxy_set_header X-Forwarded-Proto $scheme;     # HSTS 与 sitemap 依赖
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

### Docker 部署

```bash
docker compose up -d --build
```

数据通过 `./data` 卷持久化。

### 环境变量

| 变量 | 说明 | 默认 |
|------|------|------|
| `SESSION_SECRET` | 会话签名密钥；未配置则每次启动随机生成（重启后所有登录态失效） | 随机 |
| `COOKIE_SECURE` | 本地 HTTP 调试时设 `false` 关闭 Cookie Secure 标记 | `true` |
| `PORT` | 监听端口（命令行 `-port` 同效） | `3000` |

## 自定义默认外观

- 默认壁纸：`BG/BG.jpg`；默认头像：`BG/icon.jpg`；备选壁纸在 `BG/backgrounds/`
- 默认站点公告、分类、标签、关于页文案等在 `main.go` 的初始化逻辑中，可按需修改
- 站长部署后在后台「设置」中修改的配置，优先级始终高于代码默认值

## 数据与备份

- 文章、用户、评论、站点配置均在 `data/`，**请勿提交到 git、勿在更新程序时删除**
- 验证码在 `data/codes.json`，通知在 `data/notifications.json`，按日统计在 `data/stats.json`
- 备份打包整个 `data/` 即可；更新程序只替换二进制，`data/` 原地保留

## 许可

MIT。版权归属上游 GL-Blog 作者与本仓库改造者，详见 [LICENSE](./LICENSE)。
