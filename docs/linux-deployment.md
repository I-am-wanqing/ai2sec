# AI2Sec Ops Console Linux 部署文档

本文档用于部署 AI2Sec 安全 MVP。它包含 React 前端、FastAPI 后端、SQLite 存储、LangGraph 编排入口、Jinja2 报告渲染和受控 Sandbox 工具门面。

## 1. 服务器要求

推荐配置：

- Ubuntu 22.04 LTS / Debian 12 / CentOS Stream 9
- CPU 2 核以上
- 内存 2 GB 以上
- 磁盘 10 GB 以上
- 已开放 80 / 443 端口

软件版本：

- Node.js 22 LTS
- npm 10+
- Python 3.10+，推荐 Python 3.12
- Docker 24+
- Nginx 1.24+，如果不使用 Docker 部署

## 2. 前端运行参数

默认开发邀请码：

```text
demo-invite-code
```

生产环境请通过环境变量覆盖：

```bash
export AI2SEC_INVITE_CODE='change-me'
export AI2SEC_DATABASE_URL='sqlite:////opt/ai2sec/backend/data/ai2sec.db'
```

后端认证接口：

```http
POST /api/auth/invite
Content-Type: application/json

{
  "inviteCode": "xxxx"
}
```

推荐返回：

```json
{
  "valid": true,
  "token": "jwt-or-session-token",
  "expiresAt": "2026-09-04T00:00:00Z"
}
```

正式上线时建议使用 `httpOnly`、`Secure`、`SameSite=Strict` Cookie 保存会话。

## 3. 普通 Linux 部署

安装 Node.js：

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs nginx python3-venv python3-pip
```

拉取代码后安装依赖：

注：npm config set registry https://registry.npmmirror.com

```bash
cd /opt/ai2sec
npm ci
python3 -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements.txt
npm run build
```

创建后端 systemd 服务：

```ini
[Unit]
Description=AI2Sec Backend
After=network.target

[Service]
WorkingDirectory=/opt/ai2sec
Environment=AI2SEC_INVITE_CODE=change-me
Environment=AI2SEC_DATABASE_URL=sqlite:////opt/ai2sec/backend/data/ai2sec.db
ExecStart=/opt/ai2sec/.venv/bin/uvicorn ai2sec_backend.main:app --app-dir backend --host 127.0.0.1 --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

保存为 `/etc/systemd/system/ai2sec-backend.service` 后启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ai2sec-backend
```

复制前端静态文件：

```bash
sudo mkdir -p /var/www/ai2sec
sudo rsync -a --delete dist/ /var/www/ai2sec/
```

Nginx 配置示例：

```nginx
server {
  listen 80;
  server_name ai2sec.example.com;

  root /var/www/ai2sec;
  index index.html;

  gzip on;
  gzip_types text/plain text/css application/json application/javascript image/svg+xml;

  add_header X-Frame-Options "DENY" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;

  location / {
    try_files $uri $uri/ /index.html;
  }

  location /api/ {
    proxy_pass http://127.0.0.1:8000/api/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

启用站点：

```bash
sudo nginx -t
sudo systemctl reload nginx
```

## 4. Docker Compose 部署

推荐使用仓库内 `docker-compose.yml` 同时启动前后端：

```bash
docker compose up --build -d
```

访问：

```text
http://服务器IP:8080
```

后端健康检查：

```bash
curl http://127.0.0.1:8000/api/health
```

## 5. 单独 Docker 部署

构建前端镜像：

```bash
docker build -t ai2sec-ops-console:0.1.0 .
```

构建后端镜像：

```bash
docker build -f backend/Dockerfile -t ai2sec-backend:0.1.0 .
```

启动后端容器：

```bash
docker run -d \
  --name ai2sec-backend \
  --restart unless-stopped \
  -e AI2SEC_INVITE_CODE=change-me \
  -p 8000:8000 \
  ai2sec-backend:0.1.0
```

启动前端容器：

```bash
docker run -d \
  --name ai2sec-ops-console \
  --restart unless-stopped \
  -p 8080:80 \
  ai2sec-ops-console:0.1.0
```

## 6. HTTPS 配置

使用 Certbot：

```bash
sudo apt-get install -y certbot python3-certbot-nginx
sudo certbot --nginx -d ai2sec.example.com
```

建议确认自动续期：

```bash
sudo systemctl status certbot.timer
```

## 7. 后端 API

黑盒任务：

```http
POST /api/scans/blackbox
```

请求体：

```json
{
  "targetUrl": "https://example.com",
  "profile": "standard",
  "scope": {
    "includeSubdomains": true,
    "respectRobots": true,
    "rateLimit": true,
    "authenticatedScan": false
  },
  "modules": [
    "asset-discovery",
    "port-scan",
    "service-fingerprint",
    "web-crawl",
    "api-discovery",
    "parameter-discovery",
    "vuln-testing",
    "poc-validation"
  ]
}
```

白盒任务：

```http
POST /api/scans/whitebox
Content-Type: multipart/form-data
```

字段：

```text
projectName
language
auditProfile
vulnerabilityClasses[]
archive
```

报告列表：

```http
GET /api/reports
GET /api/reports/{reportId}
```

报告导出：

```http
GET /api/reports/{reportId}/export.pdf
GET /api/reports/{reportId}/export.json
GET /api/reports/{reportId}/export.md
```

## 8. 安全建议

- 邀请码在后端校验，前端只负责提交。
- 白盒压缩包必须在后端做文件类型、大小、解压路径和压缩炸弹防护。
- 黑盒目标必须做授权声明和 scope 限制。
- Docker Sandbox 当前为安全 MVP 门面，仅允许白名单命令；真实扫描工具接入前应单独隔离权限、网络和文件系统。
- 报告证据目录应不可变存储，避免后续覆盖验证材料。
- API 需要审计日志，至少记录用户、目标、时间、任务配置和导出行为。

## 9. 运维检查

检查容器：

```bash
docker ps
docker logs --tail=100 ai2sec-ops-console
```

检查 Nginx：

```bash
sudo nginx -t
sudo journalctl -u nginx -n 100 --no-pager
```

检查静态资源：

```bash
curl -I http://127.0.0.1:8080
```

预期返回 `200 OK`。
