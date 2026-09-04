# AI2Sec Ops Console Linux 部署文档

本文档用于部署当前前端原型。它是纯前端静态应用，生产环境推荐使用 Docker + Nginx；如需接入真实后端，只需要把 API 网关反向代理补到 Nginx 或负载均衡层。

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
- Docker 24+
- Nginx 1.24+，如果不使用 Docker 部署

## 2. 前端运行参数

当前版本的邀请码在前端 mock：

```text
demo-invite-code
```

生产环境不要继续使用前端硬编码邀请码。建议后端提供：

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

## 3. 普通 Linux 静态部署

安装 Node.js：

```bash
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs nginx
```

拉取代码后构建：

```bash
cd /opt/ai2sec
npm ci
npm run build
```

复制静态文件：

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

## 4. Docker 部署

构建镜像：

```bash
docker build -t ai2sec-ops-console:0.1.0 .
```

启动容器：

```bash
docker run -d \
  --name ai2sec-ops-console \
  --restart unless-stopped \
  -p 8080:80 \
  ai2sec-ops-console:0.1.0
```

访问：

```text
http://服务器IP:8080
```

更新版本：

```bash
docker build -t ai2sec-ops-console:0.1.1 .
docker stop ai2sec-ops-console
docker rm ai2sec-ops-console
docker run -d \
  --name ai2sec-ops-console \
  --restart unless-stopped \
  -p 8080:80 \
  ai2sec-ops-console:0.1.1
```

## 5. HTTPS 配置

使用 Certbot：

```bash
sudo apt-get install -y certbot python3-certbot-nginx
sudo certbot --nginx -d ai2sec.example.com
```

建议确认自动续期：

```bash
sudo systemctl status certbot.timer
```

## 6. 推荐后端 API 对接点

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
```

## 7. 安全建议

- 邀请码只能在后端校验，前端只负责提交。
- 白盒压缩包必须在后端做文件类型、大小、解压路径和压缩炸弹防护。
- 黑盒目标必须做授权声明和 scope 限制。
- Docker Sandbox 不应与前端容器共用权限、网络或文件系统。
- 报告证据目录应不可变存储，避免后续覆盖验证材料。
- API 需要审计日志，至少记录用户、目标、时间、任务配置和导出行为。

## 8. 运维检查

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
