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

## 2.5 LLM / API Key 配置（白盒审计与黑盒渗透的 LLM 流水线）

白盒审计（code-audit skill）和黑盒渗透（dsh pentest-web SOP）的 LLM 编排层需要一个 OpenAI 兼容 API，默认按 DeepSeek 配置。

在项目根目录（后端进程的工作目录）创建 `.env`：

```bash
AI2SEC_OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxx
AI2SEC_OPENAI_BASE_URL=https://api.deepseek.com
AI2SEC_OPENAI_MODEL=deepseek-chat
```

要点：

- `.env` 已在 `.gitignore` 与 `.dockerignore` 中，密钥不会进仓库或镜像。
- 也支持任何 OpenAI 兼容服务（如 vLLM 自建端点），改 `AI2SEC_OPENAI_BASE_URL` 和 `AI2SEC_OPENAI_MODEL` 即可；注意 DeepSeek 的 base URL 不带 `/v1` 后缀。
- **密钥未配置时流水线不会失败**：两条流水线自动回退到确定性引擎（白盒为 D1-D10 规则扫描，黑盒为 dsh core 侦察 + 安全探测），报告的 `engine` 字段区分 `code-audit-skill-llm` / `deterministic-rules`、`dsh-skill-llm` / `dsh-deterministic`。
- 如需彻底关闭 LLM 调用：`AI2SEC_LLM_AUDIT_ENABLED=false`、`AI2SEC_LLM_PENTEST_ENABLED=false`。

其他 LLM 相关参数（一般无需调整）：

```bash
AI2SEC_LLM_MAX_BATCHES=12       # 白盒源码分批上限
AI2SEC_LLM_BATCH_CHARS=48000    # 每批源码字符数
AI2SEC_PENTEST_MAX_ENDPOINTS=200  # 黑盒端点分析上限
```

Skill 语料依赖：仓库内 `code-audit-main/` 与 `dsh-pentest-skills-main/` 是流水线的方法论文档与工具引擎，可通过 `AI2SEC_SKILL_DIR`、`AI2SEC_PENTEST_DIR` 覆盖路径；Docker 镜像构建时已自动拷贝这两个目录。

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
# LLM 配置建议用 EnvironmentFile 而非明文写在这里：
EnvironmentFile=/opt/ai2sec/.env
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
# 密钥从项目根 .env 自动读取（AI2SEC_OPENAI_*）
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

构建后端镜像（已包含 code-audit-main 与 dsh-pentest-skills-main skill 语料）：

```bash
docker build -f backend/Dockerfile -t ai2sec-backend:0.1.0 .
```

启动后端容器：

```bash
docker run -d \
  --name ai2sec-backend \
  --restart unless-stopped \
  -e AI2SEC_INVITE_CODE=change-me \
  -e AI2SEC_OPENAI_API_KEY=sk-xxxx \
  -e AI2SEC_OPENAI_BASE_URL=https://api.deepseek.com \
  -e AI2SEC_OPENAI_MODEL=deepseek-chat \
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

黑盒任务（profile 支持 quick / standard / deep；quick 仅确定性侦察，standard / deep 走 LLM SOP，均限定安全探测层）：

```http
POST /api/scans/blackbox
```

请求体：

```json
{
  "targetUrl": "https://example.com",
  "profile": "deep",
  "scope": {
    "includeSubdomains": true,
    "respectRobots": true,
    "rateLimit": true,
    "authenticatedScan": false
  },
  "modules": []
}
```

白盒任务（auditProfile 支持 quick / standard / deep，映射 code-audit skill 的三种审计模式）：

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
