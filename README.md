# AI2Sec Ops Console

多 Agent 渗透测试工具的安全 MVP。当前包含 React 前端、FastAPI 后端、SQLite 存储、LangGraph 编排入口、Jinja2 报告渲染和受控 Sandbox 工具门面。

## 功能

- 邀请码门禁，默认开发邀请码为 `demo-invite-code`
- Dashboard 多 Agent 执行链与 Docker Sandbox 状态
- 黑盒测试任务表单，接受目标 URL
- 白盒审计任务表单，接受 `.zip` / `.tar.gz` / `.tgz` 源码压缩包
- 报告列表、漏洞详情和 Markdown/JSON 导出
- Sandbox 工具能力页和接入设置页
- 后端安全默认值：拒绝内网目标、metadata IP、localhost、危险压缩包路径和非白名单 Sandbox 命令

## 本地运行

```bash
npm install
python3 -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements-dev.txt
npm run backend
```

另开一个终端运行前端：

```bash
npm run dev
```

打开 Vite 输出的本地地址，输入邀请码 `demo-invite-code` 进入控制台。

## 测试

```bash
. .venv/bin/activate
pytest
```

## 构建

```bash
npm run build
npm run preview
```

## Docker Compose

```bash
docker compose up --build
```

前端访问 `http://localhost:8080`，后端 API 访问 `http://localhost:8000/api/health`。

Linux 生产部署见 [docs/linux-deployment.md](/Users/wanqingliu/Documents/ChatGPT/ai2sec/docs/linux-deployment.md)。
