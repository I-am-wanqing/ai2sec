# AI2Sec Ops Console

多 Agent 渗透测试工具的前端原型。当前实现聚焦 Web 控制台，不包含后端执行能力。

## 功能

- 邀请码门禁，mock 邀请码为 `demo-invite-code`
- Dashboard 多 Agent 执行链与 Docker Sandbox 状态
- 黑盒测试任务表单，接受目标 URL
- 白盒审计任务表单，接受 `.zip` / `.tar.gz` / `.tgz` 源码压缩包
- 报告列表与漏洞详情 mock 页面
- Sandbox 工具能力页和接入设置页

## 本地运行

```bash
npm install
npm run dev
```

打开 Vite 输出的本地地址，输入邀请码 `demo-invite-code` 进入控制台。

## 构建

```bash
npm run build
npm run preview
```

Linux 生产部署见 [docs/linux-deployment.md](/Users/wanqingliu/Documents/ChatGPT/ai2sec/docs/linux-deployment.md)。
