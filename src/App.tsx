import {
  Activity,
  Archive,
  Box,
  Braces,
  Bug,
  Check,
  ChevronRight,
  CircleDot,
  Code2,
  Cpu,
  Download,
  FileArchive,
  FileJson,
  FileText,
  Fingerprint,
  Globe2,
  HardDriveUpload,
  KeyRound,
  Layers3,
  LayoutDashboard,
  Lock,
  Network,
  Play,
  Radar,
  Route,
  ScanSearch,
  Server,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Sun,
  Moon,
  Terminal,
  UploadCloud,
  Workflow,
  Zap,
  type LucideIcon
} from "lucide-react";
import { ChangeEvent, DragEvent, FormEvent, ReactNode, useEffect, useMemo, useState } from "react";

type View = "dashboard" | "blackbox" | "whitebox" | "reports" | "sandbox" | "settings";
type ScanProfile = "quick" | "standard" | "deep";
type AuditProfile = "quick" | "standard" | "deep";
type Severity = "critical" | "high" | "medium" | "low";
type Finding = {
  id: string;
  title: string;
  severity: Severity;
  source: string;
  verified: boolean;
  component: string;
  description: string;
  recommendation?: string;
  evidence?: Record<string, unknown>;
};
type ReportSummary = {
  id: string;
  scanId: string;
  title: string;
  riskScore: number;
  summary: string;
  createdAt: string;
};
type ReportDetail = ReportSummary & {
  findings: Finding[];
};

const inviteCode = "demo-invite-code";
const tokenKey = "ai2sec.token";
const themeKey = "ai2sec.theme";

type Theme = "light" | "dark";

function useTheme() {
  const [theme, setTheme] = useState<Theme>(
    () => (localStorage.getItem(themeKey) === "dark" ? "dark" : "light")
  );

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem(themeKey, theme);
  }, [theme]);

  function toggleTheme() {
    setTheme((current) => (current === "dark" ? "light" : "dark"));
  }

  return { theme, toggleTheme };
}

function ThemeToggle({ theme, onToggle }: { theme: Theme; onToggle: () => void }) {
  return (
    <button
      type="button"
      className="theme-toggle"
      onClick={onToggle}
      title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
      aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
    >
      {theme === "dark" ? <Sun size={15} /> : <Moon size={15} />}
      {theme === "dark" ? "LIGHT" : "DARK"}
    </button>
  );
}

const agents = [
  { name: "Root Agent", status: "planning", icon: Workflow },
  { name: "Recon Agent", status: "ready", icon: Radar },
  { name: "Discovery Agent", status: "ready", icon: ScanSearch },
  { name: "Validation Agent", status: "isolated", icon: ShieldCheck },
  { name: "Reporting Agent", status: "standby", icon: FileText }
];

const services = [
  { name: "Docker Sandbox", value: "Online", tone: "good", icon: Box },
  { name: "Browser Tool", value: "Ready", tone: "good", icon: Globe2 },
  { name: "Proxy Chain", value: "Idle", tone: "warn", icon: Network },
  { name: "Python Runtime", value: "Ready", tone: "good", icon: Cpu },
  { name: "MCP Bridge", value: "Connected", tone: "good", icon: Braces }
];

const findings: Finding[] = [
  {
    id: "AI2-2026-001",
    title: "SQL Injection in /api/search",
    severity: "high",
    source: "Discovery Agent",
    verified: true,
    component: "GET /api/search?q=",
    description: "参数 q 在拼接查询时缺少参数化处理，Validation Agent 已通过时间盲注行为完成独立验证。"
  },
  {
    id: "AI2-2026-002",
    title: "Reflected XSS in campaign redirect",
    severity: "medium",
    source: "Validation Agent",
    verified: true,
    component: "GET /redirect?next=",
    description: "next 参数进入 HTML 响应上下文前未做输出编码，PoC 可触发受控脚本执行。"
  },
  {
    id: "AI2-2026-003",
    title: "Exposed staging service",
    severity: "low",
    source: "Recon Agent",
    verified: false,
    component: "staging.example.com:8080",
    description: "资产探测阶段发现未认证的 staging 服务，需要后续确认是否属于授权范围。"
  }
];

const terminalLines = [
  "> root-agent initialized with sandbox policy: isolated",
  "> recon-agent loaded modules: dns, ports, http-fingerprint",
  "> discovery-agent queue empty; waiting for target",
  "> validation-agent mode: independent verification",
  "> reporting-agent template: executive + technical"
];

function App() {
  const [authed, setAuthed] = useState(() => Boolean(localStorage.getItem(tokenKey)));
  const [code, setCode] = useState("");
  const [loginError, setLoginError] = useState("");
  const [view, setView] = useState<View>("dashboard");
  const [selectedFinding, setSelectedFinding] = useState(findings[0]);
  const { theme, toggleTheme } = useTheme();

  async function handleLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoginError("");
    try {
      const response = await fetch("/api/auth/invite", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ inviteCode: code.trim() })
      });
      if (!response.ok) {
        throw new Error("ACCESS DENIED: invalid invite code");
      }
      const payload = (await response.json()) as { token: string };
      localStorage.setItem(tokenKey, payload.token);
      localStorage.setItem("ai2sec.invite", code.trim());
      setAuthed(true);
      return;
    } catch (error) {
      if (code.trim() === inviteCode) {
        setLoginError("Backend unavailable. Start backend on :8000 to verify invite.");
      } else {
        setLoginError(error instanceof Error ? error.message : "ACCESS DENIED");
      }
    }
  }

  if (!authed) {
    return (
      <LoginScreen
        code={code}
        error={loginError}
        onCode={setCode}
        onLogin={handleLogin}
        theme={theme}
        onToggleTheme={toggleTheme}
      />
    );
  }

  return (
    <div className="shell">
      <Sidebar view={view} onView={setView} />
      <main className="workspace">
        <TopBar theme={theme} onToggleTheme={toggleTheme} />
        {view === "dashboard" && <Dashboard onView={setView} onFinding={setSelectedFinding} />}
        {view === "blackbox" && <BlackboxPage />}
        {view === "whitebox" && <WhiteboxPage />}
        {view === "reports" && (
          <ReportsPage selected={selectedFinding} onSelect={setSelectedFinding} />
        )}
        {view === "sandbox" && <SandboxPage />}
        {view === "settings" && <SettingsPage />}
      </main>
    </div>
  );
}

function LoginScreen({
  code,
  error,
  onCode,
  onLogin,
  theme,
  onToggleTheme
}: {
  code: string;
  error: string;
  onCode: (value: string) => void;
  onLogin: (event: FormEvent<HTMLFormElement>) => void | Promise<void>;
  theme: Theme;
  onToggleTheme: () => void;
}) {
  return (
    <main className="login-screen">
      <div className="scanline" />
      <div className="login-theme-toggle">
        <ThemeToggle theme={theme} onToggle={onToggleTheme} />
      </div>
      <section className="login-panel">
        <div className="brand-mark">
          <ShieldAlert size={42} />
          <span>AI2SEC</span>
        </div>
        <h1>OPS CONSOLE</h1>
        <p>Restricted multi-agent security workspace</p>
        <form onSubmit={onLogin} className="login-form">
          <label htmlFor="invite">INVITE CODE</label>
          <div className="input-with-icon">
            <KeyRound size={18} />
            <input
              id="invite"
              type="password"
              value={code}
              onChange={(event) => onCode(event.target.value)}
              placeholder="demo-invite-code"
              autoComplete="one-time-code"
            />
          </div>
          {error && <div className="pixel-error">{error}</div>}
          <button className="pixel-button primary" type="submit" disabled={!code.trim()}>
            <Lock size={16} />
            ENTER CONSOLE
          </button>
        </form>
        <div className="login-foot">UNAUTHORIZED ACCESS WILL BE LOGGED</div>
      </section>
    </main>
  );
}

function Sidebar({ view, onView }: { view: View; onView: (view: View) => void }) {
  const items: Array<{ id: View; label: string; icon: LucideIcon }> = [
    { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
    { id: "blackbox", label: "Blackbox Scan", icon: Globe2 },
    { id: "whitebox", label: "Whitebox Audit", icon: Code2 },
    { id: "reports", label: "Reports", icon: FileText },
    { id: "sandbox", label: "Sandbox", icon: Terminal },
    { id: "settings", label: "Settings", icon: Settings }
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <ShieldCheck size={28} />
        <div>
          <strong>AI2Sec</strong>
          <span>Agent Ops</span>
        </div>
      </div>
      <nav>
        {items.map((item) => (
          <button
            key={item.id}
            className={view === item.id ? "nav-item active" : "nav-item"}
            onClick={() => onView(item.id)}
          >
            <item.icon size={17} />
            {item.label}
          </button>
        ))}
      </nav>
      <div className="sidebar-footer">
        <StatusLight tone="good" />
        Invite verified
      </div>
    </aside>
  );
}

function TopBar({ theme, onToggleTheme }: { theme: Theme; onToggleTheme: () => void }) {
  return (
    <header className="topbar">
      <div>
        <span className="eyebrow">MULTI-AGENT PENTEST FRONTEND</span>
        <h2>AI2Sec Ops Console</h2>
      </div>
      <div className="topbar-status">
        <StatusPill label="Invite" value="Verified" tone="good" />
        <StatusPill label="Sandbox" value="Online" tone="good" />
        <StatusPill label="MCP" value="Connected" tone="good" />
        <ThemeToggle theme={theme} onToggle={onToggleTheme} />
      </div>
    </header>
  );
}

function Dashboard({
  onView,
  onFinding
}: {
  onView: (view: View) => void;
  onFinding: (finding: Finding) => void;
}) {
  return (
    <div className="page dashboard-grid">
      <section className="panel hero-console">
        <div>
          <span className="eyebrow">ROOT AGENT COMMAND SURFACE</span>
          <h1>Plan, execute, verify, report.</h1>
          <p>
            面向黑盒渗透测试和白盒源码审计的多 Agent 前端工作台。当前版本使用 mock 数据，
            后续可直接接入 LangGraph 节点、MCP 工具和 Docker Sandbox。
          </p>
        </div>
        <div className="action-row">
          <button className="pixel-button primary" onClick={() => onView("blackbox")}>
            <Globe2 size={16} />
            NEW BLACKBOX SCAN
          </button>
          <button className="pixel-button" onClick={() => onView("whitebox")}>
            <FileArchive size={16} />
            NEW WHITEBOX AUDIT
          </button>
        </div>
      </section>

      <section className="panel">
        <SectionTitle icon={<Workflow size={18} />} title="Agent Pipeline" />
        <AgentPipeline />
      </section>

      <section className="panel">
        <SectionTitle icon={<Activity size={18} />} title="Runtime Status" />
        <div className="service-list">
          {services.map((service) => (
            <div className="service-row" key={service.name}>
              <service.icon size={18} />
              <span>{service.name}</span>
              <StatusLight tone={service.tone} />
              <strong>{service.value}</strong>
            </div>
          ))}
        </div>
      </section>

      <section className="panel terminal-panel">
        <SectionTitle icon={<Terminal size={18} />} title="Agent Terminal" />
        <div className="terminal-lines">
          {terminalLines.map((line) => (
            <code key={line}>{line}</code>
          ))}
        </div>
      </section>

      <section className="panel reports-preview">
        <SectionTitle icon={<FileText size={18} />} title="Recent Findings" />
        <FindingList
          findings={findings}
          selectedId={findings[0].id}
          onSelect={(finding) => {
            onFinding(finding);
            onView("reports");
          }}
        />
      </section>
    </div>
  );
}

function BlackboxPage() {
  const [target, setTarget] = useState("https://example.com");
  const [profile, setProfile] = useState<ScanProfile>("standard");
  const [submission, setSubmission] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const modules = [
    "Probe & Tech Stack",
    "Fingerprint (CN CMS/OA/WAF)",
    "JSFinder Endpoints",
    "Secret Scan",
    "Swagger/OpenAPI",
    "SSL Analysis",
    "Security Headers",
    "Sensitive Paths"
  ];

  return (
    <div className="page form-grid">
      <section className="panel">
        <SectionTitle icon={<Globe2 size={18} />} title="Blackbox Target" />
        <form
          className="config-form"
          onSubmit={async (event) => {
            event.preventDefault();
            setLoading(true);
            setError("");
            setSubmission("");
            try {
              const response = await fetch("/api/scans/blackbox", {
                method: "POST",
                headers: authHeaders(),
                body: JSON.stringify({
                  targetUrl: target,
                  profile,
                  scope: {
                    includeSubdomains: true,
                    respectRobots: true,
                    rateLimit: true,
                    authenticatedScan: false
                  },
                  modules
                })
              });
              if (!response.ok) {
                const payload = await response.json().catch(() => ({}));
                throw new Error(payload.detail || "Failed to create blackbox scan");
              }
              const payload = (await response.json()) as { scanId: string; status: string };
              setSubmission(`Scan ${payload.scanId} queued with status ${payload.status}`);
            } catch (submitError) {
              setError(submitError instanceof Error ? submitError.message : "Failed to create scan");
            } finally {
              setLoading(false);
            }
          }}
        >
          <PixelField label="TARGET URL">
            <input value={target} onChange={(event) => setTarget(event.target.value)} />
          </PixelField>
          <PixelField label="SCAN PROFILE (DSH PENTEST SOP)">
            <div className="segmented">
              {(["quick", "standard", "deep"] as ScanProfile[]).map((value) => (
                <button
                  key={value}
                  type="button"
                  className={profile === value ? "active" : ""}
                  onClick={() => setProfile(value)}
                >
                  {value}
                </button>
              ))}
            </div>
          </PixelField>
          <div className="checkbox-grid">
            {["Include subdomains", "Respect robots.txt", "Rate limit", "Authenticated scan"].map(
              (item, index) => (
                <label key={item} className="check-row">
                  <input type="checkbox" defaultChecked={index < 2} />
                  <span>{item}</span>
                </label>
              )
            )}
          </div>
          <div className="module-grid">
            {modules.map((module) => (
              <label key={module} className="module-tile">
                <input type="checkbox" defaultChecked />
                <span>{module}</span>
              </label>
            ))}
          </div>
          <div className="action-row">
            <button className="pixel-button primary" type="submit" disabled={loading}>
              <Play size={16} />
              {loading ? "CREATING..." : "START BLACKBOX SCAN"}
            </button>
            <button className="pixel-button" type="button">
              <Archive size={16} />
              SAVE DRAFT
            </button>
          </div>
        </form>
      </section>

      <aside className="panel">
        <SectionTitle icon={<Route size={18} />} title="Execution Preview" />
        <AgentPipeline />
        <div className="summary-box">
          <span>Target</span>
          <strong>{target || "waiting for URL"}</strong>
        </div>
        <div className="summary-box">
          <span>Profile</span>
          <strong>{profile.toUpperCase()}</strong>
        </div>
        {submission && (
          <div className="success-banner">
            <Check size={17} />
            {submission}
          </div>
        )}
        {error && <div className="pixel-error">{error}</div>}
      </aside>
    </div>
  );
}

function WhiteboxPage() {
  const [fileName, setFileName] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [projectName, setProjectName] = useState("demo-service");
  const [auditProfile, setAuditProfile] = useState<AuditProfile>("standard");
  const [submission, setSubmission] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const vulnClasses = [
    "SQL Injection",
    "XSS",
    "SSRF",
    "Auth Bypass",
    "File Upload",
    "Path Traversal",
    "RCE",
    "Insecure Deserialization"
  ];

  function applyFile(file?: File) {
    if (!file) return;
    setFile(file);
    setFileName(`${file.name} / ${(file.size / 1024 / 1024).toFixed(2)} MB`);
  }

  function handleDrop(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault();
    applyFile(event.dataTransfer.files[0]);
  }

  return (
    <div className="page form-grid">
      <section className="panel">
        <SectionTitle icon={<Code2 size={18} />} title="Whitebox Source Audit" />
        <form
          className="config-form"
          onSubmit={async (event) => {
            event.preventDefault();
            setSubmission("");
            setError("");
            if (!file) {
              setError("Please select a source archive first.");
              return;
            }
            setLoading(true);
            try {
              const data = new FormData();
              data.append("projectName", projectName);
              data.append("language", "auto");
              data.append("auditProfile", auditProfile);
              vulnClasses.forEach((item) => data.append("vulnerabilityClasses", item));
              data.append("archive", file);
              const response = await fetch("/api/scans/whitebox", {
                method: "POST",
                headers: authHeaders(false),
                body: data
              });
              if (!response.ok) {
                const payload = await response.json().catch(() => ({}));
                throw new Error(payload.detail || "Failed to create whitebox audit");
              }
              const payload = (await response.json()) as { scanId: string; status: string };
              setSubmission(`Audit ${payload.scanId} queued with status ${payload.status}`);
            } catch (submitError) {
              setError(submitError instanceof Error ? submitError.message : "Failed to upload archive");
            } finally {
              setLoading(false);
            }
          }}
        >
          <PixelField label="PROJECT NAME">
            <input value={projectName} onChange={(event) => setProjectName(event.target.value)} />
          </PixelField>
          <label
            className="dropzone"
            onDragOver={(event) => event.preventDefault()}
            onDrop={handleDrop}
          >
            <UploadCloud size={34} />
            <strong>{fileName || "DROP SOURCE ARCHIVE HERE"}</strong>
            <span>Accepted: .zip .tar.gz .tgz</span>
            <input
              type="file"
              accept=".zip,.tar.gz,.tgz"
              onChange={(event: ChangeEvent<HTMLInputElement>) =>
                applyFile(event.target.files?.[0])
              }
            />
          </label>
          <PixelField label="LANGUAGE / FRAMEWORK">
            <select defaultValue="auto">
              <option value="auto">Auto Detect</option>
              <option value="python">Python</option>
              <option value="typescript">JavaScript / TypeScript</option>
              <option value="java">Java</option>
              <option value="go">Go</option>
              <option value="php">PHP</option>
            </select>
          </PixelField>
          <PixelField label="AUDIT MODE (CODE-AUDIT SKILL)">
            <div className="segmented wrap">
              {(["quick", "standard", "deep"] as AuditProfile[]).map((value) => (
                <button
                  key={value}
                  type="button"
                  className={auditProfile === value ? "active" : ""}
                  onClick={() => setAuditProfile(value)}
                >
                  {value}
                </button>
              ))}
            </div>
          </PixelField>
          <div className="module-grid">
            {vulnClasses.map((item) => (
              <label key={item} className="module-tile">
                <input type="checkbox" defaultChecked />
                <span>{item}</span>
              </label>
            ))}
          </div>
          <button className="pixel-button primary" type="submit" disabled={loading}>
            <HardDriveUpload size={16} />
            {loading ? "UPLOADING..." : "START WHITEBOX AUDIT"}
          </button>
          {submission && (
            <div className="success-banner">
              <Check size={17} />
              {submission}
            </div>
          )}
          {error && <div className="pixel-error">{error}</div>}
        </form>
      </section>

      <aside className="panel">
        <SectionTitle icon={<Layers3 size={18} />} title="Audit Pipeline" />
        <div className="stack-list">
          {[
            "Mode Determination [MODE]",
            "Reconnaissance [RECON]",
            "Execution Plan [PLAN]",
            "D1-D10 Dimension Scan",
            "Coverage Matrix",
            "Report Gate",
            "Report Render"
          ].map((item) => (
              <div className="stack-item" key={item}>
                <CircleDot size={15} />
                {item}
              </div>
            ))}
        </div>
        <div className="summary-box">
          <span>Selected mode</span>
          <strong>{auditProfile.toUpperCase()}</strong>
        </div>
        <div className="summary-box">
          <span>Coverage</span>
          <strong>{auditProfile === "quick" ? "D1 D7 D10" : "D1 - D10 FULL"}</strong>
        </div>
      </aside>
    </div>
  );
}

function ReportsPage({
  selected,
  onSelect
}: {
  selected: Finding;
  onSelect: (finding: Finding) => void;
}) {
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [reportDetail, setReportDetail] = useState<ReportDetail | null>(null);
  const [selectedReportId, setSelectedReportId] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    fetch("/api/reports", { headers: authHeaders(false) })
      .then(async (response) => {
        if (!response.ok) throw new Error("Failed to load backend reports");
        return (await response.json()) as ReportSummary[];
      })
      .then((items) => {
        setReports(items);
        if (items[0]) setSelectedReportId(items[0].id);
      })
      .catch((loadError) => setError(loadError instanceof Error ? loadError.message : "Failed to load reports"));
  }, []);

  useEffect(() => {
    if (!selectedReportId) return;
    fetch(`/api/reports/${selectedReportId}`, { headers: authHeaders(false) })
      .then(async (response) => {
        if (!response.ok) throw new Error("Failed to load report detail");
        return (await response.json()) as ReportDetail;
      })
      .then((detail) => {
        setReportDetail(detail);
        if (detail.findings[0]) onSelect(detail.findings[0]);
      })
      .catch((loadError) => setError(loadError instanceof Error ? loadError.message : "Failed to load report"));
  }, [selectedReportId, onSelect]);

  const visibleFindings = reportDetail?.findings.length ? reportDetail.findings : findings;
  const visibleSelected =
    visibleFindings.find((finding) => finding.id === selected.id) || visibleFindings[0] || selected;
  const counts = useMemo(
    () => ({
      critical: visibleFindings.filter((item) => item.severity === "critical").length,
      high: visibleFindings.filter((item) => item.severity === "high").length,
      medium: visibleFindings.filter((item) => item.severity === "medium").length,
      low: visibleFindings.filter((item) => item.severity === "low").length
    }),
    [visibleFindings]
  );

  return (
    <div className="page report-layout">
      <section className="panel report-summary">
        <SectionTitle icon={<ShieldAlert size={18} />} title="Report Summary" />
        {error && <div className="pixel-error">{error}</div>}
        {reports.length > 0 && (
          <PixelField label="REPORT">
            <select value={selectedReportId} onChange={(event) => setSelectedReportId(event.target.value)}>
              {reports.map((report) => (
                <option key={report.id} value={report.id}>
                  {report.title} / {report.id}
                </option>
              ))}
            </select>
          </PixelField>
        )}
        <div className="metric-grid">
          <Metric label="Risk Score" value={String(reportDetail?.riskScore ?? 8.2)} tone="bad" />
          <Metric label="Findings" value={String(visibleFindings.length)} tone="good" />
          <Metric label="Critical" value={String(counts.critical)} tone="bad" />
          <Metric label="High" value={String(counts.high)} tone="warn" />
        </div>
      </section>
      <section className="panel finding-column">
        <SectionTitle icon={<Bug size={18} />} title="Findings" />
        <FindingList findings={visibleFindings} selectedId={visibleSelected.id} onSelect={onSelect} />
      </section>
      <section className="panel finding-detail">
        <div className="detail-head">
          <RiskBadge severity={visibleSelected.severity} />
          <h3>{visibleSelected.title}</h3>
          <span>{visibleSelected.id}</span>
        </div>
        <div className="detail-grid">
          <DetailBlock label="Component" value={visibleSelected.component} />
          <DetailBlock label="Source Agent" value={visibleSelected.source} />
          <DetailBlock label="Verification" value={visibleSelected.verified ? "Verified" : "Pending"} />
        </div>
        <DetailSection title="Description">{visibleSelected.description}</DetailSection>
        <DetailSection title="Evidence">
          {JSON.stringify(visibleSelected.evidence || { note: "No backend evidence loaded yet." })}
        </DetailSection>
        <DetailSection title="Recommendation">
          {visibleSelected.recommendation ||
            "使用参数化查询、上下文输出编码、严格 scope 控制，并将验证结果写入不可变报告证据目录。"}
        </DetailSection>
        <div className="action-row">
          <button
            className="pixel-button"
            disabled={!reportDetail}
            onClick={() => reportDetail && downloadReport(reportDetail.id, "md")}
          >
            <Download size={16} />
            EXPORT MD
          </button>
          <button
            className="pixel-button"
            disabled={!reportDetail}
            onClick={() => reportDetail && downloadReport(reportDetail.id, "json")}
          >
            <FileJson size={16} />
            EXPORT JSON
          </button>
        </div>
      </section>
    </div>
  );
}

function SandboxPage() {
  return (
    <div className="page">
      <section className="panel">
        <SectionTitle icon={<Server size={18} />} title="Sandbox Tooling" />
        <div className="sandbox-grid">
          {[
            ["Terminal", "Shell command execution in isolated container"],
            ["Browser", "Crawling, DOM inspection and authenticated flows"],
            ["Proxy", "HTTP capture, replay and passive analysis"],
            ["Python Runtime", "PoC scripts, parsers and custom checks"],
            ["Skill Loader", "Task-specific testing playbooks"],
            ["MCP Bridge", "Structured tool routing for agents"]
          ].map(([name, desc]) => (
            <div className="tool-tile" key={name}>
              <Zap size={18} />
              <strong>{name}</strong>
              <span>{desc}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

function SettingsPage() {
  return (
    <div className="page">
      <section className="panel settings-panel">
        <SectionTitle icon={<Fingerprint size={18} />} title="Access Settings" />
        <PixelField label="INVITE API">
          <input value="POST /api/auth/invite" readOnly />
        </PixelField>
        <PixelField label="TOKEN STORAGE">
          <input value="httpOnly cookie recommended for production" readOnly />
        </PixelField>
        <div className="success-banner">
          <Lock size={17} />
          Frontend mock code: demo-invite-code
        </div>
      </section>
    </div>
  );
}

function AgentPipeline() {
  return (
    <div className="agent-pipeline">
      {agents.map((agent, index) => (
        <div className="agent-node" key={agent.name}>
          <div className="agent-card">
            <agent.icon size={18} />
            <strong>{agent.name}</strong>
            <span>{agent.status}</span>
          </div>
          {index < agents.length - 1 && <ChevronRight className="pipeline-arrow" size={18} />}
        </div>
      ))}
    </div>
  );
}

function FindingList({
  findings,
  selectedId,
  onSelect
}: {
  findings: Finding[];
  selectedId: string;
  onSelect: (finding: Finding) => void;
}) {
  return (
    <div className="finding-list">
      {findings.map((finding) => (
        <button
          key={finding.id}
          className={selectedId === finding.id ? "finding-card active" : "finding-card"}
          onClick={() => onSelect(finding)}
        >
          <RiskBadge severity={finding.severity} />
          <strong>{finding.title}</strong>
          <span>{finding.component}</span>
          <small>{finding.verified ? "Verified by Validation Agent" : "Awaiting validation"}</small>
        </button>
      ))}
    </div>
  );
}

function SectionTitle({ icon, title }: { icon: ReactNode; title: string }) {
  return (
    <div className="section-title">
      {icon}
      <h2>{title}</h2>
    </div>
  );
}

function PixelField({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="pixel-field">
      <span>{label}</span>
      {children}
    </label>
  );
}

function StatusPill({ label, value, tone }: { label: string; value: string; tone: string }) {
  return (
    <div className="status-pill">
      <span>{label}</span>
      <StatusLight tone={tone} />
      <strong>{value}</strong>
    </div>
  );
}

function StatusLight({ tone }: { tone: string }) {
  return <i className={`status-light ${tone}`} aria-hidden="true" />;
}

function RiskBadge({ severity }: { severity: Severity }) {
  return <span className={`risk-badge ${severity}`}>{severity.toUpperCase()}</span>;
}

function Metric({ label, value, tone }: { label: string; value: string; tone: string }) {
  return (
    <div className={`metric ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function DetailBlock({ label, value }: { label: string; value: string }) {
  return (
    <div className="detail-block">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function DetailSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="detail-section">
      <h4>{title}</h4>
      <p>{children}</p>
    </section>
  );
}

function authHeaders(json = true): HeadersInit {
  const token = localStorage.getItem(tokenKey) || "";
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`
  };
  if (json) headers["Content-Type"] = "application/json";
  return headers;
}

async function downloadReport(reportId: string, format: "json" | "md") {
  const response = await fetch(`/api/reports/${reportId}/export.${format}`, {
    headers: authHeaders(false)
  });
  if (!response.ok) return;
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `ai2sec-report-${reportId}.${format}`;
  link.click();
  URL.revokeObjectURL(url);
}

export { App };
