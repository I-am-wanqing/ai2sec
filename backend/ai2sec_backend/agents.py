import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, TypedDict
from .config import Settings, get_settings
from .db import insert_event, insert_finding, set_scan_status
from .reports import build_report
from .sandbox import DockerSandbox
from .audit import run_whitebox_audit
from .pentest import run_blackbox_audit
from .scanners import analyze_blackbox


class AgentState(TypedDict, total=False):
    scan_id: str
    scan_type: str
    target: str
    archive_path: str
    work_dir: str
    config: Dict[str, Any]
    plan: List[str]
    mode: str
    recon: Dict[str, Any]
    discovery: Dict[str, Any]
    coverage: Dict[str, Any]
    gate: Dict[str, Any]
    findings: List[Dict[str, Any]]
    report: Dict[str, Any]
    errors: List[str]


def run_scan(scan_id: str, settings: Optional[Settings] = None) -> None:
    settings = settings or get_settings()
    set_scan_status(scan_id, "running")
    try:
        state = _load_initial_state(scan_id)
        graph = build_agent_graph()
        final_state = graph.invoke(state)
        if final_state.get("errors"):
            set_scan_status(scan_id, "failed")
            insert_event(scan_id, "Root Agent", "Scan failed", "error", {"errors": final_state["errors"]})
            return
        set_scan_status(scan_id, "completed")
        insert_event(scan_id, "Root Agent", "Scan completed", "info", {"report": final_state.get("report")})
    except Exception as exc:
        set_scan_status(scan_id, "failed")
        insert_event(scan_id, "Root Agent", "Unhandled scan failure", "error", {"error": str(exc)})


def build_agent_graph() -> Any:
    try:
        from langgraph.graph import END, START, StateGraph

        graph = StateGraph(AgentState)
        graph.add_node("root", root_agent)
        graph.add_node("recon", recon_agent)
        graph.add_node("discovery", discovery_agent)
        graph.add_node("validation", validation_agent)
        graph.add_node("reporting", reporting_agent)
        graph.add_edge(START, "root")
        graph.add_edge("root", "recon")
        graph.add_edge("recon", "discovery")
        graph.add_edge("discovery", "validation")
        graph.add_edge("validation", "reporting")
        graph.add_edge("reporting", END)
        return graph.compile()
    except Exception:
        return SequentialGraph([root_agent, recon_agent, discovery_agent, validation_agent, reporting_agent])


class SequentialGraph:
    def __init__(self, nodes: List[Any]) -> None:
        self.nodes = nodes

    def invoke(self, state: AgentState) -> AgentState:
        for node in self.nodes:
            state = node(state)
        return state


def root_agent(state: AgentState) -> AgentState:
    plan = ["validate-input", "recon", "discovery", "independent-validation", "report"]
    state["plan"] = plan
    insert_event(state["scan_id"], "Root Agent", "Execution plan created", "info", {"plan": plan})
    return state


def recon_agent(state: AgentState) -> AgentState:
    sandbox = DockerSandbox()
    runtime = sandbox.run_terminal("python_runtime", ["python3", "--version"])
    insert_event(
        state["scan_id"],
        "Recon Agent",
        "Sandbox runtime checked",
        "info",
        {"exit_code": runtime.exit_code, "stdout": runtime.stdout},
    )
    if state["scan_type"] == "blackbox":
        state["recon"] = {"target": state["target"], "mode": "safe-mvp"}
    else:
        state["recon"] = {"archive": state["archive_path"], "mode": "safe-mvp"}
    return state


def discovery_agent(state: AgentState) -> AgentState:
    insert_event(state["scan_id"], "Discovery Agent", "Discovery started", "info")
    if state["scan_type"] == "blackbox":
        # Black-box: run the dsh pentest pipeline (recon engine → LLM SOP →
        # safe probes → 15-class coverage ledger).
        scan_id = state["scan_id"]

        def _emit(agent: str, message: str, level: str, data: Any) -> None:
            insert_event(scan_id, agent, message, level, data)

        result = run_blackbox_audit(state["target"], state["config"], emit=_emit)
        state["recon"] = {
            "target": result["recon"]["target"],
            "page": result["recon"]["page"],
            "fingerprints": result["recon"]["fingerprints"],
            "endpointCount": len(result["recon"]["jsfinder"]["endpoints"]),
            "secretCount": len(result["recon"]["jsfinder"]["secrets"]),
        }
        state["discovery"] = {
            "engine": result["engine"],
            "depth": result["depth"],
            "endpoints": result["recon"]["jsfinder"]["endpoints"][:100],
            "secrets": result["recon"]["jsfinder"]["secrets"][:30],
            "openapi": result["recon"].get("openapi"),
        }
        state["coverage"] = result["coverage"]
        state["findings"] = result["findings"]
    else:
        # White-box: run the code-audit skill pipeline (mode → recon →
        # D1-D10 dimension scan → coverage matrix → report gate).
        scan_id = state["scan_id"]

        def _emit(agent: str, message: str, level: str, data: Any) -> None:
            insert_event(scan_id, agent, message, level, data)

        result = run_whitebox_audit(
            Path(state["archive_path"]),
            Path(state["work_dir"]),
            state["config"],
            emit=_emit,
        )
        state["mode"] = result["mode"]
        state["recon"] = {key: value for key, value in result["recon"].items()}
        state["discovery"] = {
            "source": result["source"],
            "plannedDimensions": result["plannedDimensions"],
        }
        state["coverage"] = result["coverage"]
        state["gate"] = result["gate"]
        state["findings"] = result["findings"]
    insert_event(
        state["scan_id"],
        "Discovery Agent",
        "Discovery completed",
        "info",
        {"finding_count": len(state["findings"])},
    )
    return state


def validation_agent(state: AgentState) -> AgentState:
    validated = []
    for index, finding in enumerate(state.get("findings", []), start=1):
        enriched = dict(finding)
        enriched["id"] = f"AI2-{state['scan_id'][:8].upper()}-{index:03d}"
        enriched["scan_id"] = state["scan_id"]
        enriched["verified"] = _is_non_destructive_finding(enriched)
        validated.append(enriched)
        insert_finding(enriched)
    state["findings"] = validated
    insert_event(
        state["scan_id"],
        "Validation Agent",
        "Independent validation completed",
        "info",
        {"verified_count": sum(1 for item in validated if item["verified"])},
    )
    return state


def reporting_agent(state: AgentState) -> AgentState:
    report = build_report(state["scan_id"])
    state["report"] = report
    insert_event(
        state["scan_id"],
        "Reporting Agent",
        "Report generated",
        "info",
        {"report_id": report["id"], "risk_score": report["riskScore"]},
    )
    return state


def _is_non_destructive_finding(finding: Dict[str, Any]) -> bool:
    # The code-audit / dsh pentest pipelines pre-compute verification.
    agent = finding.get("source_agent", "")
    if "Dimension Agent" in agent or "Pentest" in agent or "LLM" in agent:
        return bool(finding.get("verified"))
    safe_sources = {"Recon Agent", "Discovery Agent"}
    return agent in safe_sources and bool(finding.get("evidence"))
    safe_sources = {"Recon Agent", "Discovery Agent"}
    return finding.get("source_agent") in safe_sources and bool(finding.get("evidence"))


def _load_initial_state(scan_id: str) -> AgentState:
    from .db import loads, one_row

    scan = one_row("SELECT * FROM scans WHERE id = ?", (scan_id,))
    if not scan:
        raise ValueError(f"Scan not found: {scan_id}")

    config = loads(scan["config_json"], {})
    return AgentState(
        scan_id=scan_id,
        scan_type=scan["type"],
        target=scan["target"] or "",
        archive_path=config.get("archivePath", ""),
        work_dir=config.get("workDir", ""),
        config=config,
        findings=[],
        errors=[],
    )


def new_scan_id() -> str:
    return uuid.uuid4().hex
