from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class InviteRequest(BaseModel):
    inviteCode: str = Field(min_length=1)


class InviteResponse(BaseModel):
    valid: bool
    token: str
    expiresAt: str


class BlackboxScope(BaseModel):
    includeSubdomains: bool = True
    respectRobots: bool = True
    rateLimit: bool = True
    authenticatedScan: bool = False


class BlackboxScanRequest(BaseModel):
    targetUrl: str
    profile: str = "standard"
    scope: BlackboxScope = Field(default_factory=BlackboxScope)
    modules: List[str] = Field(default_factory=list)


class ScanCreated(BaseModel):
    scanId: str
    status: str


class ScanResponse(BaseModel):
    id: str
    type: str
    status: str
    target: Optional[str]
    projectName: Optional[str]
    profile: str
    config: Dict[str, Any]
    createdAt: str
    updatedAt: str
    completedAt: Optional[str]


class EventResponse(BaseModel):
    id: int
    scanId: str
    agent: str
    level: str
    message: str
    data: Dict[str, Any]
    createdAt: str


class FindingResponse(BaseModel):
    id: str
    scanId: str
    title: str
    severity: str
    source: str
    component: str
    description: str
    evidence: Dict[str, Any]
    recommendation: str
    verified: bool
    createdAt: str


class ReportSummary(BaseModel):
    id: str
    scanId: str
    title: str
    riskScore: float
    summary: str
    createdAt: str


class ReportDetail(ReportSummary):
    findings: List[FindingResponse]
