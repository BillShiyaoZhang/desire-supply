from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class Issue:
    level: str
    code: str
    message: str
    field: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationResult:
    entity_type: str
    entity_id: str
    issues: List[Issue] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return not any(issue.level == "BLOCKER" for issue in self.issues)

    @property
    def status(self) -> str:
        if any(issue.level == "BLOCKER" for issue in self.issues):
            return "BLOCKER"
        if any(issue.level == "WARNING" for issue in self.issues):
            return "WARNING"
        if any(issue.level == "QUESTION" for issue in self.issues):
            return "QUESTION"
        return "READY"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "status": self.status,
            "ready": self.ready,
            "issues": [issue.to_dict() for issue in self.issues],
        }


@dataclass(frozen=True)
class BudgetAssessment:
    demand_id: str
    currency: str
    labor_baseline: float
    direct_cost: float
    risk_buffer_rate: float
    recommended_minimum: float
    budget_maximum: float
    health_ratio: float
    status: str
    config_version: str
    assumptions: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EligibilityResult:
    eligible: bool
    reasons: List[Dict[str, str]]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MatchScore:
    creator_id: str
    total: float
    components: Dict[str, float]
    evidence: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class MatchBrief:
    demand_id: str
    creator_id: str
    reasons: List[str]
    unknowns: List[str]
    risks: List[str]
    questions: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

