"""Small serializable types shared across integrations and reporting."""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any
import uuid

def utc_now() -> str: return datetime.now(timezone.utc).isoformat(timespec="seconds")

@dataclass
class Evidence:
    evidence_id: str
    source: str
    observed_at: str
    observation: str
    asset: str = ""
    query: str = ""
    provenance: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(cls, source: str, observation: str, **kwargs: Any) -> "Evidence":
        return cls("EV-" + uuid.uuid4().hex[:10].upper(), source, kwargs.pop("observed_at", utc_now()), observation, **kwargs)

@dataclass
class Hypothesis:
    hypothesis_id: str
    title: str
    technique_id: str
    rationale: str
    expected_host: list[str]
    expected_network: list[str]
    benign_explanations: list[str]
    tactics: list[str] = field(default_factory=list)
    detection_strategies: list[str] = field(default_factory=list)
    data_components: list[str] = field(default_factory=list)
    analytic_goal: str = ""
    mutable_elements: list[str] = field(default_factory=list)
    priority: int = 3
    status: str = "untested"
    evidence_ids: list[str] = field(default_factory=list)
    confidence: str = "low"

@dataclass
class Finding:
    finding_id: str
    title: str
    status: str
    technique_id: str
    assets: list[str]
    observation: str
    interpretation: str
    evidence_ids: list[str]
    confidence: str
    confidence_justification: str
    alternatives: list[str]
    follow_up: list[str]
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    classification: str = "suspicious"

def encode(obj: Any) -> Any:
    if hasattr(obj, "__dataclass_fields__"): return asdict(obj)
    return obj
