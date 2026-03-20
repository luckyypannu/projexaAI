from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone

@dataclass
class ScanResult:
    target: str
    scan_type: str
    trust_score: int
    risk_level: str
    pattern_flags: list[str] = field(default_factory=list)  # ← renamed
    advice: list[str] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "trust_score": self.trust_score,
            "risk_level": self.risk_level,
            "pattern_flags": self.pattern_flags,  # ← renamed
            "advice": self.advice,
            "created_at": self.created_at
        }

    @classmethod
    def from_dict(cls, data: dict) -> ScanResult:
        return cls(
            target=data["target"],
            scan_type=data["scan_type"],
            trust_score=data["trust_score"],
            risk_level=data["risk_level"],
            pattern_flags=data.get("pattern_flags", []),  # ← renamed
            advice=data.get("advice", []),
            created_at=data.get("created_at", "")
        )
