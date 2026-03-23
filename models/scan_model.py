from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone

@dataclass
class ScanResult:
    input: str
    type: str
    trust_score: int
    risk_level: str
    api_results: dict = field(default_factory=dict)
    pattern_flags: list[str] = field(default_factory=list)
    advice: list[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "input": self.input,
            "type": self.type,
            "trust_score": self.trust_score,
            "risk_level": self.risk_level,
            "api_results": self.api_results,
            "pattern_flags": self.pattern_flags,
            "advice": self.advice,
            "timestamp": self.timestamp
        }

    def to_response(self) -> dict:
        """What gets returned to frontend"""
        return {
            "input": self.input,
            "type": self.type,
            "trust_score": self.trust_score,
            "risk_level": self.risk_level,
            "pattern_flags": self.pattern_flags,
            "advice": self.advice,
            "timestamp": self.timestamp
        }

    @classmethod
    def from_mongo(cls, data: dict) -> ScanResult:
        """Convert MongoDB document back to ScanResult"""
        return cls(
            input=data["input"],
            type=data["type"],
            trust_score=data["trust_score"],
            risk_level=data["risk_level"],
            api_results=data.get("api_results", {}),
            pattern_flags=data.get("pattern_flags", []),
            advice=data.get("advice", []),
            timestamp=data.get("timestamp", "")
        )
