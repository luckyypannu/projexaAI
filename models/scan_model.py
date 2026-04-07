from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


VALID_TYPES = {"url", "phone", "email"}
VALID_RISK_LEVELS = {"Low", "Medium", "High"}


@dataclass
class ScanResult:
    input: str
    type: str
    trust_score: int
    risk_level: str
    api_results: dict[str, Any]
    pattern_flags: list[str]
    advice: list[str]
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    id: Optional[str] = None  # MongoDB _id support

    # ──────────────────────────────────────────────────────────────────────────
    # Validation
    # ──────────────────────────────────────────────────────────────────────────

    def __post_init__(self):
        if self.type not in VALID_TYPES:
            raise ValueError(f"Invalid type: {self.type}")

        if not (0 <= self.trust_score <= 100):
            raise ValueError("trust_score must be between 0 and 100")

        if self.risk_level not in VALID_RISK_LEVELS:
            raise ValueError(f"Invalid risk_level: {self.risk_level}")

        # Ensure timestamp is always timezone-aware
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)

    # ──────────────────────────────────────────────────────────────────────────
    # Serialization (→ MongoDB)
    # ──────────────────────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """
        Convert object → MongoDB-safe dict.
        Keeps datetime as native (best for TTL index).
        """
        data = asdict(self)

        # Mongo uses _id instead of id
        if self.id:
            data["_id"] = self.id
            del data["id"]

        return data

    def to_response(self) -> dict[str, Any]:
        """
        Clean API response (no internal fields like timestamp/_id).
        """
        return {
            "input": self.input,
            "type": self.type,
            "trust_score": self.trust_score,
            "risk_level": self.risk_level,
            "advice": self.advice,
            "pattern_flags": self.pattern_flags,
        }

    # ──────────────────────────────────────────────────────────────────────────
    # Factory (← MongoDB)
    # ──────────────────────────────────────────────────────────────────────────

    @classmethod
    def from_mongo(cls, doc: dict[str, Any]) -> "ScanResult":
        """
        Safely convert Mongo document → ScanResult.

        Handles:
        - datetime (native BSON)
        - ISO string timestamps
        - missing/corrupt fields
        """

        if not doc:
            raise ValueError("Empty Mongo document")

        # ── Timestamp handling ────────────────────────────────────────────────
        ts = doc.get("timestamp")

        try:
            if isinstance(ts, datetime):
                # Ensure timezone-aware
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)

            elif isinstance(ts, str):
                # Handle ISO string (including 'Z')
                ts = ts.replace("Z", "+00:00")
                ts = datetime.fromisoformat(ts)

            else:
                # Fallback
                ts = datetime.now(timezone.utc)

        except Exception:
            ts = datetime.now(timezone.utc)

        # ── Safe field extraction ─────────────────────────────────────────────
        try:
            return cls(
                input=str(doc.get("input", "")),
                type=doc.get("type", "url"),
                trust_score=int(doc.get("trust_score", 0)),
                risk_level=doc.get("risk_level", "Low"),
                api_results=doc.get("api_results", {}) or {},
                pattern_flags=list(doc.get("pattern_flags", [])),
                advice=list(doc.get("advice", [])),
                timestamp=ts,
                id=str(doc.get("_id")) if doc.get("_id") else None,
            )

        except Exception as e:
            # Debug fallback (VERY useful in production)
            raise ValueError(f"Failed to parse Mongo document: {e}") from e