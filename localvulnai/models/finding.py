from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    title: str
    severity: Severity
    description: str
    location: str  # file path or URL
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    cwe: Optional[str] = None
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)

    def to_markdown(self) -> str:
        lines = [
            f"### [{self.severity.value.upper()}] {self.title}",
            f"**Location:** `{self.location}`",
            "",
            self.description,
        ]
        if self.evidence:
            lines.extend(["", "**Evidence:**", f"```\n{self.evidence}\n```"])
        if self.recommendation:
            lines.extend(["", f"**Recommendation:** {self.recommendation}"])
        if self.cwe:
            lines.append(f"\n**CWE:** {self.cwe}")
        return "\n".join(lines)
