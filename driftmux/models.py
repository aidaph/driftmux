from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}

@dataclass(slots=True)
class ToolError:
    scanner: str
    message: str
    host: Optional[str] = None
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class OpenPort:
    port: int
    protocol: str
    state: str
    service: str
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    cpes: List[str] = field(default_factory=list)
    classifications: List[str] = field(default_factory=list)

    def endpoint(self) -> str:
        return f"{self.port}/{self.protocol}"

    def detected_version(self) -> str:
        return self.version or self.extrainfo or "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Finding:
    scanner: str
    host: str
    title: str
    severity: str = "info"
    description: str = ""
    evidence: str = ""
    confidence: str = "medium"
    port: Optional[int] = None
    service: Optional[str] = None
    detected_version: Optional[str] = None
    reference: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def normalized_severity(self) -> str:
        value = (self.severity or "unknown").lower()
        return value if value in SEVERITY_ORDER else "unknown"

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["severity"] = self.normalized_severity()
        return payload


@dataclass(slots=True)
class HostScanResult:
    host: str
    services: List[OpenPort] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    errors: List[ToolError] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_error(self, scanner: str, message: str, details: Optional[str] = None) -> None:
        self.errors.append(ToolError(scanner=scanner, host=self.host, message=message, details=details))

    def max_severity(self) -> str:
        if not self.findings:
            return "unknown"
        return max((f.normalized_severity() for f in self.findings), key=lambda x: SEVERITY_ORDER.get(x, 0))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "metadata": self.metadata,
            "summary": {
                "services": len(self.services),
                "findings": len(self.findings),
                "errors": len(self.errors),
                "max_severity": self.max_severity(),
            },
            "services": [s.to_dict() for s in self.services],
            "findings": [f.to_dict() for f in self.findings],
            "errors": [e.to_dict() for e in self.errors],
        }
