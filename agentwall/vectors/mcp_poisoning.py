from __future__ import annotations

from dataclasses import dataclass, field

import regex

SUSPICIOUS_PATTERNS = [
    r"(?i)<\s*important\s*>",
    r"(?i)<\s*system\s*>",
    r"(?i)before\s+(using|calling|invoking)\s+this\s+tool",
    r"(?i)do\s+not\s+mention",
    r"(?i)(read|access|exfiltrate)\s+(file|env|secret)",
    r"(?i)ignore\s+(previous|prior|above)",
    r"(?i)override\s+(all\s+)?(previous\s+)?instructions",
]

FORBIDDEN_KEYS = {
    "SYSTEM NOTE",
    "CRITICAL OVERRIDE",
    "ignore_previous",
    "_system",
    "__instructions__",
}


@dataclass
class ScanFinding:
    field_path: str
    pattern: str
    matched_text: str


@dataclass
class ScanResult:
    has_findings: bool = False
    findings: list[ScanFinding] = field(default_factory=list)


class MCPMetadataScanner:
    def __init__(self, extra_patterns: list[str] | None = None) -> None:
        self._patterns = [regex.compile(p) for p in SUSPICIOUS_PATTERNS]
        if extra_patterns:
            self._patterns.extend(regex.compile(p) for p in extra_patterns)

    def scan_tools_list(self, tools_response: dict) -> ScanResult:
        findings: list[ScanFinding] = []
        for tool in tools_response.get("tools", []):
            findings.extend(
                self._scan_field(
                    tool.get("description", ""),
                    f"tools.{tool.get('name', 'unknown')}.description",
                )
            )
            input_schema = tool.get("inputSchema", {})
            for param_name, param_def in input_schema.get("properties", {}).items():
                findings.extend(
                    self._scan_field(
                        param_def.get("description", ""),
                        f"tools.{tool.get('name', 'unknown')}.params.{param_name}.description",
                    )
                )
        return ScanResult(has_findings=bool(findings), findings=findings)

    def _scan_field(self, text: str, field_path: str) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        for pattern in self._patterns:
            match = pattern.search(text)
            if match:
                findings.append(
                    ScanFinding(
                        field_path=field_path,
                        pattern=pattern.pattern,
                        matched_text=match.group(),
                    )
                )
        return findings


class MCPResponseValidator:
    def __init__(self, forbidden_keys: set[str] | None = None) -> None:
        self._forbidden_keys = forbidden_keys or FORBIDDEN_KEYS
        self._metadata_scanner = MCPMetadataScanner()

    def validate(self, mcp_response: dict) -> ScanResult:
        findings: list[ScanFinding] = []
        forbidden = self._find_forbidden_keys(mcp_response)
        if forbidden:
            findings.append(
                ScanFinding(
                    field_path="response_keys",
                    pattern="forbidden_key",
                    matched_text=", ".join(forbidden),
                )
            )
        for path, value in self._iter_strings(mcp_response):
            field_findings = self._metadata_scanner._scan_field(value, path)
            findings.extend(field_findings)
        return ScanResult(has_findings=bool(findings), findings=findings)

    def _find_forbidden_keys(self, obj: dict) -> list[str]:
        found: list[str] = []
        for key in obj:
            if key.upper() in {k.upper() for k in self._forbidden_keys}:
                found.append(key)
        return found

    def _iter_strings(self, obj: object, path: str = "") -> list[tuple[str, str]]:
        results: list[tuple[str, str]] = []
        if isinstance(obj, str):
            results.append((path, obj))
        elif isinstance(obj, dict):
            for key, value in obj.items():
                results.extend(self._iter_strings(value, f"{path}.{key}" if path else key))
        elif isinstance(obj, (list, tuple)):
            for i, item in enumerate(obj):
                results.extend(self._iter_strings(item, f"{path}[{i}]"))
        return results
