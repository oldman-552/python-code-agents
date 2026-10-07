from __future__ import annotations

import argparse
import csv
import html
import io
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence, TextIO
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

SCHEMA_VERSION = "2.2"
TOOL_NAME = "rctfc-pdtm-auditor"
VERSION = "2.2.0"
USER_AGENT = "RCTFC-Authorized-Security-Tool/2.2"
MAX_TARGETS = 50
MAX_SCOPE_RULES = 100
MAX_CONFIG_BYTES = 1_048_576
MAX_TEXT_EXCERPT = 300
DEFAULT_TIMEOUT_S = 15
DEFAULT_RATE_LIMIT_RPS = 1
DEFAULT_MAX_SAMPLE_ITEMS = 3
DEFAULT_OUT_DIR = "out"
SAFE_NAABU_PORTS = "80,443,8080,8443"

ENVELOPE_FIELDS = (
    "schema_version", "tool", "version", "run_id", "request_id", "operation",
    "target", "scope", "started_at", "finished_at", "status", "success",
    "summary", "data", "findings", "injection_attempts", "recommendations",
    "artifacts", "errors", "warnings", "metrics", "next_actions",
)
FINDING_FIELDS = (
    "id", "title", "severity", "confidence", "category", "cwe", "owasp", "cvss",
    "asset", "parameter", "location", "precondition", "description", "root_cause",
    "evidence", "impact", "business_impact", "reproduction", "remediation",
    "regression_test", "false_positive_notes", "references",
)
INJECTION_FIELDS = ("source", "indicator", "excerpt", "severity", "action_taken")
RECOMMENDATION_FIELDS = (
    "priority", "title", "action", "target", "rationale", "effort", "verification",
    "related_findings",
)
SEVERITIES = ("critical", "high", "medium", "low", "info")
FAIL_LEVELS = ("none", "info", "low", "medium", "high", "critical")
FAIL_RANK = {name: index for index, name in enumerate(FAIL_LEVELS[1:])}

ANSI_ESCAPE_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\ufeff]")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SENSITIVE_KEY_RE = re.compile(
    r"(?i)\b(?P<key>api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"auth[_-]?token|token|password|passwd|secret|client[_-]?secret|"
    r"session(?:[_-]?id)?|cookie|set-cookie|authorization|proxy-authorization)"
    r"\b(?P<sep>\s*[:=]\s*)(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;<>]+)"
)
SENSITIVE_HEADER_RE = re.compile(
    r"(?im)(?P<key>cookie|set-cookie|authorization|proxy-authorization)\s*:\s*[^\r\n]+"
)
BEARER_RE = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
COMMON_TOKEN_RE = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16})\b"
)

INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "instruction-override",
        re.compile(
            r"(?:\b(?:ignore|disregard|forget|override)\b.{0,100}"
            r"\b(?:previous|prior|all|system|developer|earlier)\b.{0,60}"
            r"\b(?:instructions?|prompts?|rules?|polic(?:y|ies))\b|"
            r"(?:تجاهل|انسَ|تجاوز|ألغِ).{0,100}(?:التعليمات|القواعد|السياسات|الموجهات))",
            re.IGNORECASE | re.DOTALL,
        ),
        "medium",
    ),
    (
        "result-suppression",
        re.compile(
            r"(?:\b(?:do not|don't|never|must not)\b.{0,80}"
            r"\b(?:report|log|disclose|show|mention|delete|hide)\b.{0,80}"
            r"\b(?:finding|vulnerabilit|result|issue|error|warning)s?\b|"
            r"(?:لا\s*(?:تبلّغ|تبلغ|تذكر|تسجل|تعرض|تحذف).{0,80}"
            r"(?:ثغرة|نتيجة|مشكلة|تحذير)))",
            re.IGNORECASE | re.DOTALL,
        ),
        "medium",
    ),
    (
        "prompt-exfiltration",
        re.compile(
            r"(?:\b(?:reveal|print|show|disclose|repeat|dump|expose)\b.{0,80}"
            r"\b(?:system|developer|hidden|internal|secret)\b.{0,50}"
            r"\b(?:prompt|instructions?|policy|rules?)\b|"
            r"(?:اكشف|اطبع|اعرض|انسخ|أظهر).{0,80}"
            r"(?:تعليمات النظام|الموجه|التعليمات المخفية|السياسة الداخلية))",
            re.IGNORECASE | re.DOTALL,
        ),
        "medium",
    ),
    (
        "role-hijack",
        re.compile(
            r"(?:\b(?:you are now|act as|become|change your role to)\b.{0,80}"
            r"\b(?:admin(?:istrator)?|system|developer|root|owner)\b|"
            r"\b(?:developer mode|jailbreak|ignore safety)\b|"
            r"(?:أنت الآن|تصرّف ك|تصرف ك|غيّر دورك إلى|فعّل وضع).{0,80}"
            r"(?:المدير|المسؤول|النظام|المطور|المطوّر))",
            re.IGNORECASE | re.DOTALL,
        ),
        "medium",
    ),
    (
        "exfil-command",
        re.compile(
            r"(?:\b(?:send|upload|exfiltrate|forward|transmit|post)\b.{0,100}"
            r"\b(?:data|secret|credential|token|cookie|password|file)s?\b|"
            r"\b(?:curl|wget)\b.{0,160}(?:https?://|\|\s*base64)|"
            r"\bbase64\s+(?:-d|--decode)\b|"
            r"(?:أرسل|هرّب|سرّب|انقل).{0,80}(?:البيانات|الأسرار|الاعتمادات))",
            re.IGNORECASE | re.DOTALL,
        ),
        "medium",
    ),
    (
        "identity-claim",
        re.compile(
            r"(?:\b(?:i am|this is)\s+(?:the\s+)?"
            r"(?:system|developer|owner|administrator)\b|"
            r"^\s*(?:system|developer|administrator)\s*:|"
            r"(?:أنا\s+(?:النظام|المطور|المطوّر|المالك|المسؤول)))",
            re.IGNORECASE | re.MULTILINE,
        ),
        "info",
    ),
)
HIDDEN_STYLE_RE = re.compile(
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?\b|"
    r"font-size\s*:\s*0(?:px|em|rem|%)?\b|\bhidden\s*=|"
    r"color\s*:\s*(?:#fff(?:fff)?|white)\b)",
    re.IGNORECASE,
)
SECRET_TYPE_BY_KEY = {
    "apikey": "api_key", "accesstoken": "token", "refreshtoken": "token",
    "idtoken": "token", "authtoken": "token", "token": "token",
    "password": "password", "passwd": "password", "secret": "secret",
    "clientsecret": "secret", "session": "session", "sessionid": "session",
    "cookie": "cookie", "setcookie": "cookie", "authorization": "authorization",
    "proxyauthorization": "authorization",
}


class InputError(ValueError):
    """Raised when input fails validation."""

    def __init__(self, message: str, code: str = "INVALID_INPUT") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ToolSpec:
    name: str
    category: str
    mode: str
    risk: str
    third_party: bool = False
    active_by_default: bool = False
    requires_explicit_flag: str = ""
    skip_reason: str = ""


TOOL_CATALOG: tuple[ToolSpec, ...] = (
    ToolSpec("pdtm", "manager", "utility", "low", skip_reason="Installer/manager only; never used to scan a target."),
    ToolSpec("subfinder", "asset-discovery", "passive", "low", third_party=True, skip_reason="Queries passive third-party data sources; requires --allow-third-party-sources."),
    ToolSpec("uncover", "asset-discovery", "passive", "medium", third_party=True, skip_reason="Queries external search providers and may require provider credentials."),
    ToolSpec("chaos-client", "asset-discovery", "passive", "medium", third_party=True, skip_reason="Uses an external asset database and account credentials."),
    ToolSpec("asnmap", "asset-discovery", "passive", "medium", third_party=True, skip_reason="Uses external ASN data; not needed for an exact website target."),
    ToolSpec("cloudlist", "asset-discovery", "passive", "high", third_party=True, skip_reason="Reads cloud-provider accounts and assets; requires separately scoped credentials."),
    ToolSpec("dnsx", "dns", "active", "low", active_by_default=True),
    ToolSpec("httpx", "http", "active", "low", active_by_default=True),
    ToolSpec("tlsx", "tls", "active", "low", active_by_default=True),
    ToolSpec("naabu", "ports", "active", "medium", requires_explicit_flag="--enable-port-scan", skip_reason="TCP port scan is opt-in and limited to a small web-port list."),
    ToolSpec("katana", "crawler", "active", "medium", skip_reason="Crawler can discover state-changing or off-scope URLs; not auto-run."),
    ToolSpec("nuclei", "vulnerability-templates", "active", "high", skip_reason="Template content and request methods vary; requires human-reviewed template selection."),
    ToolSpec("shuffledns", "dns-bruteforce", "active", "high", skip_reason="Wordlist/brute-force activity is intentionally not auto-run."),
    ToolSpec("interactsh-client", "out-of-band", "active", "high", third_party=True, skip_reason="Creates out-of-band callbacks through external infrastructure."),
    ToolSpec("interactsh-server", "out-of-band", "utility", "high", third_party=True, skip_reason="Server/service role, not a scoped target scanner."),
    ToolSpec("notify", "notification", "utility", "high", third_party=True, skip_reason="Sends results to external destinations; never invoked by this tool."),
    ToolSpec("proxify", "proxy", "utility", "medium", skip_reason="Proxy service, not a target scanner."),
    ToolSpec("alterx", "asset-generation", "utility", "low", skip_reason="Generates candidate names; does not validate ownership or scan them."),
    ToolSpec("mapcidr", "asset-transformation", "utility", "low", skip_reason="Transforms CIDRs and can expand scope; not needed for explicit website targets."),
    ToolSpec("cdncheck", "asset-classification", "utility", "low", third_party=True, skip_reason="External classification is not required for the bounded scan profile."),
)
TOOL_SPEC_BY_NAME = {spec.name: spec for spec in TOOL_CATALOG}


@dataclass(frozen=True)
class ToolConfig:
    targets: tuple[str, ...]
    scopes: tuple[str, ...]
    request_id: str = ""
    operation: str = "scan"
    authorization_ref: str = ""
    mode: str | None = None
    timeout_s: int = 15
    rate_limit_rps: int = 1
    max_sample_items: int = 3
    out_dir: Path = Path("out")
    proxy: str = ""
    fail_on: str = "high"
    no_fail_on_findings: bool = False
    verbose: bool = False
    allow_third_party_sources: bool = False
    enable_port_scan: bool = False
    pdtm_bin_dir: Path = Path.home() / ".pdtm" / "go" / "bin"


@dataclass(frozen=True)
class NormalizedTarget:
    url: str
    scheme: str
    host: str
    port: int
    path: str

    @property
    def display_url(self) -> str:
        return safe_url(self.url)


@dataclass(frozen=True)
class ScopeRule:
    host: str = ""
    wildcard: bool = False
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    scheme: str = ""
    port: int | None = None
    path_prefix: str = ""

    def allows(self, target: NormalizedTarget) -> bool:
        if self.scheme and target.scheme != self.scheme:
            return False
        if self.port is not None and target.port != self.port:
            return False
        if self.network is not None:
            try:
                address = ipaddress.ip_address(target.host)
            except ValueError:
                return False
            if address not in self.network:
                return False
        elif self.wildcard:
            if target.host == self.host or not target.host.endswith("." + self.host):
                return False
        elif target.host != self.host:
            return False
        if self.path_prefix and self.path_prefix != "/":
            prefix = self.path_prefix.rstrip("/")
            if target.path != prefix and not target.path.startswith(prefix + "/"):
                return False
        return True


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    confidence: str
    category: str
    cwe: str = ""
    owasp: str = ""
    cvss: float | None = None
    asset: str = ""
    parameter: str = ""
    location: str = ""
    precondition: str = ""
    description: str = ""
    root_cause: str = ""
    evidence: str = ""
    impact: str = ""
    business_impact: str = ""
    reproduction: str = ""
    remediation: str = ""
    regression_test: str = ""
    false_positive_notes: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Recommendation:
    priority: str
    title: str
    action: str
    target: str
    rationale: str
    effort: str
    verification: str
    related_findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SecretHit:
    secret_type: str
    location: str


class ISOFormatter(logging.Formatter):
    converter = time.gmtime

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        timestamp = datetime.fromtimestamp(record.created, timezone.utc)
        return timestamp.isoformat(timespec="seconds").replace("+00:00", "Z")


def setup_logging(verbose: bool = False, stream: TextIO | None = None) -> logging.Logger:
    logger = logging.getLogger("rctfc_pdtm_auditor")
    logger.handlers.clear()
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(ISOFormatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False
    return logger


def sanitize(value: Any, max_length: int | None = None, *, single_line: bool = False) -> str:
    text = str(value)
    text = ANSI_ESCAPE_RE.sub("", text)
    text = ZERO_WIDTH_RE.sub("", text)
    text = CONTROL_RE.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if single_line:
        text = text.replace("\n", " ").replace("\t", " ")
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    if max_length is not None and len(text) > max_length:
        if max_length <= 1:
            return text[:max_length]
        text = text[: max_length - 1] + "…"
    return text


def redact(value: Any) -> str:
    text = str(value)
    text = SENSITIVE_HEADER_RE.sub(
        lambda match: f"{match.group('key')}: ***REDACTED***", text
    )
    text = BEARER_RE.sub(lambda match: f"{match.group(1)} ***REDACTED***", text)
    text = SENSITIVE_KEY_RE.sub(
        lambda match: f"{match.group('key')}{match.group('sep')}***REDACTED***", text
    )
    text = JWT_RE.sub("***REDACTED***", text)
    return COMMON_TOKEN_RE.sub("***REDACTED***", text)


def _canonical_secret_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _redact_structure(value: Any) -> Any:
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            canonical = _canonical_secret_key(key)
            if canonical in SECRET_TYPE_BY_KEY:
                redacted[str(key)] = "***REDACTED***"
            else:
                redacted[str(key)] = _redact_structure(item)
        return redacted
    if isinstance(value, list):
        return [_redact_structure(item) for item in value]
    if isinstance(value, str):
        return redact(value)
    return value


def redact_tool_output(value: str) -> str:
    lines = value.splitlines()
    if not lines:
        return redact(value)
    parsed_lines: list[str] = []
    parsed_any = False
    for line in lines:
        if not line.strip():
            parsed_lines.append(line)
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            parsed_lines.append(redact(line))
        else:
            parsed_any = True
            parsed_lines.append(json.dumps(_redact_structure(record), ensure_ascii=False, separators=(",", ":")))
    if parsed_any:
        return "\n".join(parsed_lines) + ("\n" if value.endswith("\n") else "")
    try:
        record = json.loads(value)
    except json.JSONDecodeError:
        return redact(value)
    return json.dumps(_redact_structure(record), ensure_ascii=False, indent=2)


def _safe_excerpt(text: str, start: int, end: int) -> str:
    left = max(0, start - 90)
    right = min(len(text), max(end, start + 1) + 90)
    excerpt = text[left:right]
    notes: list[str] = []
    if ZERO_WIDTH_RE.search(excerpt):
        notes.append("invisible Unicode removed")
    if ANSI_ESCAPE_RE.search(excerpt):
        notes.append("ANSI escape removed")
    clean = sanitize(redact(excerpt), MAX_TEXT_EXCERPT)
    if notes:
        clean = sanitize("[" + "; ".join(notes) + "] " + clean, MAX_TEXT_EXCERPT)
    return clean


def detect_injection(text: str, source: str) -> list[dict[str, str]]:
    raw_text = str(text)
    decoded_text = html.unescape(raw_text)
    candidates: list[tuple[int, str, str, str]] = []
    for indicator, pattern, severity in INJECTION_PATTERNS:
        for match in pattern.finditer(decoded_text):
            candidates.append((match.start(), indicator, severity, decoded_text))
    for match in ZERO_WIDTH_RE.finditer(raw_text):
        candidates.append((match.start(), "hidden-text", "info", raw_text))
    for match in ANSI_ESCAPE_RE.finditer(raw_text):
        candidates.append((match.start(), "hidden-text", "info", raw_text))
    for match in HIDDEN_STYLE_RE.finditer(decoded_text):
        candidates.append((match.start(), "hidden-text", "info", decoded_text))
    candidates.sort(key=lambda item: (item[0], item[1]))
    attempts: list[dict[str, str]] = []
    seen: set[tuple[int, str]] = set()
    for position, indicator, severity, source_text in candidates:
        key = (position, indicator)
        if key in seen:
            continue
        seen.add(key)
        attempts.append(
            {
                "source": sanitize(source, 100),
                "indicator": indicator,
                "excerpt": _safe_excerpt(source_text, position, position + 1),
                "severity": severity,
                "action_taken": "detected_and_ignored",
            }
        )
    return attempts


def detect_secrets(text: str, source: str) -> list[SecretHit]:
    value = str(text)
    hits: list[SecretHit] = []
    normalized_source = source.lower()
    if normalized_source.endswith("set-cookie") or normalized_source.endswith("cookie"):
        hits.append(SecretHit("cookie", source))
    if normalized_source.endswith("authorization") or normalized_source.endswith("proxy-authorization"):
        hits.append(SecretHit("authorization", source))
    for match in SENSITIVE_KEY_RE.finditer(value):
        key = _canonical_secret_key(match.group("key"))
        secret_type = SECRET_TYPE_BY_KEY.get(key, "secret")
        literal = match.group("value").strip("\"'")
        if len(literal) >= 4 and literal != "***REDACTED***":
            hits.append(SecretHit(secret_type, source))
    if BEARER_RE.search(value) or JWT_RE.search(value):
        hits.append(SecretHit("token", source))
    if COMMON_TOKEN_RE.search(value):
        hits.append(SecretHit("api_key", source))

    def visit_json(node: Any, path: str) -> None:
        if isinstance(node, Mapping):
            for key, item in node.items():
                canonical = _canonical_secret_key(key)
                if canonical in SECRET_TYPE_BY_KEY and item not in (None, "", "***REDACTED***"):
                    hits.append(SecretHit(SECRET_TYPE_BY_KEY[canonical], f"{source}.{sanitize(key, 100)}"))
                visit_json(item, f"{path}.{sanitize(key, 100)}")
        elif isinstance(node, list):
            for index, item in enumerate(node):
                visit_json(item, f"{path}[{index}]")

    for line in value.splitlines():
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        visit_json(parsed, source)
    unique: list[SecretHit] = []
    seen: set[tuple[str, str]] = set()
    for hit in hits:
        key = (hit.secret_type, hit.location)
        if key not in seen:
            seen.add(key)
            unique.append(hit)
    return unique


def _normalize_host(host: str) -> str:
    candidate = host.rstrip(".").lower()
    if not candidate:
        raise InputError("Target or scope host is empty.")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        address = None
    if address is not None:
        return address.compressed
    try:
        ascii_host = candidate.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise InputError("Target or scope host is not a valid IDN hostname.") from error
    if len(ascii_host) > 253:
        raise InputError("Hostname exceeds the DNS length limit.")
    labels = ascii_host.split(".")
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise InputError("Target or scope contains an invalid hostname label.")
    return ascii_host.lower()


def validate_target(value: str) -> NormalizedTarget:
    if not isinstance(value, str):
        raise InputError("Each target must be a URL or hostname string.")
    raw = value.strip()
    if not raw:
        raise InputError("Target must not be empty.")
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise InputError("Target must not contain control characters.")
    if "://" in raw and not re.match(r"^https?://", raw, re.IGNORECASE):
        raise InputError("Only http and https targets are supported.")
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "https://" + raw
    try:
        parts = urlsplit(raw)
        port_value = parts.port
    except ValueError as error:
        raise InputError("Target URL has an invalid host or port.") from error
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise InputError("Only http and https targets are supported.")
    if parts.username is not None or parts.password is not None:
        raise InputError("User information in target URLs is not accepted.")
    if parts.fragment:
        raise InputError("URL fragments are not sent to servers; remove the fragment.")
    if not parts.hostname:
        raise InputError("Target URL must contain a hostname.")
    host = _normalize_host(parts.hostname)
    port = port_value if port_value is not None else (443 if scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise InputError("Target port must be between 1 and 65535.")
    if parts.query:
        raise InputError("Query strings are not accepted by this low-impact profile because GET endpoints may have side effects or contain secrets.")
    display_host = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    netloc = display_host if port == default_port else f"{display_host}:{port}"
    normalized_url = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    return NormalizedTarget(normalized_url, scheme, host, port, parts.path or "/")


def parse_scope_rule(value: str) -> ScopeRule:
    if not isinstance(value, str) or not value.strip():
        raise InputError("Each scope rule must be a non-empty string.")
    raw = value.strip()
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        network = None
    if network is not None:
        return ScopeRule(network=network)
    has_scheme = "://" in raw
    wildcard = False
    candidate = raw
    if not has_scheme and candidate.startswith("*."):
        wildcard = True
        candidate = candidate[2:]
    if has_scheme:
        try:
            parts = urlsplit(candidate)
            explicit_port = parts.port
        except ValueError as error:
            raise InputError("Scope URL contains an invalid host or port.") from error
        if parts.scheme.lower() not in {"http", "https"}:
            raise InputError("Scope URL scheme must be http or https.")
        if not parts.hostname or parts.username is not None or parts.password is not None:
            raise InputError("Scope URL must contain a host and no user information.")
        if parts.query or parts.fragment:
            raise InputError("Scope URL must not contain a query or fragment.")
        host = _normalize_host(parts.hostname)
        scheme = parts.scheme.lower()
        port = explicit_port if explicit_port is not None else (443 if scheme == "https" else 80)
        path_prefix = parts.path or "/"
        if not path_prefix.startswith("/"):
            path_prefix = "/" + path_prefix
        return ScopeRule(host, wildcard, None, scheme, port, path_prefix)
    if any(char in candidate for char in "/?#@"):
        raise InputError("Bare scope rules must be hostnames, IPs, CIDRs, or *.example.com.")
    if ":" in candidate:
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError as error:
            raise InputError("Bare IPv6 scope rules must not include a port.") from error
        return ScopeRule(host=address.compressed)
    return ScopeRule(host=_normalize_host(candidate), wildcard=wildcard)


def validate_scope(target: str, scope: Sequence[str]) -> bool:
    normalized = validate_target(target)
    rules = [parse_scope_rule(rule) for rule in scope]
    return any(rule.allows(normalized) for rule in rules)


def safe_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        host = parts.hostname or ""
        port = parts.port
        safe_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        netloc = safe_host
        if port is not None and port not in {80, 443}:
            netloc = f"{netloc}:{port}"
        query_items = parse_qsl(parts.query, keep_blank_values=True)
        safe_query = "&".join(
            f"{quote(key, safe='')}=***REDACTED***" for key, _value in query_items
        )
        return sanitize(urlunsplit((parts.scheme, netloc, parts.path, safe_query, "")), 1000)
    except (ValueError, TypeError):
        return sanitize(redact(value), 1000)


def _as_string_list(value: Any, label: str, maximum: int) -> tuple[str, ...]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (list, tuple)):
        values = list(value)
    else:
        raise InputError(f"{label} must be a string or an array of strings.")
    if len(values) > maximum:
        raise InputError(f"{label} exceeds the limit of {maximum} entries.")
    cleaned: list[str] = []
    for item in values:
        if not isinstance(item, str) or not item.strip():
            raise InputError(f"Every {label} entry must be a non-empty string.")
        cleaned.append(item.strip())
    return tuple(cleaned)


def _parse_boolean(value: Any, label: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    raise InputError(f"{label} must be a boolean value.")


def _flatten_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise InputError("Configuration JSON must be an object.", "INVALID_JSON")
    allowed_root = {
        "request_id", "operation", "input", "options", "metadata", "target", "scope",
        "authorization_ref", "mode", "timeout_s", "rate_limit_rps", "max_sample_items",
        "out_dir", "proxy", "fail_on", "no_fail_on_findings", "verbose",
        "allow_third_party_sources", "enable_port_scan", "pdtm_bin_dir",
    }
    unknown = set(payload) - allowed_root
    if unknown:
        raise InputError(f"Unknown configuration field(s): {', '.join(sorted(map(str, unknown)))}")
    flattened: dict[str, Any] = {}
    simple_fields = {"request_id", "operation", "target", "scope", "authorization_ref"}
    option_fields = {
        "mode", "timeout_s", "rate_limit_rps", "max_sample_items", "out_dir", "proxy",
        "fail_on", "no_fail_on_findings", "verbose", "allow_third_party_sources",
        "enable_port_scan", "pdtm_bin_dir",
    }
    for key in simple_fields | option_fields:
        if key in payload:
            flattened[key] = payload[key]
    input_payload = payload.get("input", {})
    options_payload = payload.get("options", {})
    metadata_payload = payload.get("metadata", {})
    for label, part in (("input", input_payload), ("options", options_payload), ("metadata", metadata_payload)):
        if not isinstance(part, Mapping):
            raise InputError(f"Configuration section {label!r} must be an object.")
    input_unknown = set(input_payload) - {"target", "scope"}
    option_unknown = set(options_payload) - option_fields
    metadata_unknown = set(metadata_payload) - {"authorization_ref"}
    if input_unknown or option_unknown or metadata_unknown:
        names = sorted(map(str, input_unknown | option_unknown | metadata_unknown))
        raise InputError(f"Unknown nested configuration field(s): {', '.join(names)}")
    flattened.update(input_payload)
    flattened.update(options_payload)
    if "authorization_ref" in metadata_payload:
        flattened["authorization_ref"] = metadata_payload["authorization_ref"]
    return flattened


def _parse_env_layer(env: Mapping[str, str]) -> dict[str, Any]:
    names = {
        "RCTFC_TARGET": "target", "RCTFC_SCOPE": "scope", "RCTFC_REQUEST_ID": "request_id",
        "RCTFC_OPERATION": "operation", "RCTFC_AUTHORIZATION_REF": "authorization_ref",
        "RCTFC_MODE": "mode", "RCTFC_TIMEOUT": "timeout_s", "RCTFC_RATE": "rate_limit_rps",
        "RCTFC_MAX_SAMPLE_ITEMS": "max_sample_items", "RCTFC_OUT": "out_dir",
        "RCTFC_PROXY": "proxy", "RCTFC_FAIL_ON": "fail_on",
        "RCTFC_NO_FAIL_ON_FINDINGS": "no_fail_on_findings", "RCTFC_VERBOSE": "verbose",
        "RCTFC_ALLOW_THIRD_PARTY_SOURCES": "allow_third_party_sources",
        "RCTFC_ENABLE_PORT_SCAN": "enable_port_scan", "RCTFC_PDTM_BIN_DIR": "pdtm_bin_dir",
    }
    layer: dict[str, Any] = {}
    for env_name, field_name in names.items():
        if env_name not in env:
            continue
        value: Any = env[env_name]
        if field_name in {"target", "scope"} and value.lstrip().startswith("["):
            try:
                value = json.loads(value)
            except json.JSONDecodeError as error:
                raise InputError(f"{env_name} must be valid JSON when using array syntax.") from error
        layer[field_name] = value
    return layer


class QuietArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise InputError(message)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = QuietArgumentParser(description="Authorized, scope-bound PDTM inventory and low-impact scan orchestrator.")
    parser.add_argument("--target", action="append", default=None, help="Explicit URL/host; repeat for multiple targets.")
    parser.add_argument("--scope", action="append", default=None, help="Exact hostname, *.domain, URL path scope, IP or CIDR; repeatable.")
    parser.add_argument("--config", default=None, help="JSON config file.")
    parser.add_argument("--out", dest="out_dir", default=None, help="Output directory (default: out).")
    parser.add_argument("--timeout", dest="timeout_s", default=None, help="Per-tool timeout in seconds (1..120).")
    parser.add_argument("--rate", dest="rate_limit_rps", default=None, help="Requests per second (1..10).")
    parser.add_argument("--max-sample-items", default=None, help="Maximum samples to retain (0..100); response bodies are not saved.")
    parser.add_argument("--proxy", default=None, help="Optional HTTP(S) proxy; applied only to httpx.")
    parser.add_argument("--operation", choices=("scan", "inventory"), default=None)
    parser.add_argument("--request-id", default=None)
    parser.add_argument("--authorization-ref", default=None, help="User-supplied authorization reference; not independently verified.")
    parser.add_argument("--mode", choices=("passive", "active"), default=None, help="If omitted on a TTY, ask before scanning.")
    parser.add_argument("--fail-on", choices=FAIL_LEVELS, default=None)
    parser.add_argument("--no-fail-on-findings", action="store_true", default=None)
    parser.add_argument("--verbose", action="store_true", default=None)
    parser.add_argument("--allow-third-party-sources", action="store_true", default=None, help="Explicitly allow passive queries to external sources (subfinder).")
    parser.add_argument("--enable-port-scan", action="store_true", default=None, help="Opt in to TCP ports 80,443,8080,8443 only.")
    parser.add_argument("--pdtm-bin-dir", default=None, help="PDTM binary directory (default: ~/.pdtm/go/bin).")
    return parser


def _read_json_stream(stream: TextIO) -> dict[str, Any] | None:
    try:
        is_tty = stream.isatty()
    except (AttributeError, OSError):
        is_tty = False
    if is_tty:
        return None
    raw = stream.read(MAX_CONFIG_BYTES + 1)
    if len(raw.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise InputError("stdin JSON exceeds the configured size limit.", "INVALID_JSON")
    if not raw.strip():
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        raise InputError(f"stdin contains malformed JSON at line {error.lineno}, column {error.colno}.", "INVALID_JSON") from error
    if not isinstance(payload, Mapping):
        raise InputError("stdin JSON root must be an object.", "INVALID_JSON")
    return dict(payload)


def _load_json_file(path: str | Path) -> dict[str, Any]:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as error:
        raise InputError(f"Unable to read config file: {sanitize(path, 300)} ({error.strerror or 'I/O error'}).", "INVALID_CONFIG") from error
    if len(raw.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise InputError("Config file exceeds the configured size limit.", "INVALID_CONFIG")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as error:
        raise InputError(f"Config file contains malformed JSON at line {error.lineno}, column {error.colno}.", "INVALID_CONFIG") from error
    if not isinstance(payload, Mapping):
        raise InputError("Config file root must be an object.", "INVALID_CONFIG")
    return dict(payload)


def _convert_cli_layer(namespace: argparse.Namespace) -> dict[str, Any]:
    values = vars(namespace).copy()
    values.pop("config", None)
    return {key: value for key, value in values.items() if value is not None}


def normalize_input(
    config_payload: Mapping[str, Any] | None,
    stdin_payload: Mapping[str, Any] | None,
    env: Mapping[str, str],
    cli_payload: Mapping[str, Any] | None,
) -> ToolConfig:
    merged: dict[str, Any] = {
        "target": [], "scope": [], "request_id": "", "operation": "scan",
        "authorization_ref": "", "mode": None, "timeout_s": DEFAULT_TIMEOUT_S,
        "rate_limit_rps": DEFAULT_RATE_LIMIT_RPS, "max_sample_items": DEFAULT_MAX_SAMPLE_ITEMS,
        "out_dir": DEFAULT_OUT_DIR, "proxy": "", "fail_on": "high",
        "no_fail_on_findings": False, "verbose": False,
        "allow_third_party_sources": False, "enable_port_scan": False,
        "pdtm_bin_dir": str(Path.home() / ".pdtm" / "go" / "bin"),
    }
    layers = (
        _flatten_payload(config_payload) if config_payload is not None else {},
        _flatten_payload(stdin_payload) if stdin_payload is not None else {},
        _parse_env_layer(env),
        dict(cli_payload or {}),
    )
    for layer in layers:
        merged.update(layer)
    targets = _as_string_list(merged["target"], "target", MAX_TARGETS)
    scopes = _as_string_list(merged["scope"], "scope", MAX_SCOPE_RULES)
    operation = str(merged["operation"]).strip().lower()
    if operation not in {"scan", "inventory"}:
        raise InputError("operation must be 'scan' or 'inventory'.")
    mode_value = merged["mode"]
    mode = None if mode_value in (None, "") else str(mode_value).strip().lower()
    if mode not in {None, "passive", "active"}:
        raise InputError("mode must be passive or active.")
    authorization_ref = str(merged["authorization_ref"]).strip()
    request_id = str(merged["request_id"]).strip()
    if len(authorization_ref) > 256 or len(request_id) > 128:
        raise InputError("authorization_ref must be <=256 characters and request_id <=128 characters.")
    try:
        timeout_s = int(merged["timeout_s"])
        rate_limit_rps = int(merged["rate_limit_rps"])
        max_sample_items = int(merged["max_sample_items"])
    except (TypeError, ValueError) as error:
        raise InputError("timeout_s, rate_limit_rps, and max_sample_items must be integers.") from error
    if isinstance(merged["timeout_s"], bool) or not 1 <= timeout_s <= 120:
        raise InputError("timeout_s must be between 1 and 120 seconds.")
    if isinstance(merged["rate_limit_rps"], bool) or not 1 <= rate_limit_rps <= 10:
        raise InputError("rate_limit_rps must be between 1 and 10 requests per second.")
    if isinstance(merged["max_sample_items"], bool) or not 0 <= max_sample_items <= 100:
        raise InputError("max_sample_items must be between 0 and 100.")
    fail_on = str(merged["fail_on"]).lower()
    if fail_on not in FAIL_LEVELS:
        raise InputError("fail_on must be one of none, info, low, medium, high, critical.")
    no_fail = _parse_boolean(merged["no_fail_on_findings"], "no_fail_on_findings")
    verbose = _parse_boolean(merged["verbose"], "verbose")
    allow_third_party = _parse_boolean(merged["allow_third_party_sources"], "allow_third_party_sources")
    enable_port_scan = _parse_boolean(merged["enable_port_scan"], "enable_port_scan")
    proxy = str(merged["proxy"] or "").strip()
    if proxy:
        try:
            proxy_parts = urlsplit(proxy)
            proxy_port = proxy_parts.port
        except ValueError as error:
            raise InputError("proxy URL contains an invalid port.") from error
        if proxy_parts.scheme.lower() not in {"http", "https"} or not proxy_parts.hostname:
            raise InputError("proxy must be an absolute HTTP(S) URL.")
        if proxy_parts.username is not None or proxy_parts.password is not None:
            raise InputError("proxy credentials are not accepted on the command line.")
        if proxy_parts.query or proxy_parts.fragment:
            raise InputError("proxy URL must not contain a query or fragment.")
        proxy_host = _normalize_host(proxy_parts.hostname)
        proxy_netloc = f"[{proxy_host}]" if ":" in proxy_host else proxy_host
        if proxy_port is not None:
            proxy_netloc = f"{proxy_netloc}:{proxy_port}"
        proxy = urlunsplit((proxy_parts.scheme.lower(), proxy_netloc, "", "", ""))
    pdtm_bin_dir = Path(str(merged["pdtm_bin_dir"])).expanduser()
    out_dir = Path(str(merged["out_dir"])).expanduser()
    if operation == "scan":
        if not targets:
            raise InputError("scan requires at least one --target.")
        if not scopes:
            raise InputError("scan requires an explicit --scope; no network process will run without it.")
        if not authorization_ref:
            raise InputError("scan requires --authorization-ref as the user's authorization assertion.")
    return ToolConfig(
        targets=targets, scopes=scopes, request_id=request_id, operation=operation,
        authorization_ref=authorization_ref, mode=mode, timeout_s=timeout_s,
        rate_limit_rps=rate_limit_rps, max_sample_items=max_sample_items, out_dir=out_dir,
        proxy=proxy, fail_on=fail_on, no_fail_on_findings=no_fail, verbose=verbose,
        allow_third_party_sources=allow_third_party, enable_port_scan=enable_port_scan,
        pdtm_bin_dir=pdtm_bin_dir,
    )


def _validate_pd_executable(path: Path) -> tuple[bool, str]:
    try:
        with path.open("rb") as handle:
            signature = handle.read(4)
    except OSError:
        return False, "Executable candidate could not be inspected; it will not be run."
    if signature.startswith(b"#!"):
        return False, "Interpreter-script wrapper rejected; expected a native ProjectDiscovery executable, not a Python package entry point."
    if signature.startswith(b"MZ"):
        return True, "Native PE executable format detected; vendor identity was not cryptographically verified."
    native_signatures = {
        bytes.fromhex(value)
        for value in (
            "7f454c46", "feedface", "feedfacf", "cefaedfe",
            "cffaedfe", "cafebabe", "bebafeca", "cafebabf", "bfbafeca",
        )
    }
    if signature in native_signatures:
        return True, "Native executable format detected; vendor identity was not cryptographically verified."
    return False, "Unrecognized executable format; it will not be run without manual verification."


def discover_tools(pdtm_bin_dir: Path | None = None) -> tuple[list[dict[str, Any]], dict[str, Path], list[dict[str, str]]]:
    managed_dir = pdtm_bin_dir or (Path.home() / ".pdtm" / "go" / "bin")
    search_path = os.pathsep.join(part for part in (str(managed_dir), os.environ.get("PATH", "")) if part)
    installed: dict[str, Path] = {}
    inventory: list[dict[str, Any]] = []
    for spec in TOOL_CATALOG:
        found = shutil.which(spec.name, path=search_path)
        candidate = Path(found) if found else None
        is_valid, validation_reason = _validate_pd_executable(candidate) if candidate else (False, "Not found in PATH or the configured PDTM bin directory.")
        binary = candidate if is_valid else None
        if binary is not None:
            installed[spec.name] = binary
        inventory.append(
            {
                "name": spec.name, "category": spec.category, "mode": spec.mode,
                "risk": spec.risk, "third_party": spec.third_party,
                "installed": binary is not None,
                "path": sanitize(binary, 500) if binary else "",
                "candidate_path": sanitize(candidate, 500) if candidate else "",
                "validation_reason": validation_reason,
            }
        )
    unclassified: list[dict[str, str]] = []
    try:
        entries = sorted(managed_dir.iterdir(), key=lambda item: item.name.lower())
    except OSError:
        entries = []
    for entry in entries:
        if not entry.is_file() or not os.access(entry, os.X_OK):
            continue
        name = entry.name.removesuffix(".exe")
        if name in TOOL_SPEC_BY_NAME:
            continue
        unclassified.append(
            {
                "name": sanitize(name, 200), "path": sanitize(entry, 500),
                "decision": "unclassified_not_run",
                "reason": "Executable found in the PDTM directory but absent from the reviewed catalog.",
            }
        )
    return inventory, installed, unclassified


def build_tool_plan(
    mode: str,
    inventory: Sequence[Mapping[str, Any]],
    allow_third_party_sources: bool,
    enable_port_scan: bool,
    proxy: str = "",
) -> list[dict[str, Any]]:
    inventory_by_name = {str(item["name"]): item for item in inventory}
    installed_by_name = {name: bool(item["installed"]) for name, item in inventory_by_name.items()}
    plan: list[dict[str, Any]] = []
    for spec in TOOL_CATALOG:
        available = installed_by_name.get(spec.name, False)
        decision = "skipped"
        reason = spec.skip_reason or "Not selected by the current scan profile."
        if not available:
            decision = "not_installed"
            reason = str(
                inventory_by_name.get(spec.name, {}).get("validation_reason")
                or "Tool executable was not found in PATH or the configured PDTM bin directory."
            )
        elif spec.name == "subfinder":
            if proxy:
                reason = "Not run: subfinder is not routed through the configured httpx-only proxy profile."
            elif allow_third_party_sources:
                decision = "run"
                reason = "Explicitly allowed passive enumeration using external data sources; every result is scope-checked before further use."
            else:
                reason = "Not run: third-party passive-source queries require --allow-third-party-sources."
        elif spec.name in {"httpx", "dnsx", "tlsx"} and mode == "active":
            if proxy and spec.name != "httpx":
                reason = "Not run: this profile can apply the configured HTTP proxy to httpx only."
            else:
                decision = "run"
                reason = "Bounded active probe restricted to explicit, prevalidated in-scope targets."
        elif spec.name == "naabu" and mode == "active":
            if proxy:
                reason = "Not run: raw TCP port scans do not use the configured HTTP proxy."
            elif enable_port_scan:
                decision = "run"
                reason = f"Explicitly enabled and limited to TCP ports {SAFE_NAABU_PORTS}."
            else:
                reason = "Not run: TCP port scanning requires --enable-port-scan."
        elif spec.mode == "active" and mode == "passive":
            reason = "Not run in passive mode; it would send traffic to the target."
        elif spec.mode == "passive" and spec.name != "subfinder":
            reason = spec.skip_reason or "Not selected because it requires external sources or credentials."
        elif spec.mode == "utility":
            reason = spec.skip_reason or "Utility is not a target-facing scan module."
        plan.append({
            "tool": spec.name, "available": available, "mode": mode,
            "risk": spec.risk, "decision": decision, "reason": sanitize(reason, 500),
        })
    return plan


def _finding(index: int, title: str, severity: str, confidence: str, category: str, **values: Any) -> dict[str, Any]:
    return Finding(
        id=f"VULN-{index:03d}", title=title, severity=severity,
        confidence=confidence, category=category, **values,
    ).to_dict()


def _header_map_from_httpx(record: Mapping[str, Any]) -> dict[str, str] | None:
    raw_headers = record.get("header") or record.get("headers") or record.get("response_headers")
    if isinstance(raw_headers, Mapping):
        # httpx JSON converts response-header names to lowercase snake_case.
        return {str(key).lower().replace("_", "-"): str(value) for key, value in raw_headers.items()}
    if isinstance(raw_headers, (list, tuple)):
        lines = [str(item) for item in raw_headers]
    elif isinstance(raw_headers, str):
        lines = raw_headers.splitlines()
    else:
        return None
    headers: dict[str, str] = {}
    for line in lines:
        name, separator, value = line.partition(":")
        if separator and name.strip():
            headers[name.strip().lower()] = value.strip()
    return headers


def analyze_httpx_results(
    results: Sequence[Mapping[str, Any]],
    warnings: list[str],
    errors: list[dict[str, Any]],
    scoped_targets: Sequence[NormalizedTarget] = (),
) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    expected_targets = {
        (target.scheme, target.host, target.port, target.path, urlsplit(target.url).query)
        for target in scoped_targets
    }
    for result in results:
        if result.get("tool") != "httpx":
            continue
        tool_stdout = str(result.get("stdout", ""))
        if result.get("status") == "completed" and not tool_stdout.strip():
            _add_error(errors, "HTTPX_NO_RESULTS", "httpx completed without returning any JSONL response records; target reachability and HTTP checks remain unverified.", True)
        for line_number, line in enumerate(tool_stdout.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                _add_error(errors, "HTTPX_OUTPUT_UNEXPECTED", f"httpx output line {line_number} was not valid JSONL.", True)
                continue
            if not isinstance(record, Mapping):
                _add_error(errors, "HTTPX_OUTPUT_UNEXPECTED", f"httpx output line {line_number} was not a JSON object.", True)
                continue
            raw_url = str(record.get("url") or record.get("input") or record.get("host") or "")
            response_url = safe_url(raw_url) if raw_url else ""
            if not raw_url:
                _add_error(errors, "HTTPX_TARGET_MISSING", f"httpx JSONL line {line_number} did not identify the response target.", True)
            response_target: NormalizedTarget | None = None
            try:
                response_target = validate_target(raw_url) if raw_url else None
            except InputError:
                response_target = None
            response_key = (
                response_target.scheme,
                response_target.host,
                response_target.port,
                response_target.path,
                urlsplit(response_target.url).query,
            ) if response_target is not None else None
            scope_verified = response_key in expected_targets
            if raw_url and not scope_verified:
                warnings.append(f"httpx reported an unexpected target {response_url}; its status and headers were not used to create findings.")
            try:
                status_code = int(record.get("status_code"))
            except (TypeError, ValueError):
                status_code = None
            if status_code is None:
                _add_error(errors, "HTTPX_STATUS_UNAVAILABLE", f"httpx JSONL line {line_number} did not contain a valid status_code.", True)
            header_map = _header_map_from_httpx(record)
            content_type = str(record.get("content_type") or record.get("content-type") or "")
            missing_headers: list[str] = []
            if scope_verified and status_code is not None and 200 <= status_code < 300:
                if header_map is None:
                    warnings.append(f"httpx did not return parseable response headers for {response_url}; header checks were not performed.")
                    _add_error(errors, "HTTPX_HEADERS_UNAVAILABLE", f"Response headers were unavailable for {response_url}; their security policy could not be assessed.", True)
                else:
                    expected = ["X-Content-Type-Options", "Referrer-Policy"]
                    if urlsplit(raw_url).scheme.lower() == "https":
                        expected.append("Strict-Transport-Security")
                    if "html" in content_type.lower():
                        expected.append("Content-Security-Policy")
                    missing_headers = [name for name in expected if name.lower() not in header_map]
            elif scope_verified and status_code is not None and 300 <= status_code < 400:
                warnings.append(f"Security-header findings were deferred for redirect response {response_url}; inspect its explicitly in-scope destination separately.")
            raw_location = str(record.get("location") or (header_map or {}).get("location", ""))
            observation = {
                "url": response_url,
                "status_code": status_code,
                "redirect_location": safe_url(raw_location) if raw_location else "",
                "title": sanitize(redact(record.get("title", "")), 500),
                "webserver": sanitize(redact(record.get("webserver", "")), 200),
                "content_type": sanitize(redact(content_type), 200),
                "scope_verified": scope_verified,
                "headers_available": header_map is not None,
                "headers_present": sorted(sanitize(name, 100) for name in (header_map or {})), 
                "missing_security_headers": missing_headers,
            }
            observations.append(observation)
            if scope_verified and status_code in {401, 403}:
                _add_error(errors, "AUTH_REQUIRED" if status_code == 401 else "ACCESS_DENIED", f"httpx received HTTP {status_code} from {response_url}; no credentials were attempted.", True)
            elif scope_verified and status_code is not None and 300 <= status_code < 400:
                warnings.append(f"HTTP redirect {status_code} observed for {response_url}; redirected destinations were not followed by this wrapper.")
                _add_error(errors, "REDIRECT_NOT_FOLLOWED", f"httpx observed a redirect from {response_url}; redirect targets were not followed.", True)
            elif scope_verified and status_code is not None and status_code >= 500:
                _add_error(errors, "HTTP_SERVER_ERROR", f"httpx received HTTP {status_code} from {response_url}.", True)
    return observations


def build_findings(
    injection_attempts: Sequence[Mapping[str, str]],
    secret_hits: Sequence[SecretHit],
    targets: Sequence[str],
    http_observations: Sequence[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    index = 1
    for attempt in injection_attempts:
        asset = targets[0] if targets else "tool-output"
        findings.append(_finding(
            index,
            "Instruction-like text detected in untrusted tool output",
            "info", "informational", "llm_prompt_injection",
            asset=asset, location=attempt["source"],
            precondition="A downstream LLM or automation must consume the reported tool output.",
            description="Instruction-like text was present in untrusted output. This wrapper treated it as data and did not execute or follow it.",
            root_cause="External tool output can contain instruction-like content; detection does not prove successful prompt injection in the target application.",
            evidence=attempt["excerpt"],
            impact="A separate downstream LLM could be at risk if it treats this data as trusted instructions; this program did not test such a consumer.",
            business_impact="Potential integrity risk in downstream AI-assisted workflows; no target compromise was demonstrated.",
            reproduction=f"Review the sanitized excerpt for indicator {attempt['indicator']} in injection_attempts.",
            remediation="Keep tool output in an untrusted-data channel. If an LLM consumes it, enforce explicit data boundaries, a fixed tool allowlist, and policy checks outside the model.",
            regression_test="Add this excerpt as a fixture; assert detect_injection records it and the consuming workflow cannot change scope, suppress findings, or invoke tools from the excerpt.",
            false_positive_notes="Presence of instruction-like text alone does not prove the target application is vulnerable or that any instruction was followed.",
        ))
        index += 1
    for hit in secret_hits:
        if hit.secret_type == "cookie" and hit.location.lower().endswith(("cookie", "set-cookie")):
            continue
        asset = targets[0] if targets else "tool-output"
        findings.append(_finding(
            index,
            "Possible credential-like value in tool output",
            "low", "potential", "info_disclosure", cwe="CWE-200",
            asset=asset, location=hit.location,
            precondition="The detected value would need to be a live credential exposed to an unauthorized party.",
            description=f"A value matching a {hit.secret_type} pattern was detected. Its literal value was redacted and was not validated or replayed.",
            root_cause="A tool output contained text shaped like a credential; validity and ownership are unknown.",
            evidence=f"secret_type={hit.secret_type} detected=true location={hit.location} value=***REDACTED***",
            impact="If valid, a credential may enable unauthorized access; this scanner did not test the value.",
            business_impact="Potential account or data exposure if the value is live.",
            reproduction="Review the source location shown here without copying the redacted secret into logs or tickets.",
            remediation="Revoke and rotate the value if confirmed live, remove it from public output, and load secrets from a protected secret store.",
            regression_test="Add a dummy credential-shaped fixture; assert the output reports its type and location but never contains its literal value.",
            false_positive_notes="Could be a placeholder, example, or non-functional token. No authentication attempt was made.",
        ))
        index += 1
    for observation in http_observations:
        asset = str(observation.get("url", "")) or (targets[0] if targets else "")
        for header in observation.get("missing_security_headers", []):
            findings.append(_finding(
                index,
                f"Missing {header} response header",
                "low", "confirmed", "misconfig", cwe="CWE-693", owasp="A05:2021",
                asset=asset, location="HTTP response headers",
                precondition="A browser accesses this endpoint; severity depends on the application content and any separate vulnerability.",
                description=f"The observed HTTP response did not include the {header} header.",
                root_cause="The response configuration does not set this defense-in-depth header on the tested response.",
                evidence=f"http_status={observation.get('status_code')} header={header} present=false",
                impact="The missing header removes a browser-side defense; this observation alone does not prove exploitability.",
                business_impact="Could increase the impact of a separate client-side or transport issue.",
                reproduction=f"Repeat the authorized GET request to {asset} and inspect the response headers for {header}.",
                remediation=f"Set {header} on the web server or reverse proxy for the applicable response types; validate the value against the application requirements.",
                regression_test=f"Add an integration assertion that the response to {asset} includes a valid {header} value.",
                false_positive_notes="The httpx output must include response headers for this check; non-browser APIs may not need every browser header.",
            ))
            index += 1
    return findings


def build_recommendations(
    findings: Sequence[Mapping[str, Any]],
    plan: Sequence[Mapping[str, Any]],
    mode: str | None,
) -> list[dict[str, Any]]:
    recommendations: list[dict[str, Any]] = []
    order = {"P0": 0, "P1": 1, "P2": 2}
    for finding in findings:
        severity = str(finding["severity"])
        priority = "P0" if severity in {"critical", "high"} else "P1" if severity == "medium" else "P2"
        recommendations.append(Recommendation(
            priority, f"Remediate: {finding['title']}", str(finding["remediation"]),
            str(finding["location"] or finding["asset"]),
            f"{finding['title']}: {finding['impact']}",
            "high" if priority == "P0" else "medium" if priority == "P1" else "low",
            str(finding["regression_test"]), [str(finding["id"])],
        ).to_dict())
    existing_priorities = {item["priority"] for item in recommendations}
    if "P0" not in existing_priorities:
        recommendations.append(Recommendation(
            "P0", "Immediately triage any later-confirmed critical/high issue",
            "This bounded profile generated no critical/high remediation item. If a separate authorized review confirms one, restrict the affected exposure, apply the vendor fix or rotate affected credentials, and preserve evidence before closure.",
            "Production release and affected endpoint",
            "A limited scan cannot rule out critical/high issues; the action is conditional and does not claim that none exist.",
            "high",
            "Have the service owner review the complete findings and deferred-tool list, then record an explicit security sign-off or a linked urgent fix.",
            [],
        ).to_dict())
    if "P1" not in existing_priorities:
        recommendations.append(Recommendation(
            "P1", "Schedule medium-risk and authenticated coverage review",
            "Within one week, validate any medium-risk signals and arrange a separately authorized staging review for authentication, authorization, and business logic that this profile does not test.",
            "Application endpoints and identity flows",
            "The current profile does not exercise authenticated or workflow-specific behavior, so those risk areas remain unverified.",
            "medium",
            "Record the review scope, then retest its findings with an approved regression test suite.",
            [],
        ).to_dict())
    skipped_count = sum(1 for item in plan if item.get("decision") != "run")
    recommendations.append(Recommendation(
        "P2", "Review scan coverage and deferred PDTM tools",
        "Review tool_plan and tool_inventory. Install only required tools through PDTM, then enable them only after checking current flags, templates, network destinations, and scope behavior. Do not treat skipped tools as passed tests.",
        "PDTM toolchain and approved scan scope",
        f"Mode {mode or 'inventory'} does not exercise every ProjectDiscovery utility; {skipped_count} tools were skipped or unavailable.",
        "medium",
        "Re-run inventory, confirm each intended tool is installed and selected, then compare the resulting tool_plan with this report.",
        [],
    ).to_dict())
    recommendations.append(Recommendation(
        "P2", "Complete manual verification",
        "Use findings and sanitized tool outputs as leads for an authorized human review; add authenticated, business-logic, and application-specific checks only after separately defining credentials and test-data safeguards.",
        "Application security review",
        "The automated profile is bounded and cannot establish that a site is secure or cover all application behavior.",
        "medium",
        "Have a reviewer reproduce each candidate finding in a staging environment and document confirmed and untested areas.",
        [],
    ).to_dict())
    recommendations.sort(key=lambda item: (order[item["priority"]], item["title"]))
    return recommendations


def build_envelope(
    *, run_id: str, request_id: str, operation: str, targets: Sequence[str],
    scopes: Sequence[str], started_at: str, finished_at: str, status: str,
    data: Mapping[str, Any] | None = None,
    findings: Sequence[Mapping[str, Any]] = (),
    injection_attempts: Sequence[Mapping[str, str]] = (),
    recommendations: Sequence[Mapping[str, Any]] = (),
    artifacts: Sequence[str] = (), errors: Sequence[Mapping[str, Any]] = (),
    warnings: Sequence[Any] = (), requests_sent: int | None = 0,
    duration_s: float = 0.0, next_actions: Sequence[str] = (),
) -> dict[str, Any]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity = str(finding.get("severity", "info"))
        if severity in counts:
            counts[severity] += 1
    counts["total"] = len(findings)
    return {
        "schema_version": SCHEMA_VERSION, "tool": TOOL_NAME, "version": VERSION,
        "run_id": run_id, "request_id": request_id, "operation": operation,
        "target": list(targets), "scope": list(scopes), "started_at": started_at,
        "finished_at": finished_at, "status": status, "success": status == "ok",
        "summary": counts, "data": dict(data or {}),
        "findings": [dict(item) for item in findings],
        "injection_attempts": [dict(item) for item in injection_attempts],
        "recommendations": [dict(item) for item in recommendations],
        "artifacts": list(artifacts), "errors": [dict(item) for item in errors],
        "warnings": list(warnings),
        "metrics": {"requests_sent": requests_sent, "duration_s": round(duration_s, 3)},
        "next_actions": list(next_actions),
    }


def _plan_command(
    name: str, binary: Path, targets: Sequence[NormalizedTarget], config: ToolConfig,
) -> tuple[list[str], str | None]:
    command = [str(binary)]
    rate = str(config.rate_limit_rps)
    timeout = str(config.timeout_s)
    hosts = list(dict.fromkeys(target.host for target in targets))
    urls = list(dict.fromkeys(target.url for target in targets))
    if name == "subfinder":
        domains = [host for host in hosts if not _is_ip(host)]
        if len(domains) != 1:
            return [], "Subfinder needs exactly one explicitly scoped DNS root per process."
        command.extend(["-d", domains[0], "-silent", "-rl", rate, "-t", "1", "-timeout", timeout, "-max-time", "1", "-duc"])
    elif name == "dnsx":
        dns_hosts = [host for host in hosts if not _is_ip(host)]
        if not dns_hosts:
            return [], "DNS record checks require at least one hostname target."
        hosts = dns_hosts
        command.extend(["-silent", "-json", "-a", "-aaaa", "-cname", "-resp", "-rl", rate, "-t", "1", "-duc"])
    elif name == "httpx":
        command.extend([
            "-json", "-status-code", "-title", "-tech-detect", "-server",
            "-rate-limit", rate, "-threads", "1", "-timeout", timeout,
            "-retries", "0", "-disable-update-check", "-silent", "-no-color",
            "-omit-body", "-include-response-header", "-H", f"User-Agent: {USER_AGENT}",
        ])
        if config.proxy:
            command.extend(["-proxy", config.proxy])
    elif name == "tlsx":
        if config.proxy:
            return [], "Configured proxy mode is not supported for tlsx by this profile."
        tls_targets = [
            f"{target.host}:{target.port}" if target.port != 443 else target.host
            for target in targets
            if target.scheme == "https"
        ]
        if not tls_targets:
            return [], "TLS checks require an explicitly in-scope https target."
        command.extend([
            "-u", ",".join(dict.fromkeys(tls_targets)), "-json", "-silent", "-san", "-cn",
            "-concurrency", "1", "-timeout", timeout, "-retry", "0",
            "-disable-update-check",
        ])
    elif name == "naabu":
        if config.proxy:
            return [], "Raw TCP port scans do not use the configured HTTP proxy."
        if any(not _is_ip(host) for host in hosts):
            return [], "Port scanning is restricted to literal IP targets; hostnames may resolve to shared third-party CDN addresses."
        command.extend([
            "-host", ",".join(hosts), "-p", SAFE_NAABU_PORTS, "-rate", rate,
            "-c", "1", "-scan-type", "CONNECT", "-stream", "-duc", "-no-stdin",
            "-silent",
        ])
    else:
        return [], "No reviewed command builder exists for this utility; it is inventory-only."
    input_text = None
    if name == "dnsx":
        input_text = "\n".join(hosts) + "\n"
    elif name == "httpx":
        input_text = "\n".join(urls) + "\n"
    return command, input_text


def _safe_environment(isolated_home: Path) -> dict[str, str]:
    allowed = ("PATH", "SYSTEMROOT", "WINDIR", "LANG", "LC_ALL")
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment["HOME"] = str(isolated_home)
    environment["USERPROFILE"] = str(isolated_home)
    environment["TMPDIR"] = str(isolated_home)
    environment["TEMP"] = str(isolated_home)
    environment["TMP"] = str(isolated_home)
    return environment


def _safe_command(command: Sequence[str]) -> list[str]:
    return [
        safe_url(str(part)) if str(part).startswith(("http://", "https://"))
        else sanitize(redact(part), 1000)
        for part in command
    ]


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _add_error(errors: list[dict[str, Any]], code: str, message: str, recoverable: bool) -> None:
    errors.append({
        "code": sanitize(code, 80), "message": sanitize(redact(message), 1000),
        "recoverable": bool(recoverable),
    })


def _record_tool_text(
    text: str, source: str, attempts: list[dict[str, str]], secret_events: list[SecretHit],
    secret_seen: set[tuple[str, str]], warnings: list[str], logger: logging.Logger,
) -> None:
    attempts.extend(detect_injection(text, source))
    if re.search(r"\\u(?:200[b-f]|202[a-e]|feff)", text, re.IGNORECASE):
        def visit_text(node: Any) -> None:
            if isinstance(node, str):
                if ZERO_WIDTH_RE.search(node):
                    attempts.extend(detect_injection(node, source))
            elif isinstance(node, Mapping):
                for key, item in node.items():
                    visit_text(str(key))
                    visit_text(item)
            elif isinstance(node, list):
                for item in node:
                    visit_text(item)

        for line in text.splitlines():
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            visit_text(parsed)
    for hit in detect_secrets(text, source):
        key = (hit.secret_type, hit.location)
        if key in secret_seen:
            continue
        secret_seen.add(key)
        secret_events.append(hit)
        warning = f"secret_type={hit.secret_type} detected=true location={hit.location} value=***REDACTED***"
        warnings.append(warning)
        logger.warning(sanitize(warning, 300, single_line=True))


def _run_external_tool(
    name: str, command: Sequence[str], input_text: str | None, timeout_s: int,
    attempts: list[dict[str, str]], secret_events: list[SecretHit],
    secret_seen: set[tuple[str, str]], warnings: list[str], errors: list[dict[str, Any]],
    logger: logging.Logger, runner: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    started = time.monotonic()
    start_at = _now_utc()
    logger.info("event=tool_started tool=%s", sanitize(name, 80))
    try:
        process_kwargs: dict[str, Any] = {
            "text": True,
            "capture_output": True,
            "timeout": timeout_s,
            "check": False,
            "shell": False,
        }
        if input_text is None:
            process_kwargs["stdin"] = subprocess.DEVNULL
        else:
            process_kwargs["input"] = input_text
        with tempfile.TemporaryDirectory(prefix="rctfc-isolated-home-") as isolated_home:
            process_kwargs["env"] = _safe_environment(Path(isolated_home))
            result = runner(list(command), **process_kwargs)
        stdout_text = result.stdout or ""
        stderr_text = result.stderr or ""
        _record_tool_text(stdout_text, "tool-output.stdout", attempts, secret_events, secret_seen, warnings, logger)
        _record_tool_text(stderr_text, "tool-output.stderr", attempts, secret_events, secret_seen, warnings, logger)
        result_status = "completed" if result.returncode == 0 else "failed"
        if result.returncode != 0:
            _add_error(errors, "TOOL_EXIT_NONZERO", f"{name} exited with code {result.returncode}; see redacted stderr output.", True)
        logger.info("event=tool_finished tool=%s exit_code=%s", sanitize(name, 80), result.returncode)
        return {
            "tool": name, "status": result_status, "command": _safe_command(command),
            "started_at": start_at, "finished_at": _now_utc(),
            "exit_code": result.returncode, "timed_out": False,
            "duration_s": round(time.monotonic() - started, 3),
            "stdout": sanitize(redact_tool_output(stdout_text)), "stderr": sanitize(redact_tool_output(stderr_text)),
        }
    except subprocess.TimeoutExpired as error:
        stdout_value = error.stdout or ""
        stderr_value = error.stderr or ""
        if isinstance(stdout_value, bytes):
            stdout_value = stdout_value.decode("utf-8", errors="replace")
        if isinstance(stderr_value, bytes):
            stderr_value = stderr_value.decode("utf-8", errors="replace")
        _record_tool_text(str(stdout_value), "tool-output.stdout", attempts, secret_events, secret_seen, warnings, logger)
        _record_tool_text(str(stderr_value), "tool-output.stderr", attempts, secret_events, secret_seen, warnings, logger)
        _add_error(errors, "TOOL_TIMEOUT", f"{name} exceeded the {timeout_s}-second timeout.", True)
        logger.warning("event=tool_timeout tool=%s timeout_s=%s", sanitize(name, 80), timeout_s)
        return {
            "tool": name, "status": "timeout", "command": _safe_command(command),
            "started_at": start_at, "finished_at": _now_utc(), "exit_code": None,
            "timed_out": True, "duration_s": round(time.monotonic() - started, 3),
            "stdout": sanitize(redact_tool_output(str(stdout_value))), "stderr": sanitize(redact_tool_output(str(stderr_value))),
        }
    except (OSError, ValueError) as error:
        _add_error(errors, "TOOL_EXECUTION_ERROR", f"Unable to execute {name}: {error}", True)
        logger.error("event=tool_execution_error tool=%s error=%s", sanitize(name, 80), sanitize(redact(error), 300, single_line=True))
        return {
            "tool": name, "status": "error", "command": _safe_command(command),
            "started_at": start_at, "finished_at": _now_utc(), "exit_code": None,
            "timed_out": False, "duration_s": round(time.monotonic() - started, 3),
            "stdout": "", "stderr": sanitize(redact(error), 1000),
        }


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _decision_for_discovered_host(host: str, rules: Sequence[ScopeRule]) -> tuple[bool, str]:
    try:
        target = validate_target(host)
    except InputError as error:
        return False, sanitize(error, 300)
    if any(rule.allows(target) for rule in rules):
        return True, "host matched an explicit scope rule"
    return False, "host is outside all explicit scope rules"


def _convert_discovered_hosts(output: str, rules: Sequence[ScopeRule], warnings: list[str]) -> list[dict[str, Any]]:
    discovered: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in output.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, Mapping):
            candidate = str(parsed.get("host") or parsed.get("input") or parsed.get("domain") or "").strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        allowed, reason = _decision_for_discovered_host(candidate, rules)
        safe_candidate = sanitize(redact(candidate), 500)
        discovered.append({"host": safe_candidate, "scope_allowed": allowed, "reason": reason})
        if not allowed:
            warnings.append(f"Out-of-scope discovery recorded and not scanned: {safe_candidate}")
    return discovered


def _build_scan_data(
    config: ToolConfig, mode: str | None, inventory: Sequence[Mapping[str, Any]],
    unknown_tools: Sequence[Mapping[str, str]], plan: Sequence[Mapping[str, Any]],
    results: Sequence[Mapping[str, Any]], scope_decisions: Sequence[Mapping[str, Any]],
    discovered_hosts: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "mode": mode or "inventory",
        "scan_profile": "bounded_passive" if mode == "passive" else "bounded_active" if mode == "active" else "inventory_only",
        "authorization_ref": sanitize(redact(config.authorization_ref), 256) if config.authorization_ref else "",
        "authorization_verified": False,
        "tool_inventory": list(inventory),
        "unclassified_pdtm_executables": list(unknown_tools),
        "tool_plan": list(plan),
        "tool_results": list(results),
        "scope_decisions": list(scope_decisions),
        "discovered_hosts": list(discovered_hosts),
        "coverage": {
            "tools_executed": sum(1 for result in results if result.get("status") == "completed"),
            "tools_available": sum(1 for item in inventory if item["installed"]),
            "tools_skipped_or_unavailable": sum(1 for item in plan if item["decision"] != "run"),
            "unclassified_tools_not_run": len(unknown_tools),
            "wrapper_network_requests": 0,
            "external_tool_request_count": "unknown; PDTM tools do not expose a common request counter",
            "raw_response_bodies_saved": False,
            "max_sample_items": config.max_sample_items,
        },
        "tests_performed": [
            "PDTM executable inventory",
            "explicit target and scope validation before tool execution",
            "tool-output prompt-injection detection and secret redaction",
            "mode-specific bounded tool plan",
        ],
        "not_performed": [
            "authenticated testing",
            "destructive, denial-of-service, brute-force, or state-changing checks",
            "automatic Nuclei template execution",
            "automatic crawling",
            "comprehensive application, business-logic, or source-code review",
        ],
    }


def _status_from_run(
    operation: str, mode: str | None, plan: Sequence[Mapping[str, Any]],
    results: Sequence[Mapping[str, Any]], errors: Sequence[Mapping[str, Any]],
) -> str:
    if errors:
        completed = any(result.get("status") == "completed" for result in results)
        return "partial" if completed else "error"
    if operation == "inventory":
        return "ok"
    if mode == "passive":
        success = any(result.get("tool") == "subfinder" and result.get("status") == "completed" for result in results)
        return "ok" if success else "partial"
    required = {"dnsx", "httpx", "tlsx"}
    completed_names = {result.get("tool") for result in results if result.get("status") == "completed"}
    if not required.issubset(completed_names):
        return "partial"
    return "ok"


def run_task(
    config: ToolConfig, run_id: str, started_at: str, logger: logging.Logger,
    runner: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    task_started = time.monotonic()
    errors: list[dict[str, Any]] = []
    warnings: list[str] = []
    attempts: list[dict[str, str]] = []
    secrets: list[SecretHit] = []
    secret_seen: set[tuple[str, str]] = set()
    scope_decisions: list[dict[str, Any]] = []
    discovered_hosts: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    inventory, installed, unknown = discover_tools(config.pdtm_bin_dir)
    if config.operation == "inventory":
        plan = build_tool_plan("passive", inventory, False, False, config.proxy)
        data = _build_scan_data(config, None, inventory, unknown, plan, results, scope_decisions, discovered_hosts)
        recommendations = build_recommendations([], plan, None)
        return build_envelope(
            run_id=run_id, request_id=config.request_id, operation="inventory",
            targets=[], scopes=[], started_at=started_at, finished_at=_now_utc(),
            status="ok", data=data, recommendations=recommendations,
            requests_sent=0, duration_s=time.monotonic() - task_started,
            next_actions=[item["action"] for item in recommendations],
        )
    if config.mode not in {"passive", "active"}:
        raise InputError("mode must be selected before scanning.")
    targets = [validate_target(value) for value in config.targets]
    rules = [parse_scope_rule(value) for value in config.scopes]
    for target in targets:
        allowed = any(rule.allows(target) for rule in rules)
        scope_decisions.append({
            "target": target.display_url, "allowed": allowed,
            "reason": "matched explicit scope rule" if allowed else "outside all explicit scope rules",
        })
        if not allowed:
            logger.warning("event=scope_refused host=%s", target.host)
            _add_error(errors, "SCOPE_VIOLATION", f"Target {target.display_url} is outside the declared scope; no scan process was started.", False)
    plan = build_tool_plan(config.mode, inventory, config.allow_third_party_sources, config.enable_port_scan, config.proxy)
    if errors:
        data = _build_scan_data(config, config.mode, inventory, unknown, plan, results, scope_decisions, discovered_hosts)
        recommendations = build_recommendations([], plan, config.mode)
        return build_envelope(
            run_id=run_id, request_id=config.request_id, operation=config.operation,
            targets=[target.display_url for target in targets],
            scopes=[sanitize(redact(scope), 500) for scope in config.scopes],
            started_at=started_at, finished_at=_now_utc(), status="refused",
            data=data, recommendations=recommendations, errors=errors,
            requests_sent=0, duration_s=time.monotonic() - task_started,
            next_actions=[item["action"] for item in recommendations],
        )

    logger.info("event=scan_started mode=%s target_count=%d", config.mode, len(targets))
    for target in targets:
        logger.info("event=scope_checked host=%s allowed=true", target.host)

    subfinder_plan = next((item for item in plan if item["tool"] == "subfinder"), None)
    if subfinder_plan and subfinder_plan["decision"] == "run":
        binary = installed.get("subfinder")
        domains = _parse_domains(targets)
        for domain in domains:
            root = validate_target(domain)
            if not any(rule.allows(root) for rule in rules):
                warnings.append(f"Subfinder root {sanitize(domain, 255)} did not match scope and was not queried.")
                continue
            command, _unused = _plan_command("subfinder", binary, [root], config) if binary else ([], None)
            if not command:
                warnings.append("subfinder could not be planned because no approved DNS hostname was available.")
                continue
            result = _run_external_tool(
                "subfinder", command, None, config.timeout_s, attempts, secrets,
                secret_seen, warnings, errors, logger, runner,
            )
            results.append(result)
            discovered_hosts.extend(_convert_discovered_hosts(result["stdout"], rules, warnings))

    scan_targets = list(targets)
    if config.mode == "active":
        for item in plan:
            if item["decision"] != "run" or item["tool"] == "subfinder":
                continue
            name = str(item["tool"])
            binary = installed.get(name)
            if binary is None:
                warnings.append(f"{name} was planned but its executable disappeared before execution.")
                continue
            command, input_text = _plan_command(name, binary, scan_targets, config)
            if not command:
                reason = input_text or "no reviewed command available"
                item["decision"] = "skipped"
                item["reason"] = sanitize(reason, 500)
                warnings.append(f"{name} not run: {reason}")
                continue
            results.append(_run_external_tool(
                name, command, input_text, config.timeout_s, attempts, secrets,
                secret_seen, warnings, errors, logger, runner,
            ))

    if config.mode == "passive" and not any(result["tool"] == "subfinder" for result in results):
        warnings.append("Passive mode made no direct requests to the target; third-party enumeration was not enabled or unavailable.")
    warnings.extend(
        f"Tool {item['tool']} not run: {item['reason']}"
        for item in plan if item["decision"] != "run"
    )
    http_observations = analyze_httpx_results(results, warnings, errors, scan_targets)
    findings = build_findings(
        attempts,
        secrets,
        [target.display_url for target in targets],
        http_observations,
    )
    recommendations = build_recommendations(findings, plan, config.mode)
    status = _status_from_run(config.operation, config.mode, plan, results, errors)
    if any(item["decision"] != "run" for item in plan) and status == "ok":
        status = "partial"
    for warning in warnings:
        logger.warning("event=scan_warning message=%s", sanitize(redact(warning), 300, single_line=True))
    data = _build_scan_data(config, config.mode, inventory, unknown, plan, results, scope_decisions, discovered_hosts)
    data["http_observations"] = http_observations
    sample_limit = config.max_sample_items
    data["samples"] = {
        "limit_per_type": sample_limit,
        "http_observations": http_observations[:sample_limit],
        "discovered_hosts": list(discovered_hosts[:sample_limit]),
        "omitted_counts": {
            "http_observations": max(0, len(http_observations) - sample_limit),
            "discovered_hosts": max(0, len(discovered_hosts) - sample_limit),
        },
    }
    return build_envelope(
        run_id=run_id, request_id=config.request_id, operation=config.operation,
        targets=[target.display_url for target in targets],
        scopes=[sanitize(redact(scope), 500) for scope in config.scopes],
        started_at=started_at, finished_at=_now_utc(), status=status, data=data,
        findings=findings, injection_attempts=attempts, recommendations=recommendations,
        errors=errors, warnings=warnings, requests_sent=None,
        duration_s=time.monotonic() - task_started,
        next_actions=[item["action"] for item in recommendations],
    )


def _parse_domains(targets: Sequence[NormalizedTarget]) -> list[str]:
    return list(dict.fromkeys(target.host for target in targets if not _is_ip(target.host)))


def _recommendation_markdown(recommendations: Sequence[Mapping[str, Any]]) -> str:
    lines = ["# Remediation plan", ""]
    for item in recommendations:
        lines.extend([
            f"## {item['priority']} — {sanitize(item['title'])}", "",
            f"- **Action:** {sanitize(item['action'])}",
            f"- **Target:** {sanitize(item['target'])}",
            f"- **Rationale:** {sanitize(item['rationale'])}",
            f"- **Effort:** {sanitize(item['effort'])}",
            f"- **Verification:** {sanitize(item['verification'])}",
            f"- **Related findings:** {', '.join(map(str, item['related_findings'])) or 'None'}", "",
        ])
    return "\n".join(lines)


def _csv_cell(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (list, dict)) else str(value if value is not None else "")
    text = sanitize(redact(text))
    return "'" + text if text.startswith(("=", "+", "-", "@", "\t")) else text


def _write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as write_error:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError as cleanup_error:
                raise OSError(
                    f"Artifact write failed ({write_error.strerror or 'I/O error'}); "
                    f"temporary-file cleanup also failed ({cleanup_error.strerror or 'I/O error'})."
                ) from cleanup_error
        raise


def _artifact_payloads(envelope: Mapping[str, Any]) -> dict[str, str]:
    json_pretty = json.dumps(envelope, ensure_ascii=False, indent=2) + "\n"
    json_line = json.dumps(envelope, ensure_ascii=False, separators=(",", ":")) + "\n"
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=FINDING_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for finding in envelope["findings"]:
        writer.writerow({key: _csv_cell(finding.get(key, "")) for key in FINDING_FIELDS})
    return {
        "report.json": json_pretty,
        "report.jsonl": json_line,
        "findings.csv": output.getvalue(),
        "recommendations.md": _recommendation_markdown(envelope["recommendations"]),
    }


def emit(envelope: dict[str, Any], out_dir: Path, logger: logging.Logger) -> dict[str, Any]:
    run_dir = out_dir / envelope["run_id"]
    names = ("report.json", "report.jsonl", "findings.csv", "recommendations.md")
    paths = {name: run_dir / name for name in names}
    envelope["artifacts"] = [sanitize(paths[name], 1000) for name in names]
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        _add_error(envelope["errors"], "ARTIFACT_WRITE_FAILED", f"Unable to create report directory: {error.strerror or 'I/O error'}.", True)
        if envelope["status"] == "ok":
            envelope["status"] = "partial"
            envelope["success"] = False
        envelope["artifacts"] = []
        logger.error("event=artifact_write_failed artifact_directory=true")
        return envelope
    successful: list[str] = []
    failed: list[str] = []
    payloads = _artifact_payloads(envelope)
    for name in ("report.jsonl", "findings.csv", "recommendations.md"):
        try:
            _write_atomic(paths[name], payloads[name])
            successful.append(name)
        except OSError as error:
            failed.append(name)
            _add_error(envelope["errors"], "ARTIFACT_WRITE_FAILED", f"Unable to write {name}: {error.strerror or 'I/O error'}.", True)
            logger.error("event=artifact_write_failed artifact=%s", name)
    if failed:
        if envelope["status"] == "ok":
            envelope["status"] = "partial"
            envelope["success"] = False
        envelope["artifacts"] = [sanitize(paths[name], 1000) for name in successful] + [sanitize(paths["report.json"], 1000)]
        payloads = _artifact_payloads(envelope)
        retained: list[str] = []
        for name in successful:
            try:
                _write_atomic(paths[name], payloads[name])
                retained.append(name)
            except OSError as error:
                _add_error(envelope["errors"], "ARTIFACT_WRITE_FAILED", f"Unable to finalize {name}: {error.strerror or 'I/O error'}.", True)
                logger.error("event=artifact_finalize_failed artifact=%s", name)
        successful = retained
    envelope["artifacts"] = [sanitize(paths[name], 1000) for name in successful] + [sanitize(paths["report.json"], 1000)]
    try:
        final_report = _artifact_payloads(envelope)["report.json"]
        _write_atomic(paths["report.json"], final_report)
    except OSError as error:
        envelope["artifacts"] = [sanitize(paths[name], 1000) for name in successful]
        _add_error(envelope["errors"], "ARTIFACT_WRITE_FAILED", f"Unable to write report.json: {error.strerror or 'I/O error'}.", True)
        if envelope["status"] == "ok":
            envelope["status"] = "partial"
            envelope["success"] = False
        logger.error("event=artifact_write_failed artifact=report.json")
    return envelope


def _validate_envelope(envelope: Mapping[str, Any]) -> None:
    if tuple(envelope.keys()) != ENVELOPE_FIELDS:
        raise ValueError("Envelope fields do not match schema 2.2 ordering.")
    if any(tuple(item.keys()) != FINDING_FIELDS for item in envelope["findings"]):
        raise ValueError("A finding does not match schema 2.2.")
    if any(tuple(item.keys()) != INJECTION_FIELDS for item in envelope["injection_attempts"]):
        raise ValueError("An injection attempt does not match schema 2.2.")
    if any(tuple(item.keys()) != RECOMMENDATION_FIELDS for item in envelope["recommendations"]):
        raise ValueError("A recommendation does not match schema 2.2.")
    if envelope["success"] != (envelope["status"] == "ok"):
        raise ValueError("success must be true exactly when status is ok.")


def _fail_threshold_reached(envelope: Mapping[str, Any], config: ToolConfig) -> bool:
    if config.no_fail_on_findings or config.fail_on == "none":
        return False
    threshold = FAIL_RANK[config.fail_on]
    return any(
        finding["severity"] in FAIL_RANK and FAIL_RANK[finding["severity"]] >= threshold
        for finding in envelope["findings"]
    )


def _exit_code(envelope: Mapping[str, Any], config: ToolConfig) -> int:
    if envelope["status"] == "refused":
        return 3
    if envelope["status"] == "error":
        code = envelope["errors"][0]["code"] if envelope["errors"] else ""
        return 2 if code.startswith("INVALID") else 1
    if envelope["status"] == "partial":
        return 1
    return 10 if _fail_threshold_reached(envelope, config) else 0


def _interactive_mode(stdin: TextIO, stderr: TextIO) -> str:
    print("اختر مستوى الفحص قبل أي اتصال بالهدف: passive أو active", file=stderr)
    print("passive = لا فحص مباشر للهدف؛ active = طلبات محدودة للأدوات الآمنة المختارة.", file=stderr)
    print("اكتب passive أو active: ", end="", file=stderr, flush=True)
    choice = stdin.readline().strip().lower()
    if choice not in {"passive", "active"}:
        raise InputError("A valid passive/active choice is required before scanning.")
    return choice


def _recursive_sanitize(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize(redact(value))
    if isinstance(value, list):
        return [_recursive_sanitize(item) for item in value]
    if isinstance(value, tuple):
        return [_recursive_sanitize(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): _recursive_sanitize(item) for key, item in value.items()}
    return value


def _minimal_error_envelope(run_id: str, started_at: str, error: Exception) -> dict[str, Any]:
    code = error.code if isinstance(error, InputError) else "UNEXPECTED_ERROR"
    recommendations = build_recommendations([], [], None)
    return build_envelope(
        run_id=run_id, request_id="", operation="scan", targets=[], scopes=[],
        started_at=started_at, finished_at=_now_utc(), status="error", data={},
        recommendations=recommendations,
        errors=[{"code": code, "message": sanitize(redact(error), 1000), "recoverable": False}],
        next_actions=[item["action"] for item in recommendations],
    )


def main(
    argv: Sequence[str] | None = None, *, stdin: TextIO | None = None,
    stdout: TextIO | None = None, stderr: TextIO | None = None,
    env: Mapping[str, str] | None = None,
    runner: Callable[..., Any] = subprocess.run,
) -> int:
    input_stream = stdin if stdin is not None else sys.stdin
    output_stream = stdout if stdout is not None else sys.stdout
    error_stream = stderr if stderr is not None else sys.stderr
    environment = env if env is not None else os.environ
    started_at = _now_utc()
    run_id = str(uuid.uuid4())
    logger = setup_logging(False, error_stream)
    config: ToolConfig | None = None
    caught_error: Exception | None = None
    try:
        parser = build_argument_parser()
        namespace = parser.parse_args(list(argv) if argv is not None else None)
        config_payload = _load_json_file(namespace.config) if namespace.config else None
        stdin_payload = _read_json_stream(input_stream)
        config = normalize_input(config_payload, stdin_payload, environment, _convert_cli_layer(namespace))
        logger = setup_logging(config.verbose, error_stream)
        if config.operation == "scan" and config.mode is None:
            try:
                is_tty = input_stream.isatty()
            except (AttributeError, OSError):
                is_tty = False
            if not is_tty:
                raise InputError("Choose --mode passive or --mode active before scanning in non-interactive mode.")
            config = ToolConfig(**{**asdict(config), "mode": _interactive_mode(input_stream, error_stream)})
        envelope = run_task(config, run_id, started_at, logger, runner)
        envelope = emit(envelope, config.out_dir, logger)
        envelope = _recursive_sanitize(envelope)
        _validate_envelope(envelope)
        print(json.dumps(envelope, ensure_ascii=False, separators=(",", ":")), file=output_stream)
        return _exit_code(envelope, config)
    except SystemExit as exit_request:
        if exit_request.code == 0:
            return 0
        caught_error = InputError("Invalid command-line arguments.")
    except (InputError, OSError, ValueError) as error:
        logger.error("event=request_refused reason=%s", sanitize(redact(error), 300, single_line=True))
        caught_error = error if isinstance(error, (InputError, ValueError)) else InputError("A file or process operation failed.", "RUNTIME_ERROR")
    except Exception as error:
        logger.error("event=unexpected_error error=%s", sanitize(redact(error), 300, single_line=True))
        caught_error = InputError(f"Unexpected execution error: {sanitize(redact(error), 500)}", "UNEXPECTED_ERROR")
    if caught_error is None:
        caught_error = InputError("Unknown execution error.", "UNEXPECTED_ERROR")
    error_envelope = _minimal_error_envelope(run_id, started_at, caught_error)
    out_dir = config.out_dir if config is not None else Path(DEFAULT_OUT_DIR)
    error_envelope = emit(error_envelope, out_dir, logger)
    error_envelope = _recursive_sanitize(error_envelope)
    print(json.dumps(error_envelope, ensure_ascii=False, separators=(",", ":")), file=output_stream)
    if isinstance(caught_error, InputError) and caught_error.code == "SCOPE_VIOLATION":
        return 3
    return 2 if isinstance(caught_error, InputError) and caught_error.code.startswith("INVALID") else 1


if __name__ == "__main__":
    raise SystemExit(main())
