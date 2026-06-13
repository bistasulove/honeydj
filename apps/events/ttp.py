"""Regex-based TTP (tactics, techniques & procedures) classifier.

Scans the request path and body of a captured event for signatures of common
attack techniques and returns a sorted list of tags. Called from the
``enrich_event`` Celery task (architecture.md step 5); each new tag adds to an
attacker's threat score.

This is intentionally a cheap, dependency-free heuristic — it favours catching
obvious probes over precision, since the events it scans already hit a decoy.
Tags double as ATT&CK-flavoured labels shown in the admin.
"""

import re
from urllib.parse import unquote_plus

# Each entry: (tag, compiled pattern). Patterns are matched case-insensitively
# against the combined path + body text. Tags are stable identifiers — changing
# one orphans the threat score already attributed to it on existing profiles.
_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    (
        "sql_injection",
        re.compile(
            r"(\bunion\s+select\b|\bor\s+1\s*=\s*1\b|\bsleep\s*\(|\bbenchmark\s*\("
            r"|information_schema|\bwaitfor\s+delay\b|--\s|;--)",
            re.IGNORECASE,
        ),
    ),
    (
        "xss",
        re.compile(
            r"(<script\b|onerror\s*=|onload\s*=|javascript:|<img\b[^>]*\bsrc\s*=|alert\s*\()",
            re.IGNORECASE,
        ),
    ),
    (
        "path_traversal",
        re.compile(r"(\.\./|\.\.\\|%2e%2e[/\\]|/etc/passwd|\bboot\.ini\b)", re.IGNORECASE),
    ),
    (
        "command_injection",
        re.compile(
            r"(;\s*(cat|ls|id|whoami|uname|wget|curl)\b|\|\s*(sh|bash)\b|\$\(|`.*`|&&\s*\w+)",
            re.IGNORECASE,
        ),
    ),
    (
        "rce_log4shell",
        re.compile(r"\$\{jndi:(ldap|ldaps|rmi|dns)://", re.IGNORECASE),
    ),
    (
        "rce_shellshock",
        re.compile(r"\(\s*\)\s*\{\s*:;\s*\}\s*;", re.IGNORECASE),
    ),
    (
        "ssrf",
        re.compile(r"(169\.254\.169\.254|metadata\.google\.internal|file://|gopher://)", re.IGNORECASE),
    ),
    (
        "webshell_upload",
        re.compile(r"(c99\.php|r57\.php|eval\s*\(\s*base64_decode|<\?php\b|/shell\.(php|jsp|asp))", re.IGNORECASE),
    ),
    (
        "credential_access",
        re.compile(r"(\.env\b|wp-config\.php|/\.git/|id_rsa|\.aws/credentials|/\.ssh/)", re.IGNORECASE),
    ),
    (
        "scanner_tooling",
        re.compile(r"(sqlmap|nikto|nmap|masscan|nuclei|zgrab|gobuster|dirbuster|wpscan)", re.IGNORECASE),
    ),
]


def classify(path: str, body: str | None) -> list[str]:
    """Return the sorted, de-duplicated TTP tags matched in ``path`` and ``body``.

    Both the raw text and a URL-decoded copy are scanned, so payloads hidden by
    percent- or plus-encoding (``UNION%20SELECT``, ``..%2f``, ``id=1+OR+1=1``)
    are caught without losing matches that only appear in the raw form.
    """
    raw = path if not body else f"{path}\n{body}"
    decoded = unquote_plus(raw)
    haystack = raw if decoded == raw else f"{raw}\n{decoded}"
    tags = {tag for tag, pattern in _SIGNATURES if pattern.search(haystack)}
    return sorted(tags)
