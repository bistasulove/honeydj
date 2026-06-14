"""Client fingerprinting — JA3 TLS hashes and User-Agent heuristics.

Two cheap, dependency-free signals that help the enrichment pipeline tell an
automated scanner from a browser:

* **JA3** — a hash of the TLS ClientHello (version, ciphers, extensions, curves,
  point formats). nginx computes it per-connection and forwards it in the
  ``X-JA3-Hash`` request header; we never see the raw handshake. A JA3 is tied
  to the client's *TLS library*, not the tool, so it survives a forged
  User-Agent — but it is also shared by every tool built on the same library and
  shifts between library versions. Treat a match as strong evidence, not proof.

* **User-Agent** — trivially spoofed, but most scanners leave their default UA
  in place. Useful as a fallback for tools whose JA3 is unstable or unpublished
  (masscan, nmap, sqlmap, scrapy, go-http-client).

``parse_ja3_header`` and ``classify_user_agent`` are called from the event
capture path (``apps/honeypot/decoys.py``); the JA3 lookup and a second UA pass
also run during enrichment (``apps/events/tasks.py``). See architecture.md
"JA3 fingerprinting & scanner detection".
"""

import re

from django.http import HttpRequest

# JA3 header set by nginx. Use nginx's ``$ssl_ja3_hash`` (the MD5 of the raw
# JA3 string) so the values match the published hashes in KNOWN_SCANNER_JA3.
JA3_HEADER = "X-JA3-Hash"

# Published JA3 (MD5) fingerprints of common offensive tooling.
#
# Sourced from the trisulnsm JA3 fingerprint database and Salesforce's original
# JA3 writeup (see architecture.md for links). JA3 is TLS-library- and
# version-specific, so these match the tested builds noted inline and are not
# exhaustive — they are a high-signal allowlist, deliberately conservative to
# avoid flagging a browser that happens to share a library fingerprint.
#
# Tools omitted on purpose: masscan and nmap do not complete an application TLS
# handshake by default (no stable JA3); sqlmap rides Python's ``ssl`` module so
# its JA3 collides with python-requests; scrapy's JA3 comes from Twisted/pyOpenSSL
# and is not authoritatively published. All five are caught by User-Agent below.
KNOWN_SCANNER_JA3: dict[str, str] = {
    # curl — default libcurl/OpenSSL handshakes across common builds.
    "764b8952983230b0ac23dbd3741d2bb0": "curl",
    "c458ae71119005c8bc26d38a215af68f": "curl",
    "9f198208a855994e1b8ec82c892b7d37": "curl",
    # Python Requests (urllib3/OpenSSL). sqlmap and other Python tools collide here.
    "c398c55518355639c5a866c15784f969": "python-requests",
    # Nikto web scanner (tested 2.1.6, Kali).
    "a563bb123396e545f5704a9a2d16bcb0": "nikto",
    "f4262963691a8f123d4434c7308ad7fe": "nikto",
    "5eeeafdbc41e5ca7b81c92dbefa03ab7": "nikto",
    # Metasploit auxiliary TLS scanners and the HTTP scanner module.
    "16f17c896273d1d098314a02e87dd4cb": "metasploit",
    "950ccdd64d360a7b24c70678ac116a44": "metasploit",
    "6825b330bf9de50ccc8745553cb61b2f": "metasploit",
    "ee031b874122d97ab269e0d8740be31a": "metasploit",
    # Metasploit Meterpreter payload on Linux (Salesforce JA3 reference).
    "5d65ea3fb1d4aa7d826733d2f2cbbb1d": "meterpreter",
    # zgrab — the ZMap project's TLS banner grabber (UMich scanner).
    "dc76bc3a4e3bc38939dfd90d8b7214b7": "zgrab",
}

# User-Agent substrings → tool tag. Matched case-insensitively. These are the
# default UAs the tools ship with; a forged UA simply yields no match (the JA3
# pass can still catch it). Tags are stable identifiers — renaming one orphans
# the threat score already attributed to it on existing profiles.
_UA_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("sqlmap", re.compile(r"sqlmap", re.IGNORECASE)),
    ("nikto", re.compile(r"nikto", re.IGNORECASE)),
    ("masscan", re.compile(r"masscan", re.IGNORECASE)),
    ("nmap", re.compile(r"nmap", re.IGNORECASE)),
    ("zgrab", re.compile(r"zgrab", re.IGNORECASE)),
    ("nuclei", re.compile(r"nuclei", re.IGNORECASE)),
    ("metasploit", re.compile(r"metasploit|meterpreter", re.IGNORECASE)),
    ("python-requests", re.compile(r"python-requests", re.IGNORECASE)),
    ("go-http-client", re.compile(r"go-http-client", re.IGNORECASE)),
    # Anchor curl to the version delimiter so "curl" inside a longer UA token
    # (or a browser advertising a curl-compatible mode) doesn't false-positive.
    ("curl", re.compile(r"\bcurl/", re.IGNORECASE)),
]


def parse_ja3_header(request: HttpRequest) -> str | None:
    """Return the JA3 hash nginx forwarded for this request, or ``None``.

    nginx only emits ``X-JA3-Hash`` for connections that completed a TLS
    handshake, so a plain-HTTP request (no handshake, no fingerprint) arrives
    without the header and yields ``None``. An empty header is treated the same.
    """
    value = request.headers.get(JA3_HEADER)
    return value or None


def classify_user_agent(user_agent: str) -> list[str]:
    """Return tool tags inferred from ``user_agent`` (empty list if none match).

    Tags are de-duplicated and returned in signature order. The UA is attacker-
    controlled, so a match is a hint, not proof — but most scanners never change
    their default UA, making this a cheap high-recall signal.
    """
    if not user_agent:
        return []
    return [tag for tag, pattern in _UA_SIGNATURES if pattern.search(user_agent)]
