"""Banner grabbing and lightweight service identification.

The module mixes three strategies:

* HTTP-shaped ports get a minimal ``GET /`` so the server has something to
  reply to.
* Binary protocols that respond only after a structured request (SMB,
  PostgreSQL) get small hand-built probes — the bytes are inlined as
  constants to avoid pulling in a heavier library just to introspect a
  banner.
* Everything else relies on the service announcing itself first.

After capture the classifier scans the bytes through a flat regex / byte
table. The map stays small on purpose; CPE-grade matching belongs in the
CVE lookup stage, not here.
"""

from __future__ import annotations

import asyncio
import logging
import re
import struct
from dataclasses import dataclass
from typing import Callable

from .models import Host, OpenPort, ServiceInfo

logger = logging.getLogger(__name__)

HTTP_PORTS: frozenset[int] = frozenset({80, 81, 591, 8000, 8008, 8080, 8081, 8443, 8888, 9080})
READ_BYTES: int = 4096
READ_TIMEOUT: float = 2.0
HTTP_REQUEST: str = "GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: subnet-scanner/0.2\r\n\r\n"


# ---------------------------------------------------------------------------
# Protocol probes
# ---------------------------------------------------------------------------

# Minimal SMB2 NEGOTIATE request. The server replies with a NEGOTIATE
# response whose DialectRevision field identifies the SMB dialect (and
# therefore narrows the Windows version family).
SMB2_NEGOTIATE: bytes = (
    b"\x00\x00\x00\x6e"  # NetBIOS Session Service header (length = 110)
    b"\xfeSMB"  # SMB2 protocol identifier
    b"\x40\x00"  # StructureSize (64)
    b"\x00\x00"  # CreditCharge
    b"\x00\x00\x00\x00"  # Status (reserved on request)
    b"\x00\x00"  # Command: NEGOTIATE (0x0000)
    b"\x00\x00"  # CreditRequest
    b"\x00\x00\x00\x00"  # Flags
    b"\x00\x00\x00\x00"  # NextCommand
    b"\x00\x00\x00\x00\x00\x00\x00\x00"  # MessageId
    b"\x00\x00\x00\x00"  # Reserved
    b"\x00\x00\x00\x00"  # TreeId
    b"\x00\x00\x00\x00\x00\x00\x00\x00"  # SessionId
    + b"\x00" * 16  # Signature
    + b"\x24\x00"  # StructureSize (36) — negotiate request body
    + b"\x05\x00"  # DialectCount (5)
    + b"\x01\x00"  # SecurityMode (signing enabled)
    + b"\x00\x00"  # Reserved
    + b"\x40\x00\x00\x00"  # Capabilities (encryption)
    + b"\x00" * 16  # ClientGuid
    + b"\x00\x00\x00\x00"  # NegotiateContextOffset
    + b"\x00\x00"  # NegotiateContextCount
    + b"\x00\x00"  # Reserved2
    + b"\x02\x02"  # Dialect 2.0.2
    + b"\x10\x02"  # Dialect 2.1
    + b"\x00\x03"  # Dialect 3.0
    + b"\x02\x03"  # Dialect 3.0.2
    + b"\x11\x03"  # Dialect 3.1.1
)

# Bare-bones PostgreSQL StartupMessage (protocol version 3.0). A real
# server replies with either an AuthenticationRequest ('R') or an
# ErrorResponse ('E') containing diagnostic info we can parse. Either way
# the response confirms the service.
_POSTGRES_PARAMETERS = (
    b"user\x00postgres\x00database\x00postgres\x00client_encoding\x00UTF8\x00\x00"
)
POSTGRES_STARTUP: bytes = (
    struct.pack(">II", 4 + 4 + len(_POSTGRES_PARAMETERS), 196608) + _POSTGRES_PARAMETERS
)

_PROBES: dict[int, bytes] = {
    445: SMB2_NEGOTIATE,
    5432: POSTGRES_STARTUP,
}


# ---------------------------------------------------------------------------
# Classifier table
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Rule:
    name: str
    pattern: re.Pattern[str]
    version_group: int | None = None


_SIGNATURES: tuple[_Rule, ...] = (
    _Rule("ssh", re.compile(r"^SSH-2\.0-(\S+)", re.MULTILINE), version_group=1),
    _Rule("ssh", re.compile(r"^SSH-1\.\d+-(\S+)", re.MULTILINE), version_group=1),
    _Rule("http", re.compile(r"^HTTP/\d\.\d", re.IGNORECASE), version_group=None),
    _Rule("ftp", re.compile(r"^220[ \-].*?FTP[^\r\n]*", re.IGNORECASE), None),
    _Rule("smtp", re.compile(r"^220[ \-].*?SMTP[^\r\n]*", re.IGNORECASE), None),
    _Rule("smtp", re.compile(r"^220[ \-].*?(ESMTP|Postfix|Exim|Sendmail)", re.IGNORECASE), None),
    _Rule("mysql", re.compile(r"^.{1,3}\x00\x00\x00\x0a([0-9][0-9.\-A-Za-z]+)", re.DOTALL), 1),
    _Rule("rdp", re.compile(r"(MS-RDP|RDP|\x03\x00\x00\x13\x0e\xd0)", re.IGNORECASE), None),
    _Rule("redis", re.compile(r"-NOAUTH|\+PONG|\$\d+\r\nredis_version", re.IGNORECASE), None),
    _Rule("telnet", re.compile(r"^\xff[\xfb-\xfe]", re.DOTALL), None),
    _Rule("smb", re.compile(r"^.{4}\xfeSMB|^.{4}\xffSMB", re.DOTALL), None),
    _Rule("postgresql", re.compile(r"^[RE]\x00\x00\x00", re.DOTALL), None),
)

_HTTP_SERVER_HEADER: re.Pattern[str] = re.compile(
    r"^Server:\s*([^\r\n]+)", re.IGNORECASE | re.MULTILINE
)

# SMB2 dialect → human label. Picked up from the NEGOTIATE response.
_SMB_DIALECTS: dict[int, str] = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
    0x02FF: "SMB 2.x wildcard",
}

# Port → service hint used as a last resort when nothing was readable.
_PORT_HINTS: dict[int, str] = {
    135: "msrpc",
    137: "netbios",
    138: "netbios",
    139: "smb",
    389: "ldap",
    636: "ldaps",
    1433: "mssql",
    3389: "rdp",
    5985: "winrm-http",
    5986: "winrm-https",
}


def _extract_smb_version(banner: str) -> str | None:
    """Pull the negotiated SMB dialect out of a NEGOTIATE response."""

    raw = banner.encode("latin-1", errors="replace")
    idx = raw.find(b"\xfeSMB")
    if idx == -1:
        return None
    # DialectRevision sits at SMB2 header (64 B) + 4 B (StructureSize+SecurityMode).
    offset = idx + 64 + 4
    if offset + 2 > len(raw):
        return None
    dialect = int.from_bytes(raw[offset : offset + 2], "little")
    if dialect == 0x0000:
        # Server replied but didn't advertise a dialect at the expected
        # offset — common with Windows error replies. Treat as no version.
        return None
    return _SMB_DIALECTS.get(dialect) or f"SMB dialect 0x{dialect:04x}"


_POSTGRES_FIELD = re.compile(r"S(\w+)\x00", re.DOTALL)


def _extract_postgres_version(banner: str) -> str | None:
    """Pull a version hint out of a PostgreSQL ErrorResponse/AuthRequest."""

    if banner.startswith("R"):
        # AuthenticationRequest — no version leak, but service confirmed.
        return "responding"
    if banner.startswith("E"):
        # ErrorResponse fields are prefixed by single-byte codes. Look for
        # human-readable "PostgreSQL" or version hints in the payload.
        match = re.search(r"PostgreSQL\s+(\d+\.\d+(?:\.\d+)?)", banner)
        if match:
            return match.group(1)
        return "error response"
    return None


def _classify(banner: str, port: int | None = None) -> ServiceInfo:
    """Map a captured banner (and the port it came from) to a ServiceInfo."""

    for rule in _SIGNATURES:
        match = rule.pattern.search(banner)
        if match is None:
            continue
        version: str | None = None
        if rule.version_group is not None:
            try:
                version = match.group(rule.version_group)
                if version is not None:
                    version = version.strip() or None
            except IndexError:
                version = None
        if rule.name == "http" and version is None:
            header = _HTTP_SERVER_HEADER.search(banner)
            if header is not None:
                value = header.group(1).strip()
                version = value or None
        if rule.name == "smb" and version is None:
            version = _extract_smb_version(banner)
        if rule.name == "postgresql" and version is None:
            version = _extract_postgres_version(banner)
        return ServiceInfo(name=rule.name, version=version, raw_banner=banner)

    # Nothing matched. Fall back to port-based hints so the report at least
    # tells the operator what is likely listening.
    if port is not None and port in _PORT_HINTS:
        return ServiceInfo(name=_PORT_HINTS[port], version=None, raw_banner=banner[:80])

    snippet = banner.strip().splitlines()[0] if banner.strip() else ""
    return ServiceInfo(name="unknown", version=None, raw_banner=snippet[:80] or banner[:80])


async def _grab_banner(ip: str, port: int, timeout: float) -> str:
    """Open ``ip:port``, optionally send a probe, read up to READ_BYTES."""

    reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    try:
        probe: bytes | None = None
        if port in HTTP_PORTS:
            probe = HTTP_REQUEST.format(host=ip).encode("latin-1")
        elif port in _PROBES:
            probe = _PROBES[port]

        if probe is not None:
            writer.write(probe)
            try:
                await writer.drain()
            except (ConnectionResetError, OSError):
                pass

        try:
            data = await asyncio.wait_for(reader.read(READ_BYTES), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""
    finally:
        try:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, OSError):
                pass
        except Exception:  # noqa: BLE001 — best-effort cleanup
            pass
    return data.decode("latin-1", errors="replace")


async def fingerprint(host: Host, port: OpenPort, timeout: float = READ_TIMEOUT) -> ServiceInfo:
    """Identify the service listening on ``host:port`` from its banner.

    Args:
        host: Target host with a populated ``ip``.
        port: Open port confirmed by the scanner.
        timeout: Per-operation timeout for connect and read.

    Returns:
        ``ServiceInfo`` with ``name="unknown"`` if no signature matched and
        no port-based fallback fired. The raw banner is always preserved.
    """

    try:
        banner = await _grab_banner(host.ip, port.port, timeout)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as exc:
        logger.debug("banner grab failed for %s:%d: %s", host.ip, port.port, exc)
        # Even on failure, give the port-hint a chance.
        return _classify("", port=port.port)
    return _classify(banner, port=port.port)


def classify_banner(banner: str, port: int | None = None) -> ServiceInfo:
    """Public wrapper around the internal classifier for tests and reuse."""

    return _classify(banner, port=port)


# Exported for tests that want to drive ``_grab_banner`` indirectly.
_protocol_probe: Callable[[int], bytes | None] = _PROBES.get
