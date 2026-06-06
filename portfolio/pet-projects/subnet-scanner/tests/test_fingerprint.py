"""Unit tests for the banner classifier."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from core.fingerprint import classify_banner, fingerprint
from core.models import Host, OpenPort


def test_ssh_banner_parses_version():
    """Standard OpenSSH banner → name=ssh, version=full software string."""

    info = classify_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
    assert info.name == "ssh"
    assert info.version == "OpenSSH_8.9p1"


def test_ssh1_banner_parses_version():
    """SSH-1.x banners are also recognized."""

    info = classify_banner("SSH-1.99-OpenSSH_4.3p2\r\n")
    assert info.name == "ssh"
    assert info.version == "OpenSSH_4.3p2"


def test_http_banner_extracts_server_header():
    """HTTP response with a Server header → name=http, version=server string."""

    banner = (
        "HTTP/1.1 200 OK\r\n"
        "Date: Tue, 14 Jan 2025 12:00:00 GMT\r\n"
        "Server: nginx/1.18.0 (Ubuntu)\r\n"
        "Content-Type: text/html\r\n\r\n<html>"
    )
    info = classify_banner(banner)
    assert info.name == "http"
    assert info.version is not None and "nginx" in info.version


def test_http_without_server_header():
    """HTTP with no Server header → name=http, version=None."""

    banner = "HTTP/1.0 404 Not Found\r\nContent-Type: text/html\r\n\r\n"
    info = classify_banner(banner)
    assert info.name == "http"
    assert info.version is None


def test_ftp_banner_classified():
    """Standard FTP greeting → name=ftp."""

    info = classify_banner("220 ProFTPD 1.3.5e Server (Debian) [::ffff:127.0.0.1]\r\n")
    assert info.name == "ftp"


def test_smtp_banner_classified():
    """SMTP greeting → name=smtp."""

    info = classify_banner("220 mail.corp.lan ESMTP Postfix\r\n")
    assert info.name == "smtp"


def test_mysql_handshake_parsed():
    """MySQL initial handshake → name=mysql, version=protocol version string."""

    handshake = "J\x00\x00\x00\x0a5.7.42-log\x00\x10\x00\x00\x00"
    info = classify_banner(handshake)
    assert info.name == "mysql"
    assert info.version is not None and info.version.startswith("5.7")


def test_unknown_banner_falls_back():
    """Banner that matches no signature returns name=unknown but keeps raw text."""

    info = classify_banner("xX_random_garbage_Xx\r\nsecond line\r\n")
    assert info.name == "unknown"
    assert info.version is None
    assert "random_garbage" in info.raw_banner


def test_empty_banner_handled():
    """Empty input does not raise and yields name=unknown."""

    info = classify_banner("")
    assert info.name == "unknown"
    assert info.version is None


def test_raw_banner_preserved_for_classified_service():
    """The original banner is always stored verbatim for downstream consumers."""

    src = "SSH-2.0-OpenSSH_9.0\r\n"
    info = classify_banner(src)
    assert info.raw_banner == src


def test_smb2_response_identifies_dialect():
    """SMB2 NEGOTIATE response → name=smb, version=human dialect label."""

    netbios = b"\x00\x00\x00\x70"
    smb2_header = (
        b"\xfeSMB"
        + b"\x40\x00"
        + b"\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00"
        + b"\x01\x00"
        + b"\x01\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00\x00\x00\x00\x00"
        + b"\x00" * 16
    )
    # Negotiate response body: StructureSize (65 = 0x41), SecurityMode, DialectRevision = 0x0311
    body = b"\x41\x00" + b"\x01\x00" + b"\x11\x03" + b"\x00" * 50
    banner = (netbios + smb2_header + body).decode("latin-1", errors="replace")

    info = classify_banner(banner, port=445)
    assert info.name == "smb"
    assert info.version == "SMB 3.1.1"


def test_smb2_response_falls_back_to_hex_for_unknown_dialect():
    """Unknown SMB dialects still classify as smb with a hex-formatted version."""

    netbios = b"\x00\x00\x00\x70"
    smb2_header = b"\xfeSMB" + b"\x00" * 60
    # DialectRevision 0x0399 — not in the lookup table.
    body = b"\x41\x00" + b"\x01\x00" + b"\x99\x03" + b"\x00" * 50
    banner = (netbios + smb2_header + body).decode("latin-1", errors="replace")
    info = classify_banner(banner, port=445)
    assert info.name == "smb"
    assert info.version is not None and "0x0399" in info.version


def test_postgresql_error_response_parsed():
    """PostgreSQL ErrorResponse with version string in payload → name=postgresql."""

    banner = (
        "E\x00\x00\x00\x6a"
        "SFATAL\x00C28P01\x00"
        "Mpassword authentication failed for user 'postgres'\x00"
        "Fauth.c\x00L334\x00RClientAuthentication\x00PostgreSQL 15.2 on x86_64\x00\x00"
    )
    info = classify_banner(banner, port=5432)
    assert info.name == "postgresql"
    assert info.version == "15.2"


def test_postgresql_auth_request_recognized():
    """PostgreSQL AuthenticationRequest still identifies the service."""

    banner = "R\x00\x00\x00\x08\x00\x00\x00\x05"  # MD5 challenge
    info = classify_banner(banner, port=5432)
    assert info.name == "postgresql"
    assert info.version == "responding"


def test_port_hint_used_when_no_banner_match():
    """Empty/garbled banner on port 135 still gets named msrpc via hint table."""

    info = classify_banner("", port=135)
    assert info.name == "msrpc"
    assert info.version is None


def test_port_hint_does_not_override_real_match():
    """A real banner match wins over the port hint table."""

    info = classify_banner("SSH-2.0-OpenSSH_9.0\r\n", port=135)
    assert info.name == "ssh"


# --- network path: fingerprint() over a mocked connection ------------------


class _FakeReader:
    def __init__(self, data: bytes) -> None:
        self._data = data

    async def read(self, _n: int) -> bytes:
        return self._data


class _FakeWriter:
    def write(self, _data: bytes) -> None:
        pass

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        pass


def _host() -> Host:
    return Host(ip="10.0.0.1", alive=True, discovered_at=datetime.now(timezone.utc))


@pytest.mark.asyncio
async def test_fingerprint_http_sends_probe_and_reads_server(monkeypatch):
    """An HTTP port gets a GET probe and the Server header is extracted."""

    async def fake_open(ip, port, *args, **kwargs):
        return _FakeReader(b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n"), _FakeWriter()

    monkeypatch.setattr("core.fingerprint.asyncio.open_connection", fake_open)
    info = await fingerprint(_host(), OpenPort(port=80), timeout=0.2)
    assert info.name == "http"
    assert info.version is not None and "nginx" in info.version


@pytest.mark.asyncio
async def test_fingerprint_plain_banner_no_probe(monkeypatch):
    """A talk-first service (SSH) is identified from its unsolicited banner."""

    async def fake_open(ip, port, *args, **kwargs):
        return _FakeReader(b"SSH-2.0-OpenSSH_8.9p1\r\n"), _FakeWriter()

    monkeypatch.setattr("core.fingerprint.asyncio.open_connection", fake_open)
    info = await fingerprint(_host(), OpenPort(port=22), timeout=0.2)
    assert info.name == "ssh"
    assert info.version == "OpenSSH_8.9p1"


@pytest.mark.asyncio
async def test_fingerprint_connection_failure_falls_back_to_port_hint(monkeypatch):
    """If the banner grab fails, the port-hint table still names the service."""

    async def fake_open(ip, port, *args, **kwargs):
        raise ConnectionRefusedError

    monkeypatch.setattr("core.fingerprint.asyncio.open_connection", fake_open)
    info = await fingerprint(_host(), OpenPort(port=139), timeout=0.1)
    assert info.name == "smb"  # 139 → port hint
    assert info.version is None
