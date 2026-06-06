"""NetBIOS Name Service (NBNS) node-status query over UDP/137.

A second, Windows-flavoured way to find hosts that drop TCP and ICMP. Many
Windows machines keep NetBIOS-over-TCP/IP enabled and answer a *node status*
request on UDP/137 even when every TCP port is firewalled, leaking their
computer name and adapter MAC. It is a plain UDP datagram — no raw sockets,
no admin rights.

Wire format follows RFC 1002 §4.2.12 (NODE STATUS REQUEST/RESPONSE) with the
half-ASCII name encoding from RFC 1001 §4.1.
"""

from __future__ import annotations

import asyncio
import logging
import struct

logger = logging.getLogger(__name__)

NBNS_PORT = 137

# NODE STATUS REQUEST for the wildcard name "*". The NetBIOS wildcard name
# is 0x2A followed by 15 NUL bytes; under the half-ASCII scheme that encodes
# to "CK" + "AA" * 15 (32 bytes).
_WILDCARD_ENCODED = b"CK" + b"AA" * 15
NODE_STATUS_QUERY = (
    struct.pack(">H", 0x4146)  # Transaction ID (arbitrary)
    + struct.pack(">H", 0x0000)  # Flags: standard query
    + struct.pack(">HHHH", 1, 0, 0, 0)  # QDCOUNT=1, AN=NS=AR=0
    + bytes([0x20])  # encoded-name length (32)
    + _WILDCARD_ENCODED
    + bytes([0x00])  # name terminator
    + struct.pack(">H", 0x0021)  # QTYPE = NBSTAT
    + struct.pack(">H", 0x0001)  # QCLASS = IN
)

# Offset of the "number of names" byte in a standard response:
# header(12) + answer name(34) + type(2) + class(2) + ttl(4) + rdlength(2).
_NUM_NAMES_OFFSET = 56
_NAME_ENTRY_SIZE = 18  # 15-byte name + 1-byte suffix + 2-byte flags


def _decode_netbios_name(raw: bytes) -> str:
    """Trim padding/control bytes off a 15-byte NetBIOS name field."""

    return raw.decode("ascii", errors="replace").strip().strip("\x00").strip()


def parse_nbstat_response(data: bytes) -> tuple[str | None, str | None]:
    """Extract ``(computer_name, mac)`` from a NODE STATUS RESPONSE.

    The computer name is the first UNIQUE name in the table (the workstation
    or server entry); the MAC is the 6-byte adapter address that follows the
    name list. Returns ``(None, None)`` for a payload that is too short or
    does not match the standard layout — parsing is best-effort and never
    raises.
    """

    if len(data) <= _NUM_NAMES_OFFSET:
        return None, None
    num_names = data[_NUM_NAMES_OFFSET]
    offset = _NUM_NAMES_OFFSET + 1
    name: str | None = None
    for _ in range(num_names):
        if offset + _NAME_ENTRY_SIZE > len(data):
            break
        raw_name = data[offset : offset + 15]
        suffix = data[offset + 15]
        flags = struct.unpack(">H", data[offset + 16 : offset + 18])[0]
        is_group = bool(flags & 0x8000)
        decoded = _decode_netbios_name(raw_name)
        # First unique workstation (suffix 0x00) or server (0x20) name wins.
        if name is None and not is_group and suffix in (0x00, 0x20) and decoded:
            name = decoded
        offset += _NAME_ENTRY_SIZE
    mac: str | None = None
    if offset + 6 <= len(data):
        mac_bytes = data[offset : offset + 6]
        if mac_bytes != b"\x00" * 6:
            mac = ":".join(f"{b:02x}" for b in mac_bytes)
    return name, mac


class _NbnsProtocol(asyncio.DatagramProtocol):
    """Resolves a future with the first datagram received from the peer."""

    def __init__(self, future: "asyncio.Future[bytes]") -> None:
        self._future = future

    def datagram_received(self, data: bytes, addr: object) -> None:
        if not self._future.done():
            self._future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self._future.done():
            self._future.set_exception(exc)


async def nbns_query(ip: str, timeout: float = 1.0) -> tuple[str | None, str | None]:
    """Send a node-status request to ``ip`` and parse the reply.

    Returns ``(name, mac)``; ``(None, None)`` when the host stays silent — a
    non-responding host is the common case, not an error, so this never
    raises.
    """

    loop = asyncio.get_running_loop()
    future: asyncio.Future[bytes] = loop.create_future()
    transport: asyncio.DatagramTransport | None = None
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _NbnsProtocol(future), remote_addr=(ip, NBNS_PORT)
        )
        transport.sendto(NODE_STATUS_QUERY)
        data = await asyncio.wait_for(future, timeout=timeout)
    except (asyncio.TimeoutError, OSError) as exc:
        logger.debug("nbns query to %s failed: %s", ip, exc)
        return None, None
    finally:
        if transport is not None:
            transport.close()
    return parse_nbstat_response(data)
