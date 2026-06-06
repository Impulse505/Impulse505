"""Read the OS neighbour (ARP) cache to find live hosts behind firewalls.

Why this module exists
----------------------
Host discovery by TCP probe (``discovery.py``) is unreliable against a
default-configured Windows host: Windows Defender Firewall *drops* inbound
packets silently rather than rejecting them, so a closed or filtered port
is indistinguishable from a dead host — both simply time out.

ARP lives one layer below the firewall. Any host that participates in IPv4
on the local segment **must** answer ARP "who-has" requests, regardless of
its firewall policy, or it could not receive traffic at all. The moment we
*attempt* to connect to a neighbour (port scan, discovery probe — anything),
the kernel ARP-resolves its MAC before it can even send the SYN, and that
resolution succeeds even when the SYN is subsequently dropped. The live
host then sits in the local ARP cache with a real MAC address.

Reading that cache needs no raw sockets and no admin rights — we just parse
the platform's neighbour-table command:

    * Windows : ``arp -a``
    * Linux   : ``ip neigh``  (fallback: ``arp -n``)
    * macOS   : ``arp -an``

Only on-link neighbours ever get their own ARP entry; an off-subnet target
resolves to the *gateway's* MAC, never its own, so it never appears here.
That makes the lookup self-limiting to the local subnet and free of remote
false positives.
"""

from __future__ import annotations

import asyncio
import logging
import re
import sys
from typing import Awaitable, Callable

logger = logging.getLogger(__name__)

# Anchored just enough to pull a dotted IPv4 out of a noisy table row without
# also matching the digits inside a MAC (MACs are hex and contain no dots).
_IPV4 = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")
# Six 1-2 digit hex groups separated by ':' or '-' (Windows uses '-').
_MAC = re.compile(r"\b([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b")

# Linux `ip neigh` states that mean the entry has no usable MAC.
_DEAD_STATES = ("FAILED", "INCOMPLETE")

CommandRunner = Callable[[list[str]], Awaitable[str]]


def _normalize_mac(mac: str) -> str:
    """Canonicalise a MAC to lowercase colon form (``aa:bb:cc:dd:ee:ff``)."""

    return ":".join(part.lower().zfill(2) for part in re.split(r"[:-]", mac))


def _is_unicast(mac: str) -> bool:
    """Reject broadcast / multicast / all-zero MACs — not real unicast hosts."""

    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return False
    first_octet = int(mac.split(":", 1)[0], 16)
    # Bit 0 of the first octet flags group (multicast) addresses — this
    # covers IPv4 multicast (01:00:5e:...) and IPv6 (33:33:...).
    return not (first_octet & 0x01)


def parse_neighbor_table(text: str) -> dict[str, str]:
    """Parse neighbour-table command output into ``{ip: mac}``.

    Handles ``arp -a`` (Windows, dash-separated MACs), ``ip neigh`` and
    ``arp -n`` (Linux, colon MACs) and ``arp -an`` (macOS). Rows without a
    resolvable unicast MAC — interface headers, broadcast entries,
    ``FAILED``/``INCOMPLETE`` neighbours — are skipped.
    """

    table: dict[str, str] = {}
    for line in text.splitlines():
        if any(state in line for state in _DEAD_STATES):
            continue
        ip_match = _IPV4.search(line)
        mac_match = _MAC.search(line)
        if ip_match is None or mac_match is None:
            continue
        mac = _normalize_mac(mac_match.group(1))
        if not _is_unicast(mac):
            continue
        table[ip_match.group(1)] = mac
    return table


def _neighbor_command() -> list[str]:
    """Pick the neighbour-table command for the current platform."""

    if sys.platform.startswith("win"):
        return ["arp", "-a"]
    if sys.platform == "darwin":
        return ["arp", "-an"]
    return ["ip", "neigh"]


async def _run_command(argv: list[str]) -> str:
    """Run ``argv`` with no shell and return stdout decoded leniently."""

    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    return stdout.decode("utf-8", errors="replace")


async def read_neighbor_table(runner: CommandRunner | None = None) -> dict[str, str]:
    """Return the current ``{ip: mac}`` neighbour cache, or ``{}`` on failure.

    Args:
        runner: Optional async command runner injected by tests. When omitted
            the platform's neighbour-table command is executed via subprocess
            (no shell).

    Never raises: a missing command or unreadable table degrades to an empty
    mapping so discovery simply falls back to its TCP signal.
    """

    run = runner or _run_command
    argv = _neighbor_command()
    try:
        output = await run(argv)
    except FileNotFoundError:
        # `ip` is absent on some minimal Linux images — try legacy `arp`.
        if argv[0] == "ip":
            try:
                output = await run(["arp", "-n"])
            except OSError as exc:
                logger.debug("neighbour table read failed: %s", exc)
                return {}
        else:
            return {}
    except OSError as exc:
        logger.debug("neighbour table read failed: %s", exc)
        return {}
    return parse_neighbor_table(output)
