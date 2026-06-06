"""Unit tests for CLI argument parsing and config assembly."""

from __future__ import annotations

import argparse

import pytest

from cli import _build_config, _build_parser, _expand_targets, _parse_ports, _wants


def test_expand_single_ip():
    assert _expand_targets("192.168.1.10") == ["192.168.1.10"]


def test_expand_last_octet_range():
    assert _expand_targets("192.168.1.1-3") == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]


def test_expand_cidr_excludes_network_and_broadcast():
    # /30 → 4 addresses, only .1 and .2 are usable hosts.
    assert _expand_targets("192.168.1.0/30") == ["192.168.1.1", "192.168.1.2"]


def test_expand_inverted_range_rejected():
    with pytest.raises(argparse.ArgumentTypeError):
        _expand_targets("10.0.0.5-2")


def test_expand_invalid_ip_rejected():
    with pytest.raises(ValueError):
        _expand_targets("999.1.1.1")


def test_parse_ports_keywords_and_lists():
    assert 22 in _parse_ports("top100")
    assert _parse_ports("443,22,80") == [22, 80, 443]
    assert _parse_ports("8000-8002") == [8000, 8001, 8002]


def test_parse_ports_out_of_range_rejected():
    with pytest.raises(argparse.ArgumentTypeError):
        _parse_ports("70000")


def test_build_config_defaults_enable_firewall_discovery():
    args = _build_parser().parse_args(["--target", "127.0.0.1"])
    config = _build_config(args)
    assert config.use_arp is True
    assert config.use_nbns is True
    assert config.enable_cve is True


def test_build_config_honours_discovery_flags():
    args = _build_parser().parse_args(
        ["--target", "127.0.0.1", "--no-arp", "--no-nbns", "--no-cve"]
    )
    config = _build_config(args)
    assert config.use_arp is False
    assert config.use_nbns is False
    assert config.enable_cve is False


def test_build_config_profile_sets_ports_and_timeout():
    args = _build_parser().parse_args(["--target", "127.0.0.1", "--profile", "full"])
    config = _build_config(args)
    assert len(config.ports) > 100  # top1000 list
    assert config.timeout == 2.0


def test_wants_output_selection():
    assert _wants("all", "html") is True
    assert _wants("both", "json") is True
    assert _wants("both", "html") is False
    assert _wants("terminal", "json") is False
    assert _wants("html", "html") is True
