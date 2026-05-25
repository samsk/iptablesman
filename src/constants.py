"""Literals and compiled patterns only."""

from __future__ import annotations

import re

SCRIPT_NAME = "iptablesman.py"
SYSLOG_PROCNAME = b"iptablesman.py"

DEFAULT_IPTABLES = "/usr/sbin/iptables"
DEFAULT_INTERVAL = 15
DEFAULT_LOCK_FILE = "/run/iptablesman.lock"

# Drop-in filename / @name id (iptables comment segment)
BASENAME_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")

# Table / chain directory names and CLI args
TABLE_CHAIN_RE = re.compile(r"^[A-Za-z0-9_-]{1,30}$")

# Shell metacharacters rejected in rule tokens
METACHAR_CHARS = frozenset(';|&$()`<>\n\x00')

DIR_GONE_ALERT_INTERVAL_SEC = 300.0

# Per-target daemon: full traceback at most this often
SYNC_FAILURE_LOG_INTERVAL_SEC = 300.0
