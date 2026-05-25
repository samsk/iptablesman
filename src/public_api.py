"""Stable re-exports for CLI, tests, embedders (not sync cycle logic — see targets)."""

from __future__ import annotations

from src.apply import sync_file
from src.rule_tokens import (
    normalize_iptables_path,
    parse_rule_line,
    strip_user_comment_tokens,
    validate_basename,
    validate_rule_tokens,
    validate_table_or_chain,
)
from src.dropin import parse_dropin_blocks
from src.host_resolve import (
    HostIpv4Detail,
    HostResolveLogState,
    hosts_resolve_ipv4,
    substitute_host_tokens,
)
from src.owned_rules import (
    comment_owned_by_basename,
    rule_has_comment,
    rule_tag_key,
)
from src.status_cmd import (
    StatusBlock,
    cmd_list,
    cmd_status,
    collect_desired_rules,
    collect_status_blocks,
)
from src.targets import (
    SyncState,
    Target,
    discover_targets,
    explicit_target,
    list_dropin_files,
    sync_target_cycle,
)

__all__ = [
    "HostIpv4Detail",
    "HostResolveLogState",
    "StatusBlock",
    "SyncState",
    "Target",
    "cmd_list",
    "cmd_status",
    "collect_desired_rules",
    "collect_status_blocks",
    "comment_owned_by_basename",
    "discover_targets",
    "hosts_resolve_ipv4",
    "explicit_target",
    "list_dropin_files",
    "normalize_iptables_path",
    "parse_dropin_blocks",
    "parse_rule_line",
    "rule_has_comment",
    "rule_tag_key",
    "strip_user_comment_tokens",
    "substitute_host_tokens",
    "sync_file",
    "sync_target_cycle",
    "validate_basename",
    "validate_rule_tokens",
    "validate_table_or_chain",
]
