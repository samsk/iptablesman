"""Parse drop-in file into annotated rule blocks and comment tags."""

from __future__ import annotations

import logging
from pathlib import Path

from src.annotations import (
    ParsedBlock,
    assign_comment_tags,
    build_parsed_block,
    merge_annotation_dicts,
    parse_annotation_line,
)
from src.rule_tokens import (
    parse_rule_line,
    strip_user_comment_tokens,
    validate_rule_tokens,
)

log = logging.getLogger("iptablesman")


def parse_dropin_blocks(
    file_path: Path,
    raw_lines: list[str],
) -> tuple[list[ParsedBlock], list[str], bool]:
    """
    Parse drop-in into rule blocks.
    Returns (blocks, tags, fatal_error).
    """
    blocks: list[ParsedBlock] = []
    pending: dict[str, list[str]] = {}
    pending_line = 0

    for lineno, line in enumerate(raw_lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            ad = parse_annotation_line(line)
            if not ad and stripped != "#":
                log.warning("%s:%s unknown annotation syntax, ignoring line", file_path, lineno)
            merge_annotation_dicts(pending, ad)
            if pending_line == 0:
                pending_line = lineno
            continue
        if not stripped:
            continue

        tokens = parse_rule_line(line)
        if tokens is None:
            if line.strip() and not line.strip().startswith("#"):
                log.warning("%s:%s shlex error", file_path, lineno)
            continue
        if not tokens:
            continue
        tokens = strip_user_comment_tokens(tokens)
        if not validate_rule_tokens(tokens):
            log.error("%s:%s metachar in rule", file_path, lineno)
            return [], [], True

        blocks.append(
            build_parsed_block(pending, pending_line, lineno, tokens, str(file_path))
        )
        pending = {}
        pending_line = 0

    if pending:
        log.warning("%s: trailing annotations without rule, ignored", file_path)

    tags = assign_comment_tags(file_path.name, blocks)
    return blocks, tags, False
