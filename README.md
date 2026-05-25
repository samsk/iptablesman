# iptablesman

Standalone daemon: syncs Linux **iptables** rules from drop-in files under `<config-dir>/<table>/<chain>/`. It does not manage UFW, fail2ban, or the whole firewall—only rules it owns via `-m comment`.

Deploy however you like (systemd unit in this tree, config management, manual copy). Paths below use common install conventions, not a specific orchestrator.

## Quick usage

Every invocation needs `--config-dir`, except `--resync`, `--version`, or one-shot actions that still require `--config-dir` for target discovery.

```bash
# Validate desired rules (no -A/-R/-D)
iptablesman.py --config-dir /usr/local/etc/iptablesman --test

# One-shot status
iptablesman.py --config-dir /usr/local/etc/iptablesman --status

# Daemon mode (e.g. under systemd)
iptablesman.py --config-dir /usr/local/etc/iptablesman --interval 15
```

## Common commands

```bash
# List discovered targets and drop-in files
iptablesman.py --config-dir /usr/local/etc/iptablesman --list

# Desired vs live rules
iptablesman.py --config-dir /usr/local/etc/iptablesman --status

# Sync one table/chain only
iptablesman.py --config-dir /usr/local/etc/iptablesman -t nat -N POSTROUTING --interval 15

# Request immediate resync of running daemon
iptablesman.py --resync --lock-file /run/iptablesman.lock

# Build / zip version string
iptablesman.py --version
```

## Flags and defaults

### Core runtime

| Flag | Default | Notes |
| --- | --- | --- |
| `--config-dir` | *(required)* | config root; rules in `<config-dir>/<table>/<chain>/` |
| `-t`, `--table` | unset | limit to one table (requires `--chain`) |
| `-N`, `--chain` | unset | limit to one chain (requires `--table`) |
| `-i`, `--interval` | `15` | daemon resync interval seconds |
| `--lock-file` | `/run/iptablesman.lock` | single-instance lock; PID written for `--resync` |
| `--iptables-path` | `/usr/sbin/iptables` | absolute path to `iptables` binary |
| `--no-create-chain` | disabled | do not run `iptables -N` for missing chains |

Daemon mode runs when none of the one-shot flags below are set. `--table` and `--chain` must be used together or both omitted.

### Logging

| Flag | Default | Notes |
| --- | --- | --- |
| `--log-level` | `info` | `info`, `debug`, `warning`, `error` |
| `--debug` | disabled | force DEBUG and verbose traces |
| `--no-syslog` | disabled | log to stderr only |

### Metrics

| Flag | Default | Notes |
| --- | --- | --- |
| `--prometheus-metrics` | disabled | enable HTTP `/metrics` endpoint |
| `--no-prometheus-metrics` | — | disable metrics (explicit) |
| `--prometheus-host` | `localhost` | metrics bind host |
| `--prometheus-port` | `9109` | metrics bind port |
| `--prometheus-metrics-last-activity` | disabled | expose last-activity gauges from counter deltas |
| `--no-prometheus-metrics-last-activity` | — | disable last-activity gauges |

Requires `python3-prometheus-client` when metrics are enabled; daemon exits with code `2` if the module is missing.

### One-shot actions

| Flag | Default | Notes |
| --- | --- | --- |
| `--version` | disabled | print zip build timestamp; exit |
| `--list` | disabled | list targets and drop-in files; exit |
| `--status` | disabled | show desired vs live; exit |
| `--test` | disabled | validate via `iptables -C` only; exit `0` or `2` |
| `--resync` | disabled | send `SIGHUP` to PID from lock file; exit |

## Config layout

Directory passed to `--config-dir` (default on hosts: `/usr/local/etc/iptablesman`):

```
<config-dir>/
  <table>/
    <chain>/
      <basename>          # one file = one or more rules
```

- Table and chain directory names: `[A-Za-z0-9_-]{1,30}`.
- Drop-in basenames: `[A-Za-z0-9_.:-]+`.
- Files are processed in **sorted basename order** (order matters when rules depend on earlier matches).

### Drop-in format

- One non-empty, non-`#` line = one rule body (shell-style tokens).
- The daemon injects `-m comment --comment <tag>`; user `--comment` tokens are stripped.
- Shell metacharacters (`;|&$()` etc.) in rule tokens are rejected.

Annotations (stacked `#` lines immediately above a rule). Only these keys are implemented:

| Key | Alias | Purpose |
| --- | --- | --- |
| `@host=<name>` | `@hosts=<name>` | DNS gate + optional hostname→IPv4 in rule tokens |
| `@name=<id>` | — | stable iptables `--comment` tag (`basename/id`) |

Unknown `@key=value` lines log a warning and are ignored.

### Annotations reference

#### `@name`

Controls the owned **comment tag** only (not environmental gating). Used when one drop-in file has several rules or you need a stable id for `-R`/`-D` across edits.

- no `@name`, one rule → tag `basename`
- no `@name`, several rules → `basename/1`, `basename/2`, …
- `@name=udp` → `basename/udp`; duplicates → `basename/udp/2`, …
- numeric-only `@name` (e.g. `42`) is rejected → auto-numbered slot

#### `@host` / `@hosts`

**Apply gate** — if any `@host` / `@hosts` is present, **every** listed name must resolve to at least one IPv4 (`getaddrinfo(AF_INET)`). This is a DNS check only (not “is this IP configured on this machine”). If any name fails:

- the rule is not `-A` / `-R`’d this cycle
- an existing owned rule with the same comment tag **stays** in the chain (not removed on transient DNS failure)
- `--test` fails for that rule

If there is no `@host`, the rule is always eligible for apply.

**Hostname substitution** — when resolution succeeds, rule tokens that **exactly match** a listed hostname are replaced with that host’s **chosen IPv4** (lowest sorted address in the DNS answer) before compare/apply. Prefer this for peers you want to track via DNS (e.g. `-d registry.internal` with `@host=registry.internal`). A literal IP in the drop-in without a matching hostname token is **not** updated when DNS changes.

**Multiple hosts = AND** — `# @host=a @host=b` means both must resolve. For “apply on host A **or** host B”, use separate rules (one `@host` each) or separate per-host drop-ins.

**Multi-A DNS** — multiple A records still allow apply; **first sorted IPv4** wins. Syslog `LOG_ALERT` on first sight, then hourly `ERROR`, recommending one A record or a literal IP.

**Alerts** — unresolved: `@host no IPv4 resolved for …`; ambiguous multi-A: `@host multiple IPv4 for …`.

#### When resolved IP changes

On each daemon cycle (`--interval`, default 15s) and on `SIGHUP` / `systemctl reload iptablesman`:

1. DNS is queried again; chosen IP = lowest sorted IPv4 in the answer.
2. Hostname tokens in the rule are rewritten to that IP.
3. Desired rule (same comment tag) is compared to the live owned rule.
4. Body differs → **`iptables -R`** (in-place replace, same tag).
5. Body matches → no-op.

| Situation | Result |
| --- | --- |
| DNS returns new IP | `-R` on next cycle |
| DNS unchanged | no-op |
| DNS fails temporarily | old rule left unchanged; apply skipped |
| Multi-A set changes which IP sorts first | `-R` when effective body differs |
| `--test` | `iptables -C` against desired IP; fails if live still old |

Does not add a second rule for the same tag; does not follow per-packet round-robin—only re-resolves on each sync cycle.

Drop-in samples and resulting comment tags: [docs/annotation-examples.md](docs/annotation-examples.md).

Apply strategy per owned comment tag:

- unchanged → no-op
- changed → `-R`
- new → `-A`
- removed → `-D`
- safe delete+append only when needed

### Example drop-in

File: `nat/POSTROUTING/wrong-uplink-postnat-log`

```
# @host=px-gw-01.example
-o eth0 ! -m set --match-set px-egress src -j LOG --log-prefix "px-egress-wrong: " --log-level 4
```

File: `nat/POSTROUTING/wrong-uplink-postnat-drop` (basename sort places LOG before DROP)

```
-o eth0 ! -m set --match-set px-egress src -j DROP
```

## Test mode (`--test`)

Non-mutating validation:

- parses all drop-ins under selected targets
- resolves `@host`
- runs `iptables -C` for each effective desired rule
- never calls `-A`, `-R`, or `-D`

Exit code: `0` success, `2` validation failure.

With `--debug`, logs per-rule progress; otherwise logs only problematic rules.

## Metrics

Standalone metrics server:

```bash
iptablesman.py --config-dir /usr/local/etc/iptablesman --interval 15 \
  --prometheus-metrics --prometheus-host localhost --prometheus-port 9109
```

Exposed series (when enabled):

- `iptablesman_monitored_chains`
- `iptablesman_monitored_rules`
- `iptablesman_sync_cycles_total`
- `iptablesman_sync_errors_total`
- `iptablesman_cycle_duration_seconds`
- `iptablesman_last_cycle_unixtime`
- `iptablesman_chain_packets{table,chain}`
- `iptablesman_chain_bytes{table,chain}`
- `iptablesman_rule_packets{table,chain,comment}`
- `iptablesman_rule_bytes{table,chain,comment}`

Optional last activity (`--prometheus-metrics-last-activity`):

- `iptablesman_chain_last_activity_unixtime{table,chain}`
- `iptablesman_rule_last_activity_unixtime{table,chain,comment}`

Counters come from `iptables-save -c`; rule metrics include only comments owned by configured drop-in basenames.

## Install (standalone)

```bash
# from repo root (this directory: __main__.py, src/, iptablesman.service)
zip -r iptablesman.zip __main__.py src -x '*/__pycache__/*' -x '*.pyc'
install -m 644 iptablesman.zip /usr/local/lib/

# launcher: exec zip so argv[0] stays iptablesman.py for logs/proctitle
cat >/usr/local/sbin/iptablesman.py <<'EOF'
#!/usr/bin/env python3
import os, sys
Z = "/usr/local/lib/iptablesman.zip"
if not os.path.isfile(Z):
    sys.exit(f"iptablesman: zip not found: {Z}")
os.execv(sys.executable, [sys.executable, Z] + sys.argv[1:])
EOF
chmod 755 /usr/local/sbin/iptablesman.py

install -d /usr/local/etc/iptablesman
# edit iptablesman.service: set IPTABLESMAN_BIN, IPTABLESMAN_CONFIG_DIR, INTERVAL, LOCK_FILE
install -m 644 iptablesman.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now iptablesman
```

One-shot without installing: `python3 iptablesman.zip --config-dir /path --test`

Runtime deps: `python3`, `python3-setproctitle`; for metrics, `python3-prometheus-client`. Host must provide `iptables` / `iptables-save` (see design notes on nft backend).

## Technical notes

- **systemd**: unit `iptablesman.service` runs the daemon; env file can set `IPTABLESMAN_*`. `systemctl reload iptablesman` → `SIGHUP` → immediate resync.
- single-instance lock prevents parallel daemons
- `SIGHUP` or `--resync` forces immediate resync (skips sleep)
- service unit is hardened (sandbox, `CAP_NET_ADMIN` for netlink)

## Design decisions

### Why `iptables` CLI, not native nftables (`nft`)?

Hosts in this ecosystem already treat **iptables as the operator API**: UFW, `ufw.rules.d` hooks, `iptables-restore`, `iptables-save -c`, and ad-hoc debugging. iptablesman is a **small incremental sync** into existing chains (e.g. extra `nat/POSTROUTING` rules next to MASQUERADE), not a greenfield firewall.

| Topic | Choice | Rationale |
| --- | --- | --- |
| Control plane | `iptables` / `iptables-save` | Matches how adjacent tooling and runbooks inspect and reload rules |
| Rule format | One line = iptables argv tail | Same language as hand-written `ufw.rules.d` fragments; no second syntax to learn |
| Ownership | `--comment` tag per drop-in | `-C` / `-R` / `-A` / `-D` per owned rule without flushing chains others manage |
| Kernel backend | Compatible with **iptables-nft** | On Debian, `iptables` may be the nftables compatibility layer (`iptables-nft`); iptablesman does not need operators to use `nft` JSON |
| Scope | IPv4-oriented sync | Fits current drop-ins; not a full nftables set/map compiler |

**Why not manage rules only via `nft`?**

- **Coexistence**: UFW and many hooks assume the iptables front-end. Replacing that with native `nft` rulesets would fight the rest of the stack on the same node.
- **Blast radius**: Per-tag `-R` updates one owned rule; replacing whole nftables tables is riskier when other daemons also touch the same chains.
- **Complexity**: Sets (e.g. `ipset` + `-m set`) and chain ordering are already expressed in iptables form where this tool is used; a native `nft` backend would duplicate parsers, tests, and metrics (`iptables-save -c` parsing) for little gain here.
- **Problem size**: A handful of tagged drop-ins (monitoring, egress checks) does not justify a nftables-specific reconciler.

**Non-goals (for this project):**

- Replacing UFW or owning full `filter`/`nat` tables
- Native `nft` rule generation or libnftables integration
- IPv6 tables in the initial design (CLI path is iptables-centric)

A separate tool could target `nft` only on hosts with no iptables/UFW stack; that is out of scope for iptablesman.

## Development tests

```bash
cd files
PYTHONPATH=. python3 -m unittest discover -s src/test -v
```

## How this project was built

This is an **AI-assisted** project: most implementation and routine edits were produced with **Cursor** agents/assistants, while **design and architecture decisions** remain **human-driven**.
