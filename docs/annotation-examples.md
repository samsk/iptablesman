# Annotation examples

Drop-in file basename `allow-dns` → resulting iptables `--comment` tag shown as **tag** below.

See [README.md](../README.md) for full annotation reference (`@host`, `@name`, DNS/IP change behavior).

## `@host` only

Rule applies only while every listed name resolves to IPv4:

```
# @host=px-gw-01.example
-d px-gw-01.example -j RETURN
```

→ tag: `allow-dns` (single rule, no `@name`)

## Repeat `@host` on one line

Merged list; **all** must resolve (AND, not OR):

```
# @host=px-gw-01.example @host=px-gw-02.example
-j RETURN
```

## Stacked `#` lines

Annotations merged before the rule:

```
# @host=svc-a.example
# @name=udp
-p udp -j RETURN
```

→ tag: `allow-dns/udp`

## Multiple rules in one file

```
# @name=log
-j LOG --log-prefix "egress: "
# @name=drop
-j DROP
```

→ tags: `allow-dns/log`, `allow-dns/drop`

## Unnamed rules

Auto-numbered when more than one rule in the file:

```
-j RETURN
-p tcp -j ACCEPT
```

→ tags: `allow-dns/1`, `allow-dns/2`

## Duplicate `@name`

```
# @name=mark
-j MARK --set-mark 1
# @name=mark
-j MARK --set-mark 2
```

→ tags: `allow-dns/mark`, `allow-dns/mark/2`

## Hostname in rule body

Token replaced with resolved IPv4 before `-C`/apply:

```
# @host=registry.internal
-d registry.internal -p tcp --dport 443 -j ACCEPT
```

## Ignored / invalid

Logged; rule still parsed where possible:

```
# @host=x
# trailing annotations with no rule below → warning, ignored

# foo @host=ok bar          # non-@ tokens ignored; @host=ok kept
# @name=42                  # numeric-only @name → auto slot (not 42)
# @foo=bar                  # unknown @foo → warning, ignored
```
