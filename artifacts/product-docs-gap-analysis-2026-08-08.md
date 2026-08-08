# Pharos product/documentation gap analysis — 2026-08-08

**Status: all items below fixed in the docs the same day.** `server-setup.mdx` gained `--tui`
(confirmed as an intentional home-lab debugging feature, not internal-only — see its description
below), the `source` field, and the 3 new counters with a PromQL example; `cli-clients.mdx` gained
`auth sign`, the interactive key-setup flow, and the multi-record output header; `configuration.mdx`
gained the `client.conf` precedence chain and webhook payload examples; `network-scan.mdx` and
`install.mdx` gained `--auto`/`scan-auto`; `install.mdx` gained `--fetch-ca-ssh`; `automation.mdx`'s
pulse field list was completed. `showcase.mdx` was removed entirely (see §2). Not yet committed.

**Method:** two independent research passes, cross-referenced and spot-verified against the actual
doc source before inclusion below (not taken at face value from either pass).

1. A documentation-site pass read only `website/src/content/docs/*.mdx` + the homepage and
   cataloged every feature/flag/config item the marketing/docs site claims, per product, with
   citations and whether a concrete usage example was given.
2. A code-research pass read only the actual product source (`mdb`, `ph`, `pharos-server`,
   `pharos-pulse`, `pharos-scan`, `pharos-console-web`, `scripts/install.sh`) and cataloged every
   real flag/subcommand/env var/capability, with citations.
3. This report cross-referenced the two catalogs and independently re-verified every finding below
   directly against the docs source with `grep`/`Read` before including it. One candidate finding
   from the raw comparison — that `ph` might be wrongly documented as supporting `mdb`'s
   `-H`/`--human` flag — did not survive verification: `cli-clients.mdx:64` correctly scopes it to
   `mdb` only ("`mdb` also accepts a `-H`/`--human` flag"). It's noted below as a non-finding, since
   it shows the docs are more careful about that distinction than a naive table comparison suggested.

---

## 1. Undocumented features (real, exist in code, absent from docs)

### pharos-server
- **Three new Prometheus write-path counters** — `pharos_records_added_total`,
  `pharos_records_updated_total`, `pharos_records_deleted_total` (each labeled by `source`),
  shipped in v1.12.0. `server-setup.mdx`'s metrics section (lines 217–220) still lists only the
  three pre-existing gauges (`pharos_cpu_usage_percentage`, `pharos_memory_usage_bytes`,
  `pharos_total_records`). This is the same gap the Integration Team's dashboard brief
  (`artifacts/release-notes/v1.12.2-change-summary.md`) was just written to cover — that content
  is a natural starting point for closing this doc gap too.
- **Record provenance (`source` field)** — every record is now stamped server-side with which
  client wrote it (`mdb`/`ph`/`pharos-scan`/`pharos-pulse`/`web-console`), immutable once set.
  Zero mention anywhere in the docs — not in `architecture.mdx`'s data-model description, not in
  `server-setup.mdx`.
- **`--tui` server flag** (`pharos-server/src/main.rs:90`) — runs the server with a terminal UI
  instead of plain logging. No doc mention at all. Possibly intentionally internal/operator-only;
  worth a decision either way rather than silence.

### mdb / ph (`cli-clients.mdx`)
- **`auth sign <challenge>` subcommand** — signs a challenge string offline for manual/scripted
  authentication. `cli-clients.mdx:74` only describes the *automatic* path ("Pharos will
  automatically handle the SSH challenge-response if your key is enrolled") — the manual
  subcommand itself is never named.
- **Interactive key setup** — when no signing key exists, `mdb`/`ph` now offer (TTY-gated) to
  generate one locally and optionally enroll it on a hub over SSH, reusing `install.sh`'s
  `--fetch-ca-ssh` pattern. A whole interactive first-run UX with no doc coverage.
- **`/etc/pharos/client.conf`** as a real, standing config source (third in the server-address
  resolution order: `PHAROS_SERVER` env → `PHAROS_HOST`/`PHAROS_PORT` env → `client.conf` →
  built-in default). It only surfaces as a passing aside inside the `--debug` flag's description
  (`cli-clients.mdx:114`) — `configuration.mdx`'s "CLI Client Configuration" section documents the
  env vars but never mentions the file or the precedence chain.
- **The new "N matches:" header + record separation** for multi-record query output, shipped this
  week in v1.12.1. Expected to be undocumented since it just shipped — flagging so it isn't lost
  once someone next touches `cli-clients.mdx`.

### pharos-scan
- **`--auto` unattended discovery mode** — entirely absent from `network-scan.mdx`, which
  documents only the interactive TUI, `--json`, and CIDR-subnet modes.
- **`install.sh scan-auto` target** — `install.mdx`'s installation-role table lists 5 roles
  (`hub`/`node`/`server`/`pulse`/`toolbelt`); the installer actually supports 6. The systemd-timer
  based unattended-scan install path has no doc entry at all.

### install.sh
- **`--fetch-ca-ssh <user@host>`** — automates CA certificate retrieval over SSH. `install.mdx`
  instead walks through the manual `scp`-based copy process (lines 63–79) and never mentions the
  flag that does the same thing in one step.

### pharos-pulse
- **Incomplete field list** — `automation.mdx`'s baseline-collection description names 6 fields
  (CPU brand, core count, RAM, kernel version, serial number, network interfaces). The agent
  actually also collects and sends `uuid`, `manufacturer`, `product_name`, `os_name`, `os_version`.
  `manufacturer` appears exactly once, in passing, on the Console page — not where pulse's own
  collection is described. Anyone building an LDAP field mapping or a dashboard off pulse data
  wouldn't know these fields exist without reading source.

## 2. Documentation accuracy

- No confirmed cases of docs describing a feature the code doesn't actually have. (See the
  `ph`/`-H` non-finding above — checked, and it's correctly scoped.)
- **`showcase.mdx` was removed entirely (2026-08-08).** What was initially flagged here as just a
  stale `v1.2.0 Pharos-Scan` version string was, on closer look, a page of four fully fabricated
  case studies — invented usernames (`@homelab-hero`, `@server-ninja`), an invented enterprise
  customer ("Global Logistics Corp"), an invented "Open-Source IoT Project," each with an invented
  direct quote, plus a footer inviting readers to "share your setup" as if an existing contributor
  community already existed. There are no real users of Pharos yet besides its own author, so none
  of this was genuine social proof. Deleted rather than patched — no other page linked to it, and
  the docs nav is generated from the content collection's `order` field, so removing the file was
  sufficient with no separate nav edit needed. Revisit once there's real usage to showcase.

## 3. Feature usage instruction gaps (documented as existing, no concrete how-to)

- **Webhook alerting** (`PHAROS_WEBHOOK_URL`/`PHAROS_WEBHOOK_FORMAT`,
  `PHAROS_ALERT_WEBHOOK_URL`/`PHAROS_ALERT_SCRIPT`) — `configuration.mdx` lists these as settable
  env vars but gives no example payload for any of the three `PHAROS_WEBHOOK_FORMAT` values
  (`generic`/`slack`/`discord`), no example alert script, and no worked example of what actually
  arrives when, say, a host goes stale. Someone wiring this up has to read source to know what to
  expect.
- **`auth sign`**, once documented per §1, will need a worked example showing *when* you'd reach
  for it (scripted/non-TTY provisioning) versus letting `mdb`/`ph` handle it silently — a bare
  flag mention won't be enough to make the distinction clear.
- **The 3 new Prometheus counters**, once documented, need the same treatment the Integration Team
  brief already gives them (PromQL examples, not just names) — otherwise they'll just repeat the
  pattern the 3 existing gauges already have in `server-setup.mdx`, where they're named but never
  demonstrated with a query.

---

## Suggested next step

Highest-value, lowest-effort fixes first: add the 3 new counters to `server-setup.mdx`'s metrics
list, add `scan-auto`/`--auto` to `install.mdx`/`network-scan.mdx`, and fix the `showcase.mdx`
version string — all small, surgical doc edits with no ambiguity about what to write. The `source`
field, interactive key setup, and `auth sign` gaps are larger and would benefit from a short
dedicated doc section each rather than a one-line patch.
