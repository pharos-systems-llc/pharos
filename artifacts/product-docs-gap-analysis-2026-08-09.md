# Pharos product/documentation gap analysis — 2026-08-09

Follow-up pass to `product-docs-gap-analysis-2026-08-08.md` (all 12 items from that pass are
fixed and confirmed present in the current docs). Same method: two independent research passes
(docs-site catalog, code catalog), cross-referenced here, with every claim below independently
re-verified against actual source before inclusion — two of the code catalog's own claims did not
survive verification and are noted as ruled out, not included as findings.

---

## 1. Two real, security-relevant documentation gaps (highest priority)

### `PHAROS_SANDBOX` is documented incorrectly, not just incompletely

`configuration.mdx` describes it as: *"Enable Sandbox-specific UI hints."*

What it actually does, confirmed at `pharos-console-web/src/lib/pharos.ts:114-121` (and again at
line 342, same logic duplicated):

```js
const useTls = !!process.env.PHAROS_CA_CERT || !!process.env.PHAROS_TLS_CERT || process.env.PHAROS_SANDBOX === 'true';
...
client = tls.connect(portEnv, hostEnv, {
    ca: process.env.PHAROS_CA_CERT ? fs.readFileSync(process.env.PHAROS_CA_CERT) : undefined,
    rejectUnauthorized: !!process.env.PHAROS_CA_CERT
});
```

Setting `PHAROS_SANDBOX=true` forces the console's backend connection to use TLS — and if
`PHAROS_CA_CERT` isn't *also* set, `rejectUnauthorized` becomes `false`: **TLS certificate
validation is silently disabled**, accepting any certificate on the backend connection, not just
self-signed ones. This is a real security-relevant behavior with no relationship to "UI hints."
Docs need correcting, not just extending.

### `PHAROS_SKIP_AUTH` is a full authentication bypass and isn't documented anywhere

Confirmed at `pharos-console-web/src/middleware.ts:29-32`:

```js
// Support PHAROS_SKIP_AUTH for E2E testing / Sandbox dev
if (!session && process.env.PHAROS_SKIP_AUTH === 'true') {
    session = { userId: 'admin', roles: ['admin'], sub: 'admin' };
}
```

If set, any unauthenticated request to the console gets a synthesized `admin` session with zero
login required. It doesn't appear in `configuration.mdx`'s console env var table, `console.mdx`,
or anywhere else the doc audit checked. An undocumented flag that grants full admin access with no
login is worse than a documented one — right now there's nothing warning an operator not to set
this outside a throwaway sandbox/E2E environment.

**Recommendation for both:** document accurately, and mark both explicitly as
dev/sandbox/testing-only with a visible warning against production use — that's clearly the
intent (per the `PHAROS_SKIP_AUTH` comment itself), it just isn't communicated anywhere a real
operator would see it.

## 2. Real feature gaps

### The field-value wildcard/pattern query language has zero user-facing documentation

`pharos-server/src/storage.rs`'s `wildcard_match()` implements a real glob-style pattern language
per field value — `*` (any sequence), `+` (one-or-more), `?` (any single char), and `[...]`
(character sets) — usable in any query, e.g. `mdb hostname="web-*"` or the `mac_addr="bc:24:*"`
syntax fixed in Issue #207. `cli-clients.mdx` documents exactly one wildcard usage: the
whole-query `'*'` (match every record). The per-field pattern language itself — arguably one of
the more powerful things about the query syntax — is invisible unless you read the source (or
this session's own bug-fix history). Worth its own short section with a few worked examples
(prefix match, character-set match).

### The `guest` client identity is always read-only, undocumented

Confirmed live in `pharos-server/src/main.rs:212-214` — this is wired into the real middleware
chain unconditionally, not just a test fixture:

```rust
middleware_chain.add(Arc::new(ReadOnlyMiddleware {
    read_only_ids: vec!["guest".to_string()],
}));
```

Any connection that identifies itself as `id "guest"` is forced read-only regardless of security
tier or authentication. This is a genuinely useful, real feature (a safe default identity for
monitoring scripts, dashboards, anything that should structurally never be able to write) with no
mention in `server-setup.mdx`'s security tier documentation.

## 3. Ruled out — do not action these

- **`ph` documented with `-H`/`--human`:** the doc catalog's table listed this under both `mdb`
  and `ph` again this pass (same citation-formatting artifact as the previous audit). Verified
  again directly: `cli-clients.mdx:64` still correctly scopes it to `mdb` only. `ph`'s own source
  has no such flag. Not a real gap — noted so it isn't chased a third time.
- **`change`'s `force` keyword "skips addonly constraint":** the code catalog's claim did not
  survive verification. `pharos-server/src/protocol.rs:237` does accept `force` as a synonym for
  `make`, but `pharos-server/src/lib.rs:429-432` explicitly discards it
  (`Command::Change { force: _, .. }`) with a comment confirming it's deliberately inert — parsed
  for RFC 2378 grammar compatibility (the "Encrypt" field keyword Pharos doesn't implement), not a
  live addonly bypass. No security issue, no doc gap.
- **`mdb siteinfo`:** a recognized wire-passthrough command, technically present but not
  documented. Very low value/low priority — omitting it is reasonable, this is a stub-level RFC
  command Pharos doesn't meaningfully implement (see `architecture.mdx`'s existing "recognized but
  unimplemented" list, which `siteinfo` would belong in if documented at all).

---

## Suggested next step

Fix the two security-relevant items first (§1) — they're both misdescriptions/omissions of
sensitive behavior, not just missing examples. The wildcard query language (§2) is the next
highest-value addition; the `guest` identity is a small, easy addition to the existing security
tier table.
