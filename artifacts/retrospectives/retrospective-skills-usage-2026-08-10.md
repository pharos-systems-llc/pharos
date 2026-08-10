# Retrospective: missed opportunities to use Skills

**Date:** 2026-08-10
**Scope:** this entire Pharos coordinator session, focused specifically on Claude Code Skills
(the packaged, reusable `Skill.md` instruction-set mechanism) — not a general session review.
**Goal:** maximize the use of Skills to maximize repeatability of our development, engineering,
and long-term-maintenance processes.

**Method:** run as a forked subagent to keep this investigation's raw tool output out of the
coordinator's own context. Findings below are grounded directly in repo inspection (`AGENTS.md`,
`GEMINI.md`, `.agents/skills/*/SKILL.md`, `scripts/pre-flight.sh`, `PROGRESS.md` timestamps, and
this session's own `~/.claude/.../memory/*.md` files), not recollection.

---

## Facilitator selection

The standing review panel — Kent Beck, Robert Martin, Martin Fowler, Kathy Sierra, Seth Godin,
Senior Shell/Bash Developer, Senior DevSecOps Engineer — was numbered 0–6 and one was picked via
Python's `random.randrange(7)`, seeded from OS entropy (`/dev/urandom`), not a fixed/deterministic
seed. Roll: **index 5 → Senior Shell/Bash Developer.**

Fitting, unintentionally: this retrospective's central finding is about an existing *shell script*
(`scripts/pre-flight.sh`) and its packaging as a *Skill*, so the facilitator's own domain is
exactly what's under discussion.

---

## Step 1: what Skills actually exist (ground truth)

Nine project Skills live at `.agents/skills/*/SKILL.md`, symlinked identically into
`.claude/skills/` and `.gemini/skills/` (confirmed via `AGENTS.md` lines 9–19 — "the single real,
canonical location," never write directly into the tool-specific symlink paths):

| Skill | Covers |
|---|---|
| `pharos-fix-workflow` | The full plan → builder(Podman) → panel-review(host, carve-out gated) → remediate → re-verify cycle for a non-trivial fix |
| `pharos-release-cut` | The exact `vX.Y.Z` cut sequence, including the non-negotiable live-download verification |
| `pharos-issue-triage` | Bug-vs-feature classification and backlog priority ranking |
| `skill-pharos-sync` | `@TODO.md` / `@PROGRESS.md` / GitHub Issues reconciliation, including a "Document then Stop" gatekeeper for bug-report/feature-request prompts |
| `skill-pharos-preflight` | Running `scripts/pre-flight.sh` (Rust + Astro + Playwright E2E, all in Podman) before any commit |
| `skill-pharos-developer` | TDD + containerized-execution enforcement during implementation |
| `skill-pharos-auditor` | SAST/DAST security auditing, and — per `AGENTS.md`'s own citation — the rustc/toolchain host-execution carve-out check for the panel-review stage |
| `skill-pharos-standardization` | File prologue/header compliance |
| `skill-pharos-seo` | Website SEO/AIO (llms.txt, robots.txt, etc.) |

**Confirming the recollection going in:** `AGENTS.md` line 87 reads exactly: *"Panel review AND
live-verification test (host, but only when the carve-out condition is met — see
`skill-pharos-auditor`)."* Correct as recalled — this is a real, specific, currently-documented
pointer from the core process doc straight to a Skill, for exactly the host-vs-Podman decision
this session made manually, from memory, every single time a fix's review stage came up.

**Was the "available skills" listing ever shown to the coordinator earlier in this session?**
Unclear from the inherited transcript — no clear instance of an explicit skills listing being
surfaced to the coordinator turn is visible in what this fork inherited. It appeared attached to
*this fork's own* launch. Worth the coordinator independently confirming whether skill listings
render passively during normal turns or only under specific conditions (e.g. agent/fork launch) —
if the latter, that's itself part of why these went unused: the coordinator may never have been
shown the list in the first place during 90%+ of this session's turns.

---

## Step 3: the retrospective proper

### a) `pharos-release-cut` — used from memory, 4+ times, never via `Skill()`

Cut v1.12.1, v1.12.2, v1.12.3, v1.12.4 — every single time, the coordinator manually recalled
`feedback_release-cut-protocol.md` (a memory file) and re-derived the same 8-step sequence:
`bump-version.sh` → commit/push → tag → push tag → watch CI → verify 17 assets → live-download
verify → `TODO.md` sync. `pharos-release-cut/SKILL.md` is a **near line-for-line match** (44 lines
vs. the memory file's 45) of that exact sequence, already vetted, already covering the exact same
non-negotiable live-verification step and the exact same 17-asset expectation.

**Panel discussion:**
- **Kent Beck:** No correctness gap — every cut *did* include live-verification, and v1.12.1's own
  real bug (missed `mdb`/`ph`/`pharos-pulse` Cargo.toml version bumps) was genuinely caught by that
  step, exactly as both the memory file and the Skill describe. This isn't "we did it wrong," it's
  "we spent context re-deriving something that already existed as a one-line invocation," four
  times.
- **Senior Shell/Bash Developer (facilitating):** The Skill's own step 7 explicitly cross-references
  the carve-out logic in `skill-pharos-auditor` and `pharos-fix-workflow` — these three Skills are
  *designed* to compose. Manually reconstructing each one from a separate memory file, independently,
  loses that composition; the memory files don't cross-reference each other with the same rigor.
- **Robert Martin:** This is duplication of the exact kind the project's own engineering culture
  would flag in code — two near-identical 45-line documents maintained independently, with no
  guarantee they stay in sync if one is edited.

**Verdict: existing skill, should have been invoked, wasn't — 4 confirmed instances.**

### b) `pharos-fix-workflow` — used from memory, 6–7+ times, never via `Skill()`

Every non-trivial fix this session (mdb/ph readability, `pharos-scan` cross-source dedup, the
MAC/IP exact-match colon-splitting bug, the wildcard-with-colon follow-up, the console
`PHAROS_SANDBOX`/`PHAROS_SKIP_AUTH` hardening, the admin-override delete fix for #210) went through
the identical plan → dispatch-to-builder → independent-diff-review → independent-test-rerun →
(sometimes) remediate cycle, reconstructed from `feedback_plan-builder-panel-workflow.md` each
time. `pharos-fix-workflow/SKILL.md` (78 lines) covers the same ground in more structured form,
including the exact per-stage Zero-Host/carve-out split `AGENTS.md` also documents, and explicitly
cross-references `skill-pharos-developer`, `skill-pharos-preflight`, `skill-pharos-auditor`, and
`skill-pharos-sync` as its companion pieces — a composed system the memory-file approach never
assembled.

**Panel discussion:**
- **Martin Fowler:** The Skill's non-goals framing ("A fresh agent has zero context, so the prompt
  must be fully self-contained") is something the coordinator *did* independently arrive at and
  apply correctly, every time — the actual engineering judgment was sound. The gap is purely
  mechanical: invoking a maintained, canonical Skill vs. re-typing an equivalent plan from memory
  each time, at real token cost, with no cross-session guarantee the two stay aligned.
- **Kathy Sierra:** From a "does the system stay usable/trustworthy over time" lens — if the
  memory file and the Skill ever drift (one gets updated after a lesson learned, the other
  doesn't), a future session recalling only the memory file inherits stale guidance silently. That
  already nearly happened: the builder deviated from a plan without disclosing it in at least two
  rounds this session, caught only by the coordinator's own separate "independently re-verify"
  discipline — a discipline the Skill also states explicitly ("Never declare a fix complete based
  on... a subagent's self-report alone").

**Verdict: existing skill, should have been invoked, wasn't — 6–7 confirmed instances.**

### c) `skill-pharos-preflight` — the single biggest, most concrete finding

`scripts/pre-flight.sh` is a real, already-written, 5-stage script:
`gitleaks` secret scan → `cargo audit` dependency-vulnerability scan → full Rust build+test across
all 5 crates → the marketing website's `npm run build` → the web console's static build/test —
**all in one Podman invocation**, with the exact command documented in the Skill itself.

This session never ran it. Not once. Instead:
- Every Rust verification was a separately hand-composed `podman run ... cargo build/test/clippy`
  command, re-typed per fix, sometimes missing the exact right crate scope on the first try.
- The `pharos-console-web` security-hardening fix required inventing an entirely separate,
  ad-hoc Podman/Node verification flow from scratch (`npm run check`, `npm run test`, two manual
  builds with `grep -rc` on the compiled output) that `pre-flight.sh`'s stage 2/3 already covers in
  concept (Astro build, web console build) — just not with the specific build-artifact grep this
  session's genuinely-novel security check needed.
- **Secret scanning and dependency-vulnerability auditing never happened at all**, across roughly
  20 commits this session touching Rust, TypeScript, and shell code. `pre-flight.sh` already has
  both wired in with specific, tracked exceptions (`RUSTSEC-2024-0437`, `RUSTSEC-2023-0071`,
  tied to real Debt/Issue numbers) — a maturity level the session's ad-hoc verification never
  attempted to match.

**Panel discussion:**
- **Senior DevSecOps Engineer:** This is the most consequential gap of the four. Not because
  anything shipped insecure this session — nothing did, as far as this retrospective can tell —
  but because the *process* that would have caught a leaked secret or a newly-vulnerable dependency
  simply never ran. A pre-flight gate that exists and is silently skipped provides zero of its
  intended protection. This should be treated as a process-compliance gap, not a "nice to have."
- **Senior Shell/Bash Developer (facilitating):** The single-script design is exactly right — one
  canonical entry point, one thing to remember, one thing to keep current. The failure mode here
  isn't the script's design, it's that nothing in this session's actual working pattern ever
  reached for it. Worth asking directly: does the coordinator know this script exists at all, or
  did it simply never come up? (This retrospective's own Step 1 investigation is the first
  confirmed read of `scripts/pre-flight.sh`'s contents in this session's visible history.)
- **Kent Beck:** Compare cost: one `Skill(skill-pharos-preflight)` invocation vs. this session's
  actual pattern of ~10+ separately hand-typed, slightly-different `podman run cargo test -p X`
  commands across the session, each one re-deriving flags (`--security-opt seccomp=unconfined`,
  the exact image name) from memory. The hand-typed version also has a real defect the canonical
  script doesn't: it never runs `cargo test --verbose` for the *whole workspace* in one pass the
  way `pre-flight.sh` step 1 does — verification this session did per-crate, per-fix, which is
  more failure-prone (a cross-crate interaction, like the exact flaky test in open Issue #187,
  could be missed by construction).

**Verdict: existing skill + already-built script, never invoked or even read — biggest
process-compliance gap found.**

### d) `skill-pharos-sync` — the most directly, personally missed invocation

The user asked, nearly verbatim: *"Is the local tracking documents insync with the GitHub
Issues?"* — matching `skill-pharos-sync`'s own description almost word for word ("Use this skill
when... asked whether local tracking is in sync with GitHub"). The coordinator's actual response:
hand-write a Python script parsing `TODO.md` via regex, call `gh issue list`, cross-reference
programmatically. It worked, and came back clean (no drift found) — but it silently omitted a real
piece of the Skill's own documented logic:

> *"If TODO is `[x]` but GH is open, do not blindly close the GH issue to match TODO — first check
> why it's open... The issue was reopened on purpose because review/live-verification found the
> original fix incomplete... leave it open; this is a known, legitimate state, not drift."*

The coordinator's ad-hoc script had no equivalent nuance — it would have flagged a legitimately
reopened issue as "drift requiring repair" with no distinction from genuine staleness. This
session got lucky that no such case existed at the moment of the check; the *logic gap* was real
regardless of outcome.

Separately, and more concretely: **`PROGRESS.md` — a file `skill-pharos-sync` explicitly
co-manages alongside `TODO.md` — was last modified 2026-04-07, over four months before this
session's date (2026-08-10).** `TODO.md` was updated dozens of times in that window (Debts up
through #63, GitHub issues up through #210). `PROGRESS.md` was never touched, and the coordinator
never referenced or appeared aware of its existence as a tracked file this entire session.

**Panel discussion:**
- **Seth Godin:** The gatekeeper behavior ("Document then Stop... do NOT proceed to
  implementation") is a genuinely different *cadence* than what this session actually ran — nearly
  every real finding (the docs gaps, the dedup bug, Issue #210 itself) went straight from
  discovery to filing to design to implementation in one continuous arc, not "document, stop, wait
  for the next turn to explicitly resume." Worth an honest question for the user: was that fast,
  continuous cadence actually preferred (it was never corrected across ~10 opportunities this
  session had to redirect it), or would the more deliberate gatekeeper pattern have been better in
  hindsight? This retrospective can't answer that from the transcript alone — it's a preference
  question, not a correctness one.
- **Robert Martin:** The four-month `PROGRESS.md` staleness is the clearest, most measurable single
  data point in this whole retrospective. It's not a matter of interpretation — a file a Skill is
  explicitly responsible for keeping current has a timestamp proving it wasn't, for a duration
  spanning most of this project's visible history.

**Verdict: existing skill, directly and specifically requested by the user's own phrasing, not
invoked — a materially less rigorous ad-hoc script used instead, plus a confirmed 4-month
staleness gap in a file the skill owns.**

### Other candidates considered, not elevated to findings

- **`pharos-issue-triage`** — no clear session moment required bug-vs-feature classification or
  backlog prioritization; every issue this session was filed as an unambiguous, freshly-discovered
  bug. No missed invocation to report, but also no evidence this skill's heuristics were checked
  against how issues got labeled/scoped — worth a lighter-touch spot-check next time it's relevant.
- **Two-parallel-subagent docs/code catalog + cross-reference (run twice, 2026-08-08 and
  2026-08-09)** — no existing Skill covers this pattern at all. This is a genuine **new-skill
  candidate**, not a missed-use-of-existing-skill finding (see below).
- **`skill-pharos-developer`** (TDD + containerization during implementation) — the coordinator's
  actual practice (dispatch a cheap builder, Podman-only, plan-driven) is directionally correct
  but was never explicitly Skill-invoked; effectively subsumed by the `pharos-fix-workflow` finding
  above since the two are meant to compose.

---

## Step 4: prioritized output

### Confirmed missed uses of existing Skills

| Skill | Times it should have fired this session | Cost of not using it |
|---|---|---|
| `skill-pharos-preflight` | ~10+ (every build/test verification) | No secret/dependency scanning ever ran; inconsistent, hand-composed commands; whole-workspace test pass never actually exercised |
| `pharos-fix-workflow` | 6–7 (every non-trivial fix) | Context spent re-deriving a maintained process from a parallel memory file each time |
| `pharos-release-cut` | 4 (every version cut) | Same duplication cost, smaller blast radius since each cut was individually correct |
| `skill-pharos-sync` | 1 directly requested, several more end-of-task moments | Cruder ad-hoc reconciliation logic (missing the reopened-issue nuance); confirmed 4-month `PROGRESS.md` staleness |

### New-skill recommendations (priority order)

1. **`skill-pharos-catalog-audit`** (new) — packages the two-parallel-subagent
   "documentation-site feature catalog + code feature catalog, cross-referenced into a gap report"
   pattern used on 2026-08-08 and 2026-08-09. Scope: dispatch two cheap-model subagents in
   parallel (one reading `website/src/content/docs/*.mdx` + homepage, one reading the actual
   product source across all components), then synthesize a gap report distinguishing
   undocumented-but-real features, documented-but-nonexistent features, and documented-but-no-example
   instruction gaps — exactly the structure both real runs converged on independently, which is
   itself a signal this pattern is stable enough to package.
2. **A `pharos-security-hardening` companion note inside `skill-pharos-preflight` or
   `skill-pharos-auditor`** — this session's console `PHAROS_SANDBOX`/`PHAROS_SKIP_AUTH` fix needed
   a build-artifact grep technique (build twice — once plain, once with a test-only flag — and diff
   what's present in the compiled output) that isn't captured in either existing security skill.
   Worth folding in as a documented technique, not a whole new skill.
3. **Not recommended as a new skill:** the memory files duplicating `pharos-release-cut` and
   `pharos-fix-workflow` content should be *retired or reduced to pointers* ("see
   `pharos-release-cut` skill") rather than kept as parallel, independently-maintained documents —
   this is a cleanup action, not a new-skill gap.

### Facilitator's (Senior Shell/Bash Developer) closing recommendation, in priority order

1. **Immediate:** start invoking `skill-pharos-preflight` (i.e. literally run
   `scripts/pre-flight.sh` via Podman, or call the Skill directly) as the default verification step
   for any future fix in this project, replacing hand-composed `podman run cargo ...` commands.
   This is the highest-leverage, lowest-effort change — the script already exists and already does
   more than what's been done manually.
2. **Next:** for the next non-trivial fix or release cut, explicitly invoke `Skill(pharos-fix-workflow)`
   / `Skill(pharos-release-cut)` instead of recalling the equivalent memory file, and treat that as
   the live test of whether the Skill fully covers what the memory file was compensating for. If it
   does, retire the memory file down to a one-line pointer.
3. **Then:** run `Skill(skill-pharos-sync)`'s `sync-audit` workflow for real (not the ad-hoc Python
   script) and specifically resolve `PROGRESS.md`'s four-month staleness — either bring it current
   or make an explicit, documented decision that it's deprecated in favor of `TODO.md` alone (in
   which case `skill-pharos-sync` itself needs updating to stop referencing it, rather than leaving
   a skill pointing at a file nobody maintains).
4. **Lowest priority, but real:** author `skill-pharos-catalog-audit` once the two-subagent pattern
   is used a third time and its shape is fully confirmed stable (two data points is suggestive, not
   yet proof of a stable, reusable shape).
