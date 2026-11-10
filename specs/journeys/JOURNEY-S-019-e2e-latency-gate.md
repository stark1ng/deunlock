# JOURNEY-S-019: E2E unlock-latency benchmark + SPEC §4.3 gate

## Roadmap Link
- Source roadmap: [specs/unlock-proximity/ROADMAP.md](../unlock-proximity/ROADMAP.md) — Step S-019.
- Feature: `scripts/e2e-unlock.sh` benchmark harness that drives 100
  `pamtester deunlock-test $USER authenticate` invocations against the
  real R5CY214FQHM phone with `DEUNLOCK_REAL_RADIOS=1`, parses
  `/var/lib/deunlock/last.log` (audit format SPEC §3 #8 +
  JOURNEY-S-006), computes p50/p95/p99 from
  `elapsed_ms = t_end_ms - t_start_ms`, and fails non-zero on
  `p50 > 1500 ms` OR `p99 > 2000 ms` OR `n_failures > 0`. Wired to a
  `make e2e-unlock` Makefile target gated behind
  `DEUNLOCK_REAL_RADIOS=1` (same gate-pattern S-019 `e2e-real` already
  uses for the nine-case wire-suite).

## 1. Journey

When **I am the operator who has shipped the deunlock daemon
(`deunlock-presenced`), installed `pam_deunlock.so` against the
`deunlock-test` PAM service, paired my R5CY214FQHM phone, and want to
prove the SPEC §4.3 latency contract (`p50 < 1.5 s, p99 < 2.0 s`)
holds end-to-end on real radios**, I want to **run a single command
that drives 100 unlocks, summarizes the percentile distribution as
JSON on stdout, and exits non-zero the moment the budget is
breached** so I can **catch a regression before it lands in front of
a real user, treat the latency target as a CI-enforceable contract
not a hand-eyeballed metric, and have a one-line evidence string to
paste into the row that closes this roadmap step**.

## 2. CJM

The operator has just finished pairing their phone (DEV-001 closed
2026-05-17), `deunlock-presenced` is running under their user session
(S-009), the `pam_deunlock.so` module is wired into `deunlock-test` via
`deunlock install-pam --service deunlock-test --pam-dir /etc/pam.d
--with-presenced=true`, and the PAM service file points at
`pam_deunlock.so timeout=1200`. They want to prove the end-to-end
latency story before declaring the unlock-proximity roadmap
finished. Today there is no command that drives the benchmark, no
JSON contract for the percentile distribution, and no enforced
budget — a regression would land unnoticed. This journey gives the
operator one make-target, a fail-fast gate, and a reproducible
evidence shape that fits into `docs/known-gaps.md` and into the
roadmap's closure row.

### Phase 1: Operator runs the benchmark with phone in range and gets a green budget

**User Intent:** Prove the SPEC §4.3 contract holds on real
hardware, capture the JSON summary as the evidence that ships in
the closure row.

**Actions:**
1. Operator confirms the phone is unlocked, in range, and
   `DeUnlockCompanionService` is connected (visible in `deunlock status
   --json`).
2. Operator runs `DEUNLOCK_REAL_RADIOS=1 make e2e-unlock`.
3. The script runs `pamtester deunlock-test $USER authenticate` 100
   times; the operator taps fingerprint on the phone for each
   challenge.
4. After the last unlock, the script parses the new audit lines and
   emits one JSON line:
   `{"p50_ms":1080,"p95_ms":1620,"p99_ms":1740,"n_failures":0,"n_timeouts":0}`.
5. Exit code is 0; the operator pastes the JSON into the closure
   row of `docs/known-gaps.md` (or, since no DEV-NNN gap is open
   against S-019, into this journey doc's Closure Appendix).

**Pain / Risk:**
- Phone screen off mid-run: `BiometricPrompt` may fire late on the
  first few unlocks while the screen wakes; tail-of-distribution
  outliers blow p99 past 2.0 s. Operator mitigation: pre-wake the
  phone, run a warm-up of 5 unlocks before the benchmark.
- Operator types `pamtester deunlock-test` but no such PAM service
  file exists on disk. Script must fail-fast with a clear setup
  hint, not run pamtester 100 times against `PAM_USER_UNKNOWN`.
- `DEUNLOCK_REAL_RADIOS=1` not set: the Makefile target must refuse
  with the same one-line "refusing" message the existing
  `make e2e-real` target uses (SPEC §4.3 + DEV-004 + S-019 e2e-real
  pattern).
- Audit-log truncation between snapshot lines: if another process
  truncates `/var/lib/deunlock/last.log` mid-run, the percentile math
  reads phantom data. Mitigation: script snapshots
  `wc -l $AUDIT_LOG_PATH` before and after, and asserts
  `END_LINES >= START_LINES + ITERATIONS` before computing
  percentiles.

**Success Signal:** The script prints exactly one JSON line to
stdout, exits 0, and the JSON line satisfies
`p50_ms <= 1500 && p99_ms <= 2000 && n_failures == 0`.

### Phase 2: Operator runs the benchmark without the daemon and the gate fails fast

**User Intent:** Prove the gate also catches the "daemon-down" case
(SPEC §4.3 daemon-down latency ≤ 50 ms target + SPEC §6 failure
taxonomy "Socket connect refused (daemon down) → `PAM_AUTHINFO_UNAVAIL`").

**Actions:**
1. Operator stops the daemon: `systemctl --user stop deunlock-presenced`.
2. Operator runs `DEUNLOCK_REAL_RADIOS=1 make e2e-unlock`.
3. Every `pamtester` invocation returns `PAM_AUTHINFO_UNAVAIL`
   within ≤ 50 ms (S-008 closure pin); the audit log records each
   call with outcome `daemon-down` (or `transport-error` depending
   on the PAM module's reason classification).
4. The script's percentile math sees 100 lines but
   `n_failures = 100`; the JSON summary emits the elapsed-ms
   distribution AND a non-zero failure count.
5. Exit code is 1; the operator now knows daemon-down is the gate
   surface (not silent fall-through).

**Pain / Risk:**
- Operator confused that the script "fails" when the daemon-down
  case is exactly the case they wanted to test. Mitigation: the
  script's stdout JSON shows `n_failures=100`, which is the
  diagnostic signal — the operator reads the JSON and sees the
  root cause without diving into the audit log.
- `pamtester` itself returns a non-zero exit on
  `PAM_AUTHINFO_UNAVAIL`. The script must NOT abort on the first
  non-zero pamtester exit — it has to keep going, count the
  failure, and surface the count in the JSON. The fail-fast gate
  is the FINAL JSON summary, not any single iteration.
- Without the daemon, the audit log may not grow at all (the
  daemon owns the writer). Mitigation: the PAM module's own log
  record for `daemon-down` is missing from `/var/lib/deunlock/last.log`
  because the daemon never sees the call; the script counts
  `pamtester` exit-code failures separately as `n_failures` and
  treats "audit-line shortfall" as the same class of failure.

**Success Signal:** Exit code 1; JSON line shows
`n_failures > 0`; operator can `grep daemon-down` in the audit log
or `systemctl --user status deunlock-presenced` to confirm the root
cause.

### Phase 3: p99 regresses past 2.0 s, gate fails, regression is caught

**User Intent:** Catch the case where the daemon is up, the radio
is fine, but a regression (e.g., a slow tokio task added in a
future step) blows the p99 budget past the SPEC §4.3 ceiling.

**Actions:**
1. Operator runs `DEUNLOCK_REAL_RADIOS=1 make e2e-unlock` after a
   suspect change.
2. The script completes all 100 iterations (no failures), parses
   the audit log, computes
   `p50_ms=1200, p95_ms=2100, p99_ms=2300`.
3. Script emits the JSON
   `{"p50_ms":1200,"p95_ms":2100,"p99_ms":2300,"n_failures":0,"n_timeouts":0}`.
4. Script exits 1 because `p99_ms > 2000`.
5. Operator now has a reproducible evidence string for the
   regression: the JSON line goes into the bug report.

**Pain / Risk:**
- p50 looks OK but p99 is bad — the operator might miss the
  failure if the JSON is multi-line or pretty-printed. Mitigation:
  the script emits exactly ONE single-line JSON record so
  `make e2e-unlock | jq '.p99_ms'` is a one-liner.
- A network-stack jitter spike on the radio's host CPU makes p99
  flaky run-to-run. Mitigation: the operator re-runs the
  benchmark; the script is idempotent (no daemon restart, no audit
  log truncation). If the regression persists across three runs,
  it is a real regression. (This is operator-side discipline; the
  script does not enforce it.)
- A regression in the percentile math itself (the script computes
  p99 wrong). Mitigation: the Rust integration test
  `e2e_unlock_script.rs` ships a synthetic audit-log fixture and
  asserts the JSON output shape + exit code; the math is exercised
  in `make test` on every CI run, independent of real radios.

**Success Signal:** Exit code 1; JSON line shows `p99_ms > 2000`
or `p50_ms > 1500`; operator pastes the JSON line into the
regression bug report.

### Phase 4: CI runs `make test`, the script-fixture test exercises the percentile math without real radios

**User Intent:** Ensure the script ships green in CI even though
CI has no phone in hand — the percentile math, JSON shape, and
exit-code matrix must be CI-enforceable.

**Actions:**
1. CI runs `make test`.
2. `cargo test -p deunlock-cli --test e2e_unlock_script` shells out
   to `scripts/e2e-unlock.sh` with a fake audit-log fixture in
   `/tmp/<tempdir>/last.log`, `DEUNLOCK_E2E_ITERATIONS=3`, and a
   `DEUNLOCK_PAMTESTER_BIN` env var pointing at a stub pamtester
   that always succeeds (or always fails, depending on the test
   case).
3. The test asserts: (a) JSON shape matches the SPEC contract, (b)
   exit code is 0 when the synthetic distribution satisfies the
   gate, (c) exit code is 1 when p50 or p99 exceeds the budget.

**Pain / Risk:**
- The CI host has no `pamtester` binary. The script's fail-fast
  pre-flight must look for `pamtester` only on a real run; the
  fixture test uses `DEUNLOCK_PAMTESTER_BIN=<stub>` to inject a
  hermetic test double.
- The script's `DEUNLOCK_REAL_RADIOS=1` gate would block the fixture
  test in CI. The fixture path sets `DEUNLOCK_REAL_RADIOS=1` AND
  `DEUNLOCK_PAMTESTER_BIN=<stub>` AND
  `DEUNLOCK_AUDIT_LOG=<tempdir>/last.log` — the gate is satisfied
  but no real BlueZ work happens.
- Percentile math edge cases: `ITERATIONS=1` (single value, p50 =
  p95 = p99 = that value); `ITERATIONS=2` (linear interpolation vs.
  nearest-rank); `ITERATIONS=3` (the fixture default — small
  enough to hand-verify the percentile output).

**Success Signal:** `cargo test -p deunlock-cli --test
e2e_unlock_script` passes; `make test` total count increases by
the new test cases; CI green without real radios.

### Friction and Opportunity

| Friction | Phase | Opportunity |
|----------|-------|-------------|
| `pamtester` is not installed on the operator's box | 1 | Script pre-flight checks `command -v pamtester`; fail-fast hint: "install `pamtester` from your distro's package repo". |
| Operator forgets to set `DEUNLOCK_REAL_RADIOS=1` | 1, 2, 3 | Makefile target refuses with a one-line message matching the existing `make e2e-real` pattern. |
| Audit log permissions (the daemon owns `/var/lib/deunlock/last.log` as `0600`) | 1, 2 | Script pre-flight checks the audit log path is readable by `$USER`; if not, fail-fast hint: "sudo chgrp $USER /var/lib/deunlock/last.log" or "set DEUNLOCK_AUDIT_LOG to a user-writable path". |
| A run interrupted mid-loop leaves the audit log with N < ITERATIONS new lines | 1, 3 | Script asserts `END_LINES >= START_LINES + ITERATIONS` before computing percentiles; if short, fails with a clear "audit log short: expected N got M" hint. |
| Operator wants a smaller smoke-test (5 unlocks) before committing to 100 | 1 | `DEUNLOCK_E2E_ITERATIONS=5 DEUNLOCK_REAL_RADIOS=1 make e2e-unlock` runs 5 iterations against the budget. |

### North Star Summary

A single command — `DEUNLOCK_REAL_RADIOS=1 make e2e-unlock` — drives
100 unlocks, prints one JSON line, and exits 0 when the SPEC §4.3
budget holds. The same command exits 1 the moment p50 or p99
regresses. The fixture test in `make test` exercises the
percentile math and JSON shape on every CI run, so the gate is
CI-enforceable even though the real-radio run requires hardware in
hand. The operator's evidence trail for closure is one JSON line,
pasted verbatim into the closure row.

## 3. UX Implementation and Assessment

### Time to First Value
- [x] One command (`DEUNLOCK_REAL_RADIOS=1 make e2e-unlock`) drives
      the entire benchmark; no intermediate setup steps beyond the
      already-installed daemon + pamtester.
- [x] JSON output is a single line so `jq` / `grep` consumption is
      one-liner-friendly.

### Onboarding Clarity
- [x] `make help` does not list the target by default (it is
      gated behind `DEUNLOCK_REAL_RADIOS=1`); the target's purpose
      is documented inline in the Makefile so a reader of the file
      sees the SPEC anchor and the gate.
- [x] Script's fail-fast pre-flight messages name the missing
      dependency by name (`pamtester` / PAM service file / audit
      log path) and the override env var if any.

### Production-Ready Defaults
- [x] Default `ITERATIONS=100` matches the SPEC §4.3 contract
      verbatim ("drives `pamtester` 100 times").
- [x] Default `P50_BUDGET_MS=1500` and `P99_BUDGET_MS=2000` match
      the SPEC §4.3 latency targets verbatim.
- [x] Default `AUDIT_LOG_PATH=/var/lib/deunlock/last.log` matches the
      daemon's default (`DEFAULT_AUDIT_LOG_PATH` in `runtime.rs`).
- [x] Default `PAM_SERVICE=deunlock-test` matches the SPEC §4.3
      Testing Strategy E2E section verbatim.

### Golden Path Quality
- [x] The script always emits exactly one JSON line on stdout —
      no other stdout traffic, even on failure (diagnostics go to
      stderr).
- [x] Exit code matrix is exhaustive: 0 (gate green) | 1 (gate
      red, distinguishable by JSON contents) | 2 (pre-flight
      failure, no JSON emitted).

### Decision Load
- [x] Operator does not pick percentile algorithms (nearest-rank
      pinned in the script).
- [x] Operator does not pick budget thresholds (SPEC §4.3 is the
      single source of truth, hard-coded in named constants).

### Progressive Complexity
- [x] Default invocation is a single command; advanced overrides
      (`DEUNLOCK_E2E_ITERATIONS`, `DEUNLOCK_PAM_SERVICE`,
      `DEUNLOCK_PAM_USER`, `DEUNLOCK_AUDIT_LOG`,
      `DEUNLOCK_PAMTESTER_BIN`) are opt-in env vars with safe
      defaults.

### Error Quality
- [x] Every fail-fast pre-flight names the problem and the
      one-line fix.
- [x] Mid-run pamtester failures are counted in the JSON
      (`n_failures`) rather than aborting the loop; the gate is
      evaluated against the full distribution.

### Failure Safety
- [x] Script is idempotent: rerunning leaves no state behind
      beyond the new audit-log lines.
- [x] No `rm -rf`, no `sudo`, no destructive operations.

### Runtime Transparency
- [x] Each iteration logs `[i/N] pamtester rc=<n>` to stderr so
      the operator sees progress.
- [x] The final JSON line on stdout is the machine-readable
      contract; stderr is human-readable narration.

### Debuggability
- [x] On gate-fail, stderr prints the parsed elapsed-ms array's
      head and tail (10 values each) so the operator can spot
      outliers without digging into the audit log.
- [x] `DEUNLOCK_E2E_VERBOSE=1` enables `set -x` for shell-level
      tracing (optional, opt-in).

### Cross-Surface Consistency
- [x] `DEUNLOCK_REAL_RADIOS=1` gate matches DEV-004 and the
      existing `make e2e-real` target exactly (verbatim env var
      name; same `ifeq ($(DEUNLOCK_REAL_RADIOS),1)` Makefile guard).
- [x] JSON field names (`p50_ms`, `p95_ms`, `p99_ms`,
      `n_failures`, `n_timeouts`) are kebab-snake-case-aligned
      with the audit-log column names from S-006 (`elapsed_ms`,
      `t_start_ms`, etc.) so a downstream consumer sees a single
      vocabulary.

### Workflow Consistency
- [x] Script lives at `scripts/e2e-unlock.sh` next to the
      existing `scripts/e2e-emulator-up.sh` etc.
- [x] Makefile target name `e2e-unlock` matches the existing
      `e2e-real` cadence.

### Change Safety
- [x] No production code is modified by S-019. Only a new
      script, a new Makefile target, and a new Rust integration
      test.
- [x] Adding the target to the Makefile does not change any
      existing target's behaviour.

### Experimentation Safety
- [x] The fixture test (`tests/e2e_unlock_script.rs`) is hermetic
      — it never touches `/var/lib/deunlock/last.log`, never
      invokes the real `pamtester`, never connects to BlueZ.

### Interaction Latency
- [x] Pre-flight failure exits in milliseconds with a clear
      message (no retries, no daemon connect attempts).
- [x] The per-iteration loop overhead (parsing the audit log,
      computing percentiles) is negligible compared to the
      pamtester wall-clock budget.

### Developer Feedback Speed
- [x] The Rust integration test runs in milliseconds; CI feedback
      is immediate.
- [x] The real-radio run takes ~100 × ~1.5 s = ~150 s for 100
      unlocks; acceptable for a final gate.

### Team Scale
- [x] Script is version-controlled at `scripts/e2e-unlock.sh`;
      every operator runs the same code.
- [x] Budgets live in the script as named constants
      (`P50_BUDGET_MS`, `P99_BUDGET_MS`); a change requires a code
      review.

### System Scale
- [x] No state, no DB, no global cache; scales with audit-log
      size (which is already O(unlocks-per-session)).

### Right Behavior by Default
- [x] Default invocation enforces SPEC §4.3 verbatim; an operator
      must explicitly override env vars to relax any threshold.

### Anti-Bypass Design
- [x] The Makefile target refuses to run without
      `DEUNLOCK_REAL_RADIOS=1`; an operator cannot accidentally run
      the benchmark in a CI context that lacks real radios.
- [x] The fixture test in CI exercises the gate logic itself;
      a regression in the percentile math is caught on every
      `make test` without real radios.

## 4. Tests

### TC-01: Synthetic distribution under budget exits 0

**Given** a synthetic audit-log fixture with three new lines
producing `elapsed_ms = [1000, 1100, 1200]` (peer_id `abc`,
nonce_hex 32 chars, outcome `ok`, reason `ok`), and a stub
pamtester that always exits 0.

**When** the script runs with `DEUNLOCK_REAL_RADIOS=1`,
`DEUNLOCK_E2E_ITERATIONS=3`, `DEUNLOCK_AUDIT_LOG=<tempfile>`,
`DEUNLOCK_PAMTESTER_BIN=<stub>`, `DEUNLOCK_PAM_SERVICE=test`,
`DEUNLOCK_PAM_USER=test`.

**Then** the script emits exactly one JSON line on stdout matching
`{"p50_ms":1100,"p95_ms":1200,"p99_ms":1200,"n_failures":0,"n_timeouts":0}`,
exits 0, and `make test` includes the assertion via the Rust
integration test.

### TC-02: Synthetic distribution over p99 budget exits 1

**Given** a synthetic audit-log fixture with three new lines
producing `elapsed_ms = [1000, 1500, 2500]`.

**When** the script runs with the same env as TC-01.

**Then** the script emits a JSON line with `p99_ms = 2500`, exits
1, and the Rust integration test asserts `exit_code == 1` and
`p99_ms > 2000` in the parsed JSON.

### TC-03: Synthetic distribution over p50 budget exits 1

**Given** a synthetic audit-log fixture with three new lines
producing `elapsed_ms = [1600, 1700, 1800]`.

**When** the script runs with the same env as TC-01.

**Then** the script emits a JSON line with `p50_ms = 1700`, exits
1.

### TC-04: Stub pamtester returns non-zero for every iteration

**Given** a stub pamtester binary that exits 1 always; synthetic
audit log has no new lines.

**When** the script runs with `DEUNLOCK_E2E_ITERATIONS=3`.

**Then** the script reports `n_failures = 3` in the JSON, exits 1
(gate fails on `n_failures > 0`).

### TC-05: `DEUNLOCK_REAL_RADIOS=1` missing → Makefile refuses

**Given** the operator runs `make e2e-unlock` without setting
`DEUNLOCK_REAL_RADIOS=1`.

**When** `make` evaluates the target.

**Then** the recipe prints "e2e-unlock requires
DEUNLOCK_REAL_RADIOS=1; refusing" on stdout and exits 1; the script
is NOT invoked.

### TC-06: `pamtester` not on PATH on a real run → fail-fast

**Given** `DEUNLOCK_PAMTESTER_BIN` is unset and `pamtester` is not
on PATH.

**When** the script runs with `DEUNLOCK_REAL_RADIOS=1`.

**Then** the script exits 2 with a stderr message naming
`pamtester` as the missing dependency; no JSON line is emitted.

### TC-07: Audit log path missing → fail-fast

**Given** `DEUNLOCK_AUDIT_LOG=/nonexistent/path`.

**When** the script runs.

**Then** the script exits 2 with a stderr message naming the
audit log path and a one-line fix hint; no JSON line is emitted.

### TC-08: Real-radio run with phone in range (REQUIRES OPERATOR)

**Given** a paired R5CY214FQHM phone in range, daemon up,
pamtester installed, PAM service `deunlock-test` configured.

**When** the operator runs `DEUNLOCK_REAL_RADIOS=1 make e2e-unlock`.

**Then** the script drives 100 real unlocks, the operator taps
fingerprint on each, and the JSON line satisfies `p50_ms <=
1500 && p99_ms <= 2000 && n_failures == 0`. **This test case is
operator-driven and cannot run in CI.** Evidence pasted into the
"Closure Appendix" of this journey doc when the operator runs it.

## Traceability
- Roadmap item: [specs/unlock-proximity/ROADMAP.md S-019](../unlock-proximity/ROADMAP.md)
- Implementation files:
  - `scripts/e2e-unlock.sh` (new) — the benchmark harness.
  - `Makefile` (modified) — `e2e-unlock` target with the
    `DEUNLOCK_REAL_RADIOS=1` gate.
  - `crates/deunlock-cli/tests/e2e_unlock_script.rs` (new) — Rust
    integration test that shells out to the script with a
    hermetic fixture (synthetic audit log + stub pamtester).
- Test files:
  - `crates/deunlock-cli/tests/e2e_unlock_script.rs` — TC-01..TC-04 +
    TC-06 + TC-07 (TC-05 is a Makefile assertion verified by
    inspection; TC-08 is the operator-driven real-radio probe).

## Implementation

### Files created
- `scripts/e2e-unlock.sh` — the bash harness. `set -euo pipefail`;
  named constants at the top:
  - `ITERATIONS=${DEUNLOCK_E2E_ITERATIONS:-100}`
  - `P50_BUDGET_MS=1500`
  - `P99_BUDGET_MS=2000`
  - `AUDIT_LOG_PATH=${DEUNLOCK_AUDIT_LOG:-/var/lib/deunlock/last.log}`
  - `PAM_SERVICE=${DEUNLOCK_PAM_SERVICE:-deunlock-test}`
  - `PAM_USER=${DEUNLOCK_PAM_USER:-$USER}`
  - `PAMTESTER_BIN=${DEUNLOCK_PAMTESTER_BIN:-pamtester}`
  Pre-flight:
  1. Assert `DEUNLOCK_REAL_RADIOS=1` else exit 2.
  2. Assert `pamtester` (or `$PAMTESTER_BIN`) is executable.
  3. Assert `$AUDIT_LOG_PATH` exists and is readable.
  Loop:
  1. Snapshot `START_LINES=$(wc -l < $AUDIT_LOG_PATH)`.
  2. For `i in 1..N`: run `$PAMTESTER_BIN $PAM_SERVICE $PAM_USER
     authenticate`; record rc; if non-zero, increment
     `N_FAILURES`.
  3. Snapshot `END_LINES`.
  Parse:
  1. Take lines `START_LINES+1..END_LINES` from the audit log.
  2. For each line, split on `,`; compute
     `elapsed_ms = $4 - $3`; accumulate into a sorted array.
  3. Count `n_timeouts` = lines with `outcome=response-timeout` or
     `reason=response-timeout`.
  Percentiles:
  1. Nearest-rank algorithm on the sorted array (k = ceil(p/100 *
     n) - 1, zero-indexed).
  Emit:
  1. Print exactly one JSON line on stdout.
  2. Exit 0 if `p50 <= P50_BUDGET_MS && p99 <= P99_BUDGET_MS &&
     n_failures == 0`; else exit 1.

- `crates/deunlock-cli/tests/e2e_unlock_script.rs` — Rust
  integration test. Uses `tempfile::tempdir()` for the audit log
  and a `tempfile::NamedTempFile` for the stub pamtester (a small
  bash script chmod 0o755 that exits 0 or 1). Each test invokes
  the script via `std::process::Command::new("bash")
  .arg(repo_root.join("scripts/e2e-unlock.sh"))` with the env
  vars set on the command. Pre-creates the fixture audit-log
  lines BEFORE invoking the script (since the stub pamtester
  doesn't write to the log), then sets `DEUNLOCK_E2E_PREPOPULATED=1`
  so the script reads the existing lines as if pamtester had
  written them.

### Files modified
- `Makefile` — adds `## e2e-unlock` target with the
  `DEUNLOCK_REAL_RADIOS=1` gate, mirroring `make e2e-real`'s
  pattern.
- `specs/unlock-proximity/ROADMAP.md` — ticks S-019 DoD bullets
  that can be verified mechanically; leaves the "one hand-run
  with hardware" bullet as `[~]` with a marker pointing at this
  journey doc's Closure Appendix (which the operator fills in
  when they run the real-radio probe).

### Deviations
- The "one hand-run with hardware" DoD bullet REQUIRES the
  operator (phone + laptop in hand). This sub-agent run ships
  the script, Makefile target, fixture test, and operator-side
  documentation — but cannot itself drive the real-radio probe
  in a CI / sub-agent context. The operator will paste the
  output of `DEUNLOCK_REAL_RADIOS=1 make e2e-unlock` into the
  Closure Appendix below when they run it.
- The script reads pre-populated audit-log lines in fixture mode
  (`DEUNLOCK_E2E_PREPOPULATED=1`) so the Rust integration test
  doesn't need to compute or inject elapsed-ms via the stub
  pamtester (which has no audit-log writer of its own). The
  prepopulation is a test-only env var; the production code path
  (real-radio run) ignores it and uses the START_LINES /
  END_LINES snapshot.

## Closure Appendix

### Operator-side real-radio probe (TC-08)

**Status:** PENDING OPERATOR — requires phone + laptop in hand.

When the operator runs the real-radio probe, paste the JSON line
verbatim here, followed by `git log -1 --oneline` (so the
evidence is anchored to a SHA), and tick the
`[x] One hand-run with hardware...` bullet in
`specs/unlock-proximity/ROADMAP.md` Step S-019.

Template:

```
$ DEUNLOCK_REAL_RADIOS=1 make e2e-unlock
[stderr noise here]
{"p50_ms":<NNN>,"p95_ms":<NNN>,"p99_ms":<NNN>,"n_failures":0,"n_timeouts":0}
$ echo $?
0
$ git log -1 --oneline
<sha> feat(e2e): scripts/e2e-unlock.sh + make e2e-unlock + fixture test
```
