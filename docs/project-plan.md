# DeUnlock — project plan to v1.0

Companion documents: `specs/deunlock/SPEC.md` (what the protocol is),
`specs/deunlock/AUDIT-001.md` (what has actually been measured, including every
defect found and closed), `docs/next-slices.md` (why each slice exists),
`specs/deunlock/ROADMAP.md` (the original 23 build steps, all closed).

This file is the plan forward. Every work package below ends in something a
stranger can check: a test that fails on the old build, or a live log line.

## Where the project stands (verified, not assumed)

The loop works on a real machine, not a stand:

| Piece | State | Evidence |
|---|---|---|
| Pairing by typed code (D-08) | works | `pair: code proved … peer_id=14f3a566…` |
| One GATT application for all peers (D-18) | works | `registering GATT app: pair service + one session service per peer peers=1` |
| Per-user install: systemd unit, identity, offer | works | `deunlock-presenced.service` active, `host_id=b254fffb…`, socket `/run/user/1000/deunlock/auth.sock` |
| PAM module in the real `sudo` | works | `sudo mkdir -p /opt/…` → `drwxr-xr-x root root`, 4.4 s, audit `success` |
| Bilateral revoke (D-14) | works | `outcome=bond-revoked`, `peers_after=0` |
| Phone noticing a forgotten bond (D-26/D-26b) | works | `session service absent after 3 discoveries … parked`, resumes after re-pair |
| Rust suite | 649 tests, clippy `-D warnings` clean | `cargo test --workspace -j 3`, `/tmp/f19.log` |
| Android unit tests + APK | green, installs over Wi-Fi | `testDebugUnitTest assembleDebug` |
| The terminal offers a choice (W-1) | works live | `Confirm on your phone, or type your password:` then `Authentication failure` and no second prompt; `pam caller hung up mid-challenge` |

Not wired yet: every PAM surface except `sudo`. On this machine `lightdm`,
`lightdm-greeter`, `lightdm-autologin` and `login` exist; `polkit-1` does not
(the policy agent's service file has to appear before it can be extended).

## Standing rules (they do not get relaxed for a deadline)

1. **Security before convenience.** Every protocol or state change lands with a
   negative test. A change that cannot be tested negatively is not ready.
2. **The phone's key never leaves the Keystore.** Nothing in a plan may require
   exporting it, and no slice may weaken the rule that the MAC is verified before
   the biometric prompt.
3. **A privileged install step is run by the operator, not by the agent.** Scripts
   print the rollback; they refuse to run twice over an existing backup.
4. **Backups are dated and flat**: `cp file backups/file.YYYY-MM-DD.bak`.
5. **Attribution stays**: `LICENSE` (MIT) and `NOTICE` name the upstream fork.
6. **No secrets in chat.** No password, no pairing code reuse, no private key.
7. **One command, one purpose.** A test run writes to a file and is read once
   (`cargo test --workspace -j 3 > /tmp/fN.log 2>&1`); running the suite twice in
   one shell is how a RAM-starved machine gets OOM-killed.
8. **Commit per work package**, with the measurement in the message. Push to
   `main` only after the suite and the linter are green.

## W-1 — the terminal offers a choice instead of a wait (delivered 2026-11-12)

**Why**: today the phone is asked silently and the password prompt only appears
after the deadline; an operator who wanted to type never gets the chance.

**Delivered**: `crates/deunlock-pam/src/choice.rs` prints the one line, polls the
caller's tty beside the daemon socket and takes whichever answers first; a typed
password is stored as `PAM_AUTHTOK` and the module returns `PAM_IGNORE`, so
`pam_unix` verifies it and the module never authenticates a password itself.
`phone=off` / `DEUNLOCK_OFF=1` skip the phone (no socket, no prompt). The daemon
now abandons a challenge whose caller hung up instead of holding the peer's only
slot (AUDIT-001 D-27). Evidence, budgets and the open phone-side withdrawal are
in AUDIT-001 under W-1.

**Deliverables**
- `deunlock-pam`: a caller conversation that prints one line
  (`Confirm on your phone, or type your password:`) and reads
  `PAM_PROMPT_ECHO_OFF` on the caller's tty, interleaved with the daemon wait.
- Whichever arrives first wins; a typed password cancels the challenge and is
  handed back as the PAM authtok, never logged, never forwarded.
- Per-service budget: a few seconds for services where typing is possible,
  full deadline for the greeter.
- `DEUNLOCK_OFF=1` and `--module-args phone=off` skip the phone entirely.

**Acceptance**: pty-driven tests — password first (phone cancelled), phone first
(typed bytes discarded), neither (deadline, password prompt returns). Live: type
a password inside `sudo true` and see sudo accept it without waiting 27 s.

**Risk**: tty handling inside PAM conversation (echo toggling, SIGWINCH). Mitigate
by driving a pty in tests before touching the live `sudo`.

**Estimate**: 1 session.

## W-2 — the surfaces the project promised

**Why**: `sudo` was the proving ground; the feature the fork exists for is
unlocking a locked session.

**Deliverables**
- `lightdm-greeter` (lock screen) wired and round-trip tested; then `lightdm`,
  then `login`.
- `polkit-1` only after the policy agent ships its service file on this machine;
  verify with `systemctl status polkit` and `dpkg -S /etc/pam.d/polkit-1` first.
- `scripts/install-pam-system.sh <service>` unchanged in shape: backup, single
  insert as `auth sufficient`, printed rollback, refuses a second run.

**Acceptance**: lock the session, unlock with the phone, then unlock with the
password — both after one another without a reboot; `sudo` untouched.

**Risk**: a broken greeter stack locks the operator out. Mitigate: only the lock
screen first (recoverable by switching VT), keep the `.bak`, and test with a
throwaway user session before the real one.

**Estimate**: 0.5–1 session.

## W-3 — the phone looks like a tool

**Why**: it is the part the user touches every hour; the current screens are
scaffolding.

**Deliverables** (Compose, Material 3 overrides, no new screens — one screen)
- Theme: true-black surface, phosphor green accent, monospace numerals.
- Challenge arrival: pulse ring + scanline sweep, countdown to the deadline.
- Success: terminal-style `ACCESS GRANTED` echo; failure: `DENIED` with the
  reason in plain words (`declined`, `expired`, `wrong code`).
- The approval screen must redraw on **every** challenge (known defect: today it
  renders the first one only).
- Accessibility: green on black ≥ 4.5:1, countdown announced, animations respect
  the system's reduce-motion setting.

**Acceptance**: Robolectric tests for state rendering per challenge number;
screenshot review; signature path unchanged (same unit tests still green).

**Risk**: animation on the critical path delaying the signature. Rule: the
biometric call starts first, animation runs beside it.

**Estimate**: 1–2 sessions.

## W-4 — many phones, many computers

**Why**: a laptop and a desktop, a phone and a spare phone — the current design
allows exactly one of each.

**Deliverables**
- Desktop: pair mode stays discoverable while bonds exist — extended advertising
  (BLE 5, 255-byte packets) or an explicit time-boxed `deunlock pair-window`.
- Phone: bond storage becomes a list (`files/bonds/*.toml`, one per peer) with a
  per-bond Keystore alias, a migration from the single record, and a chooser that
  marks the active computer.
- Both directions: one phone unlocking two computers, two phones unlocking one.

**Acceptance**: two phones paired without revoking either; both unlock `sudo`;
one phone pairs to a second computer and each bond answers only its own host
(replaying a challenge from the other host must fail — cross-host replay test).

**Risk**: GATT handle regeneration on rebuild (D-18) is the fragile part; add a
test that a third peer added at runtime does not drop the first two.

**Estimate**: 2–3 sessions.

## W-5 — a desktop tray app

**Why**: the CLI is right for the protocol and wrong for the operator; showing a
pair code currently means reading a terminal.

**Deliverables**: new crate `deunlock-tray` (GTK4 + libadwaita, no web runtime):
bond list with `last answered`, pair-code dialog with a copy button and a TTL,
pair-mode toggle, audit tail, status (`advertising`, `peers`, `stale`). Every
action calls the same library the CLI calls — the tray owns no state.

**Acceptance**: the tray can complete pairing and show a live unlock without the
terminal; killing the tray leaves the daemon untouched.

**Risk**: a second UI path drifting from the CLI. Rule: no logic in the tray.

**Estimate**: 1–2 sessions.

## W-6 — stop paying for a phone that is not there

**Why**: a bond to a phone in another city costs the full 25 s deadline on every
authentication, forever.

**Deliverables**: persist `last_answered_at` beside the bond (a signature, a
denial or a revoke — not a challenge nobody answered); deadline ≈3 s for peers
unseen for a day; `deunlock status` renders `live` / `stale`; never delete a bond
on a timer.

**Acceptance**: with a stale peer, `pamtester` returns in ≈3 s; with a live peer,
the full budget still applies; restart of the daemon does not reset the field.

**Estimate**: 0.5 session.

## Order and gates

```
W-1 → W-2 → W-3 → W-4 → W-5 → W-6
```

W-1 and W-2 first because they are the daily-use path; W-3 next because it is
independent; W-4 before W-5 because the tray's bond list is only interesting once
there is more than one bond; W-6 anywhere after W-2.

Each package's gate: `cargo test --workspace -j 3` and
`cargo clippy --workspace --all-targets -j 3 -- -D warnings` green (currently 649
tests); Kotlin `testDebugUnitTest` green when Android code moved; a live log line
or a rendered frame for whatever the package claims; AUDIT-001 updated with what
was measured; one commit, pushed.

## Definition of done for v1.0

- A user installs with two documented commands and never needs a terminal
  afterwards except to type a password when they choose to.
- Unlocking a locked session, `sudo`, and polkit prompts all accept the phone.
- Two phones and two computers coexist without revoking anything.
- The phone's UI is the one described in W-3 and shows the deadline honestly.
- A phone that is gone costs ≈3 s, not 25 s, and `deunlock status` says so.
- Every claim in the README is backed by a test or a recorded live run, and
  AUDIT-001 lists the open defects honestly — including the ones deliberately
  left open.
