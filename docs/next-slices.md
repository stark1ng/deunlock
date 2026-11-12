# What the product still owes, in the order it should be paid

Written at the end of the session that proved the loop end to end (pair-code →
code proved → subscribed → PAM on the real `sudo` → `sudo mkdir` as root with a
fingerprint and no password). Everything below is unbuilt work, not a bug list —
bugs live in `specs/deunlock/AUDIT-001.md`.

## Slice 1 — done: the terminal offers a choice, not a wait

Delivered 2026-11-12. The module prints one line, reads the caller's tty with
echo off beside the running challenge, and takes whichever answers first: a
typed password becomes `PAM_AUTHTOK` and the stack continues (`PAM_IGNORE`), a
signature wins as before, and `phone=off` / `DEUNLOCK_OFF=1` skip the phone
without touching the terminal. `choice=<ms>` caps the phone side while a
keyboard is available; without a terminal the full `timeout=` budget still
applies. Measurements, the five pty tests and the one defect this exposed
(D-27, the daemon holding the peer's slot for a caller that had gone away) are
in `AUDIT-001.md`.

## Slice 2 — the surface the project promised

Unwired PAM services on this machine: `lightdm`. Absent: `polkit-1`. Also
unwired: `login`, `ppp` (VPN), `sshd` (key-only today).

- `lightdm-greeter` / the lock screen is the actual PulseUnlock feature: unlock a
  locked session with a fingerprint. Needs a live test on a session that can be
  locked without losing work.
- `polkit-1` needs the service file created by the policy agent package before it
  can be edited; verify what the desktop actually ships here.
- Keep the installer's backup-and-rollback shape, one service per invocation
  (`scripts/install-pam-system.sh <service>`), and never touch a service twice
  without telling the operator the backup already exists.

## Slice 3 — the phone looks like a tool, not a test harness

Everything green-glow is cosmetic and belongs here: a Material 3 theme override
(black surface, phosphor green, monospace numerals), a scanline/CRT treatment on
the approval screen, a pulse ring that animates from the moment the challenge
arrives until the signature is sent, and a success state that reads as a terminal
echoing `ACCESS GRANTED`. Constraints:

- The approval screen must **redraw for every challenge** (the current build
  renders only the first one).
- Animation must not delay the signature: start the biometric call immediately,
  animate in parallel, and keep the deadline visible as a countdown.
- Accessibility: the green must stay above 4.5:1 on the black surface, and the
  countdown must be announced, not only drawn.
- One screen, zero settings, as decided at the start.

## Slice 4 — more than one of each

Desktop side is nearly there: `bonds.toml` already holds many peers and one GATT
application already carries one session service per peer. What is missing:

- Pair mode is exclusive in the advertisement (31-byte legacy packet), so a
  second phone requires revoking the first. Fix by extended advertising
  (255 bytes, BLE 5) or by an explicit time-boxed `deunlock pair-window`.
- The phone side still stores exactly one bond (`files/deunlock-bond.toml`).
  It needs a list with a per-bond Keystore alias, a migration from the single
  record, and a screen that shows "this computer / that laptop" with the active
  one marked. One phone unlocking several computers is the same change seen from
  the other side.

## Slice 5 — a desktop tray app

The project decided on CLI-only for the desktop, and that decision should stand
for the protocol — but not for the operator's control surface. A `deunlock-tray`
crate (GTK4 + libadwaita, no web runtime) with: bond list and per-bond "last
answered", the pair-code dialog, pairing mode toggle, the audit tail, and the
same green-on-black identity as the phone. Every action calls the same library
the CLI calls; the tray owns no state of its own.

## Slice 6 — stop paying for a phone that is not there

A bond to a phone left in another city costs the full 25 s deadline on every
authentication. Persist "when this peer last actually answered" (signature,
denial or revoke — not a challenge nobody answered) beside the bond store, cut
the deadline to ~3 s for peers unseen for a day, and show `live`/`stale` in
`deunlock status`. Never delete a bond on a timer.
