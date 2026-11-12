# W-4 — many phones, many computers: how it gets built

Plan, not code. Every claim below was read out of the tree or measured on this
machine; anything assumed is marked as such.

## What already holds

| Fact | Where |
|---|---|
| The challenge transcript carries `host_id[32]` first, before service, user and nonce | `crates/deunlock-core/src/challenge.rs:9`, `:102` |
| …so a signature made for one computer cannot verify under another. Cross-host replay is prevented by construction; W-4 adds the *test*, not the mechanism. | `verify_transcript` path, `orchestrator.rs` |
| One GATT application holds the pair service **and one session service per peer** | `crates/deunlock-transport/src/peripheral.rs:868` (`rebuild_services`) |
| Adding or removing a peer rebuilds that application: abort every loop → drop the app handle → `serve_gatt_application` again | same function |
| The pair service is registered even when bonds exist — only the *advertisement* hides it | `orchestrator.rs:1636` (`build_uuid_union`) |
| Pairing already requires an outstanding offer with an unspent code (TTL, 5 attempts) | `runtime.rs:760` (`verify_pair_code`) |
| The phone keeps exactly one bond (`bond.json`), but the Keystore alias is already per-peer | `bond/BondStore.kt:241`, `bg/DeUnlockCompanionService.kt:687` |

Two measured constraints decide the design:

```
$ bluetoothctl show          # BlueZ 5.72, kernel 6.8
Controller 04:EA:56:C2:0E:51 … Powered: yes
```

* A legacy advertisement holds **one** 128-bit UUID (31-byte budget; pair UUID +
  session UUID = 35 bytes, and BlueZ refuses that with `Failed to register
  advertisement` — already measured when the first bond landed, recorded above
  `build_uuid_union`).
* `bluer`'s extended advertising is `Type::Broadcast` — non-connectable. It cannot
  carry session UUIDs for a phone that has to connect, so extended advertising is
  **not** a route here. (Verified in the vendored `bluer` source: `adv.rs:27`.)

## The design

**Pairing availability is tied to the pending offer, not to "no bonds".**

`deunlock pair-code` already mints an offer with a code and a TTL (300 s by default, `crates/deunlock-cli/src/pair_code.rs:25`). While an
unexpired offer exists the advertisement carries the **pair UUID**; with no offer
it carries the **session UUIDs**. That is the whole desktop change:

* no new state — the offer file *is* the state;
* no new CLI verb — `pair-code` announces the window it opens;
* a bonded desktop stops advertising the pair service the moment the code expires,
  which is the security property the current "only when no bonds" rule was buying.

The cost, stated plainly: during the window a bonded phone that has to *reconnect*
will not find the session UUID, so it can miss one unlock. In practice the phone
keeps a persistent GATT client (`PersistentGattClient`), so reconnects are rare;
the window is short and operator-initiated; the UUID set rotates back within the
minute tick. Documented, not hidden.

**Pair acceptance stays where it is** — the code. `verify_pair_code` refuses with
`no usable offer` when none exists, so reachability of the pair characteristic is
not itself an authorisation. (The comment above `build_uuid_union` warning about
drive-by pairing predates this check; the check is the gate.)

**The phone stops being single-bond.** `bond.json` becomes `bonds/<peer_id>.json`
with the same per-peer Keystore alias, plus a migration that is tested against the
file this machine actually has.

## Stages, in order

Each is one commit with its measurement, negative test first.

### W-4.1 — the window (desktop)

* `build_uuid_union`: pair UUID while an unexpired offer exists, else the session
  UUIDs. Offer presence is already known to the daemon (`runtime.rs` reads it per
  attempt), so this is a parameter, not new plumbing.
* `pair-code`: log and print the window it opens (`advertising the pair service for
  300 s`), and re-advertise immediately when the offer is minted or spent instead of
  waiting for the rotation tick.
* Tests: with an offer → pair UUID present, session UUIDs absent; offer expired →
  the reverse; offer spent after a wrong code → the reverse; no offer → the
  reverse. Live: pair a *second* phone while the first stays bonded.

### W-4.2 — N peers without collateral damage (desktop)

* The rebuild is the risk: peers are unreachable between dropping the app and
  `serve_gatt_application` returning. Measure that gap (`tracing` timestamps
  around the rebuild), log it, and if it exceeds one advertisement interval,
  queue a challenge that arrives inside it instead of failing it.
* Test (the one D-18 asked for): pair peers 1 and 2, add peer 3 at runtime, then a
  challenge for each of the three must succeed; and revoking #2 must leave #1 and
  #3 answering.
* Negative: a session service for a revoked peer must not linger in the registered
  application.

### W-4.3 — the phone's bond store (Android)

* `bonds/<peer_id>.json`, one record per computer, alias unchanged
  (`deunlock.ed25519.<peer tail>`), so no Keystore migration is needed.
* Migration: `bond.json` present → write `bonds/<peer>.json`, keep the old file
  untouched for one release, log `bond store migrated`.
* Tests (JVM): migration keeps the alias and the bond key and still answers a
  challenge; two bonds are stored and listed; revoking one leaves the other; a
  corrupt new file falls back to the old one instead of losing the bond.

### W-4.4 — routing and the chooser (Android)

* `DeUnlockCompanionService` maps `peer_id → bond` instead of holding one record;
  the incoming session service already identifies the peer, and the LAN hello
  carries `host_id`.
* Home screen: a list of computers with the active one marked; "add a computer"
  starts the pair flow; revoke stays per-row.
* Tests: a challenge for peer A signs with A's alias (not B's); the chooser marks
  the peer of the last challenge; two desktops paired without revoking either.

### W-4.5 — the combinations, live

* Two phones → one desktop: both unlock `sudo`, one after the other, no re-pair.
* One phone → two desktops: each answers only its own challenge.
* **Cross-host replay (negative, the reason this stage exists):** capture a
  signature for computer A, present it to computer B → `bad-signature`, and the
  audit records it.
* `deunlock status` lists both phones with `live`/`stale` per peer (W-6 already
  keys that by peer).

## Risks and what would change the plan

| Risk | Mitigation |
|---|---|
| Rebuild blackout loses a challenge for an existing peer | measure first (W-4.2); queue rather than fail if it is wider than one interval |
| Window hides session UUIDs → one missed unlock | short, operator-initiated, announced in the CLI; persistent client makes reconnects rare |
| Pair window + code TTL disagree | one clock: the offer's own expiry decides both |
| Migration loses the only bond on this machine | old file kept, migration tested on a copy of the real `bond.json`, rollback is "delete `bonds/`" |
| GATT handles after a rebuild (D-18's warning) | the runtime test in W-4.2 is the gate; no merge without it |

## Open questions for the operator

1. Window length = the offer's own TTL, so there is one clock. The default is
   300 s (`pair-code --ttl`), and for those five minutes a bonded phone that has to
   reconnect will not see the host. Keep 300, or drop the default to 120 so the
   exposure is shorter but pairing has to start sooner?
2. Should `pair-code` refuse to mint an offer while another one is unspent, or
   replace it (today it replaces)?
