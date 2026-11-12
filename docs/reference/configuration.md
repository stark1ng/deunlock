# Configuration and storage

This page describes the active daemon and PAM configuration. It does not replace the design specification or change the service's authentication policy.

The presence daemon selects BlueZ's available default Bluetooth adapter at
startup. It does not assume the controller is named `hci0`; reinitialized
controllers can appear as `hci1` or later. After controller removal, restarting
the daemon selects the currently available adapter. An RPC status of `up` alone
does not establish that the desktop is advertising or the phone is subscribed.

## Files and ownership

| Path | Owner / use |
| --- | --- |
| `/var/lib/deunlock/bonds.toml` | Desktop application bond records: peer public keys, names, and status |
| `/var/lib/deunlock/keys/<peer_id>.bin` | Per-peer 32-byte application bond material; current desktop path reads files |
| `/var/lib/deunlock/last.log` | Authentication transaction log |
| `$XDG_RUNTIME_DIR/deunlock/auth.sock` | Daemon RPC socket, mode `0600` |
| `$XDG_RUNTIME_DIR/deunlock/presenced.pid` | Daemon single-instance lock |
| `$XDG_CONFIG_HOME/systemd/user/deunlock-presenced.service` | Installed user unit; falls back to `~/.config/systemd/user` |
| `/etc/pam.d/<service>` and `<service>.bak` | Service policy and the installer's saved original |
| Android app-private `deunlock-bond.toml` | Host metadata, application bond material, and a Keystore alias |

The intended default desktop store belongs to the desktop account running the daemon. Keep directories private (`0700`) and key files private (`0600`). The shared default path is not a separate store for each Linux account. Changing the daemon's storage flags alone does not change the PAM module's fixed bond directory.

When PAM creates `last.log` before the daemon starts, it uses mode `0600` and
the bond-store directory's owner and group. Existing records are preserved.
For a log created by an older version with root ownership, have an administrator
restore its ownership to the desktop account and its mode to `0600`; upgrading
does not change ownership of existing files.

Android's signing private key is represented by its Keystore alias. It is not a raw Ed25519 seed stored in that TOML file. See [storage boundaries](../explanation/security.md#implementation-and-design) for the difference between a Keystore signing key and the application's bond material.

## PAM socket resolution

The active parser accepts `socket=<path>`. It resolves the socket in this order:

1. An explicit `socket=` module argument.
2. `$XDG_RUNTIME_DIR/deunlock/auth.sock` when that environment variable is nonempty.
3. `/run/user/<effective-uid>/deunlock/auth.sock`.

Under a real PAM invocation the socket is resolved from the **account being authenticated**, not from the process: `sudo` runs the auth phase as root, and `/run/user/0/deunlock/auth.sock` has no daemon behind it. See [the entry point](../explanation/mechanics.md).

PAM can run under a different account or environment from the desktop session. Inspect the actual daemon path before selecting an override. The module reads `~/.local/share/deunlock/bonds.toml` (falling back to `/var/lib/deunlock/bonds.toml`) and chooses the first non-revoked peer in record order; it does not race all bonded phones.

The parser does not load `/etc/deunlock.conf`. Recognised module arguments:

| Argument | Effect |
| --- | --- |
| `socket=<path>` | Override the daemon socket |
| `timeout=<ms>` | PAM-side read budget; values below 1,000 ms are ignored |
| `choice=<ms>` | Phone-side budget when the caller has a terminal (default 6,000 ms), clipped by `timeout=` |
| `phone=off` | Skip the phone entirely; the next module prompts as usual |

Any other argument is ignored, because PAM stacks routinely carry arguments meant for other modules. `DEUNLOCK_OFF=1` in the environment has the same effect as `phone=off`.

## Deadlines and limits

| Setting | Active value | Effect |
| --- | --- | --- |
| Daemon challenge response deadline | 25,000 ms | Wait for the phone's response |
| PAM response read budget | 27,000 ms (`timeout=`) | Bound the blocking RPC read |
| Phone-side budget while the caller can type | 6,000 ms (`choice=`) | Stop asking once a password is the faster answer |
| Per-peer challenge slot | One | Serialize challenges to one phone |
| Per-peer queue wait | 1,000 ms | Return `busy` if the slot remains occupied |
| Daemon concurrent connection cap | Four | Limit simultaneous RPC handlers |
| Daemon replay cache | Last 64 accepted nonces per peer | Reject a cached nonce after signature verification |
| RPC CBOR payload cap | 65,536 bytes | Reject oversized local messages |

These limits come from source constants, not a user-editable config file. The replay cache is in memory for the daemon's lifetime. Its implementation is a bounded recent-nonce cache, not a persistent time-to-live database.

A caller that closes the socket is treated as withdrawn: the daemon abandons the challenge instead of holding the peer's single slot until the deadline. That is what makes the password path fast on the next attempt.

## PAM policy

The installer's current default line is:

```text
auth sufficient pam_deunlock.so timeout=27000
```

With `sufficient`, a success can end authentication if no earlier required module has failed; its failure is normally ignored while the stack continues. With `required`, failure remains a failure even if later modules succeed. A later password module does not automatically erase that failure. Extended control expressions can define other policies. These semantics come from the [Linux-PAM control-field reference](https://github.com/linux-pam/linux-pam/blob/master/doc/man/pam.conf-syntax.xml).

SPEC §3.2 D7 specifies `auth required`, while the installer emits `sufficient`. This is an existing implementation/design mismatch. The examples document the installer, not an approval to weaken D7. An administrator must select the intended policy for the complete service stack, including earlier modules, included stacks, and recovery behavior.

### The terminal offers a choice

With a terminal available the module prints one line and reads it with echo off while the challenge runs:

```text
Confirm on your phone, or type your password: _
```

Whichever answers first wins. A password cancels the challenge (the socket is closed) and is handed to the stack through `PAM_AUTHTOK`; the module then returns `PAM_IGNORE`, so the next auth module verifies it. The module never verifies a password itself, so a typed password cannot authenticate anything on its own — that is why the return code is `PAM_IGNORE` and not `PAM_SUCCESS`. A password is never logged, never written to `last.log`, and never sent to the daemon.

Without a terminal (`cron`, a pipe, an `sshd` session with no pty) nothing is printed and the phone keeps the full `timeout=` budget, as before.

### Results returned to PAM

| Return code | When |
| --- | --- |
| `PAM_SUCCESS` | The phone signed the challenge |
| `PAM_IGNORE` | The operator typed a password; it is now `PAM_AUTHTOK` for the next module |
| `PAM_AUTHINFO_UNAVAIL` | No bond, daemon down, phone offline, nobody answered, or the phone is disabled — the stack falls through |
| `PAM_AUTH_ERR` | The phone denied, a replayed challenge, or a signature that did not verify — the stack stops |

Returning an error does not alone determine whether the whole stack permits access; see [the result mapping](protocol.md#results-returned-to-pam).

## Service installation

`install-presenced` writes a user unit before attempting binary installation. The live path copies the selected source to `/usr/local/libexec/deunlock-presenced` and runs `systemctl --user daemon-reload` and `enable --now`. That copy needs permission to write the destination.

`--dry-run --from /usr/local/libexec/deunlock-presenced` writes a unit pointing at the preinstalled binary and prints the systemctl commands without running them. It is not a filesystem-free preview. `--unit-dir` changes where the unit is written.

The shipped unit restarts on failure and restricts filesystem writes to its configured paths. If you override data paths, review the unit's `ReadWritePaths` too. Its user-session lifetime also matters for authentication before login: a stopped user service cannot answer requests.

Source: [PAM configuration](https://github.com/Mewplane/deunlock/blob/648375e/crates/deunlock-pam/src/config.rs), [orchestrator limits](https://github.com/Mewplane/deunlock/blob/648375e/crates/deunlock-presenced/src/orchestrator.rs), [user unit](https://github.com/Mewplane/deunlock/blob/648375e/crates/deunlock-presenced/dist/deunlock-presenced.service).

<!-- Structure: Diátaxis reference; original prose for deunlock. -->
