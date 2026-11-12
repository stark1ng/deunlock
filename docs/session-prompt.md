# Prompt for the next session

Paste the block below as the first message of a fresh session. It is written to
be self-contained: a new session starts with no memory of the previous one.

---

We continue DeUnlock — an open-source PulseUnlock equivalent: the phone confirms
a desktop password prompt (`sudo`, polkit, lock screen) with fingerprint/face, and
nothing but an Ed25519 signature ever leaves the phone. Fork of `syauth` (MIT),
Linux-first, Rust daemon + PAM module + CLI, Kotlin/Compose phone app over UniFFI.

Repo: `/mnt/king4tb/CODE/deunlock`, branch `main`, remote
`git@github.com:stark1ng/deunlock.git`, identity "First Star King"
<messier7four@gmail.com>. Start by reading, in this order:

1. `docs/project-plan.md` — the six work packages left, their acceptance
   criteria and the order (W-1 first: a choice between phone and password in the
   terminal instead of a silent 27 s wait).
2. The tail of `specs/deunlock/AUDIT-001.md` — every defect measured so far,
   D-01 … D-26b, with the log lines that proved each one. New findings continue
   at D-27.
3. `docs/next-slices.md` — why each package exists, in the operator's words.

Then verify the state before touching code (all of this worked at the end of the
previous session):

- daemon: `systemctl --user status deunlock-presenced` (active), socket
  `/run/user/1000/deunlock/auth.sock`, state in `~/.local/share/deunlock`
  (`host.key`, `bonds.toml`, `keys`), host_id `b254fffb…`
- bonded peer `14f3a566465f2d29c16564ef2be12fd9`
- `pam_deunlock.so` installed, `/etc/pam.d/sudo` has
  `auth sufficient pam_deunlock.so timeout=27000` first, backup
  `sudo.deunlock.bak` present
- phone: Redmi 23122PCD1G (garnet), Android 16 / HyperOS, package
  `com.sy.deunlock.android`, attached over **Wi-Fi** (no cable needed)

Commands you will need:

```bash
cd /mnt/king4tb/CODE/deunlock
export ANDROID_HOME=/mnt/king4tb/tools/android-sdk
export JAVA_HOME=/mnt/king4tb/tools/jdk-17.0.21+9
ADB=$ANDROID_HOME/platform-tools/adb

# Rust: run ONCE, into a file, with -j 3 (a full run without it gets OOM-killed)
cargo test --workspace -j 3 > /tmp/fN.log 2>&1; tail -3 /tmp/fN.log
cargo clippy --workspace --all-targets -j 3 -- -D warnings

# Android
cd deunlock-android && ./gradlew --no-daemon --console=plain testDebugUnitTest assembleDebug
$ADB install -r app/build/outputs/apk/debug/app-debug.apk

# Phone over Wi-Fi (IP:port changes; rediscover if connect fails)
$ADB mdns services            # _adb-tls-connect._tcp → the address to use
$ADB connect 192.168.10.87:38771

# Pairing and verification
DEUNLOCK_HOST_KEY=$HOME/.local/share/deunlock/host.key ./target/release/deunlock pair-code
pamtester sudo roma authenticate          # runs the real stack, no password, no root
sudo true                                 # the human-visible path
```

Rules that are not negotiable:

- Security first: every protocol/state change needs a negative test (forged MAC,
  foreign host_id, replay, wrong pairing code). No test, no merge.
- The phone's private key never leaves the Android Keystore; the challenge MAC is
  verified before the biometric prompt.
- Privileged install steps are run by me, not by you: print the exact command,
  keep the `.bak`, print the rollback.
- `sudo -n` is not a test of the PAM stack (it never runs the auth conversation) —
  use `pamtester`, then an interactive `sudo true`.
- Backups are flat and dated: `cp f backups/f.YYYY-MM-DD.bak`.
- One work package per commit, with its measurement in the message; push to
  `main` only with the suite and clippy green.
- Never ask me for a password; never put one in chat.
- Android logcat: capture to a file then grep (`adb logcat -d -b main > /tmp/lc.txt`);
  `adb install -r` kills the app, so relaunch and wait a few seconds before judging.

Start with **W-1**: teach the PAM module to offer a real choice — print one line,
open a `PAM_PROMPT_ECHO_OFF` conversation on the caller's tty, run the challenge
beside it, and take whichever answers first (a typed password cancels the
challenge and is never logged or forwarded). Write the pty tests before touching
the live `sudo`. Report with the stage table (done / current / open) and the log
line or test count behind each claim.
