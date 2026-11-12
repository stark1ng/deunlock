//! W-1 — the terminal offers a choice instead of a silent wait.
//!
//! Before this module the PAM stack asked the phone and said nothing: an
//! operator who wanted to type had to sit through the whole 27 s deadline, and
//! an operator who wanted the phone had no idea anything was happening. The
//! module now prints one line on the caller's terminal, opens an echo-off read
//! on it, and runs the challenge beside it:
//!
//! ```text
//! Confirm on your phone, or type your password: _
//! ```
//!
//! Whichever answers first wins:
//!
//! * **password** — the challenge socket is closed (which cancels it; see
//!   `auth::PendingChallenge`) and the bytes are handed back to the caller as
//!   [`Choice::Password`]. They are never logged, never written to `last.log`
//!   and never sent to the daemon. The caller installs them as `PAM_AUTHTOK`
//!   and returns `PAM_IGNORE`, so the *next* module in the stack (pam_unix)
//!   verifies them — this module never authenticates a password itself.
//! * **phone** — the typed bytes, if any, are discarded (`tcflush`) and the
//!   verdict is [`Choice::Phone`].
//! * **neither** — [`Choice::Deadline`]; the caller falls through to the
//!   password prompt as it did before W-1.
//!
//! Two budgets, because they are two different situations. With a terminal the
//! phone side is capped at a few seconds ([`DEFAULT_CHOICE_WINDOW`]): a typist
//! wins immediately, a phone user reaches the sensor in ~4 s, and nobody is
//! asked to stare at a prompt that cannot be answered. Without a terminal
//! (cron, a pipe, an `sshd` session with no pty) there is nothing to type, so
//! the full `timeout=` budget still applies.
//!
//! Everything here is safe to fail: no terminal, no daemon, no bonds, or
//! `phone=off` all end in a plain fall-through, never in a locked-out machine.

use std::{
    fs::{File, OpenOptions},
    io::{Read as _, Write as _},
    os::{
        fd::{AsFd as _, AsRawFd as _},
        unix::fs::OpenOptionsExt as _,
    },
    time::{Duration, Instant},
};

use deunlock_presenced::{OUTCOME_REASON_TRANSPORT_ERROR, Response, read_frame_blocking};
use nix::{
    errno::Errno,
    poll::{PollFd, PollFlags, PollTimeout, poll},
    sys::termios::{LocalFlags, SetArg, Termios, tcgetattr, tcsetattr},
};

use crate::{
    auth::{self, AuthOutcome, PamContext, PendingChallenge},
    config::Config,
};

/// The one line printed before anything is asked (W-1 deliverable).
pub const CHOICE_PROMPT: &str = "Confirm on your phone, or type your password: ";

/// Phone-side budget when the caller can type.
///
/// Measured on the reference phone: ~4 s from the notification to the sensor
/// answering. Six seconds leaves room for a slow first press without making a
/// typist wait for a phone that is in another room.
pub const DEFAULT_CHOICE_WINDOW: Duration = Duration::from_millis(6_000);

/// Floor for an operator-supplied `choice=<ms>`.
pub const MIN_CHOICE_WINDOW_MS: u64 = 1_000;

/// Longest password accepted from the terminal. Linux-PAM's own
/// `PAM_MAX_RESP_SIZE` is 512; anything larger is not a password.
pub const MAX_PASSWORD_LEN: usize = 512;

/// libpam argument that skips the phone entirely: `pam_deunlock.so phone=off`.
pub const PAM_PHONE_OFF_ARG: &str = "phone=off";

/// libpam argument for the phone-side budget: `choice=4000`.
pub const PAM_CHOICE_ARG_PREFIX: &str = "choice=";

/// Environment switch that skips the phone entirely, for a machine whose
/// pairing is broken. `DEUNLOCK_OFF=1`.
pub const DISABLE_ENV: &str = "DEUNLOCK_OFF";

/// What the race produced.
#[derive(Debug)]
pub enum Choice {
    /// The daemon answered for the phone. Carry the verdict to the caller.
    Phone(AuthOutcome),
    /// The operator typed a password. Hand it to the next module; never log it.
    Password(SecretBytes),
    /// Nothing answered inside the window. Fall through to the password.
    Deadline,
    /// The phone was disabled for this invocation (`phone=off` / `DEUNLOCK_OFF`).
    PhoneDisabled,
}

/// A typed password: zeroed on drop, redacted in `Debug`, never `Display`.
///
/// The bytes are the operator's password. They exist only between the terminal
/// read and `pam_set_item(PAM_AUTHTOK)`, and nothing in this crate may copy
/// them into a log line, an audit file or the daemon socket.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wrap raw terminal bytes, dropping the line terminator.
    #[must_use]
    pub fn from_terminal(mut bytes: Vec<u8>) -> Self {
        while matches!(bytes.last(), Some(b'\n' | b'\r')) {
            bytes.pop();
        }
        Self(bytes)
    }

    /// Read-only view for `pam_set_item`. Never log the result.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Whether the operator pressed Enter on an empty line.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately no length either: it is a side channel nobody needs.
        f.write_str("SecretBytes(<redacted>)")
    }
}

/// Whether the phone may be asked at all for this invocation.
///
/// `DEUNLOCK_OFF=1` (any non-empty value except `0`) and the `phone=off`
/// module argument are the documented escape hatches: a broken pairing must
/// degrade to a normal password prompt, never to a machine nobody can enter.
#[must_use]
pub fn phone_enabled(argv: &[&str], disable_env: Option<&str>) -> bool {
    let env_off = disable_env.is_some_and(|raw| {
        let raw = raw.trim();
        !raw.is_empty() && raw != "0"
    });
    let arg_off = argv.iter().any(|arg| arg.eq_ignore_ascii_case(PAM_PHONE_OFF_ARG));
    !(env_off || arg_off)
}

/// Phone-side budget for this invocation: `choice=<ms>` if given, else
/// [`DEFAULT_CHOICE_WINDOW`], never above the module's own `timeout=`.
#[must_use]
pub fn choice_window(argv: &[&str], auth_timeout: Duration) -> Duration {
    argv.iter()
        .find_map(|arg| arg.strip_prefix(PAM_CHOICE_ARG_PREFIX))
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|ms| *ms >= MIN_CHOICE_WINDOW_MS)
        .map_or(DEFAULT_CHOICE_WINDOW, Duration::from_millis)
        .min(auth_timeout)
}

/// Offer the choice and return whichever side answered first.
///
/// `pam_tty` is the `PAM_TTY` item; `None` (or a path that will not open) falls
/// back to `/dev/tty`, and if neither is a terminal the phone is simply asked
/// for the full budget with no prompt — the pre-W-1 behaviour.
#[must_use]
pub fn run(cfg: &Config, ctx: &PamContext, argv: &[&str], pam_tty: Option<&str>) -> Choice {
    let disable_env = std::env::var(DISABLE_ENV).ok();
    if !phone_enabled(argv, disable_env.as_deref()) {
        return Choice::PhoneDisabled;
    }

    // Open the terminal BEFORE the challenge: if there is no terminal there is
    // also no reason to shorten the phone budget, and no prompt to print.
    let tty = CallerTty::open(pam_tty);
    let window = match tty {
        Some(_) => choice_window(argv, cfg.auth_timeout),
        None => cfg.auth_timeout.min(auth::DAEMON_RESPONSE_BUDGET),
    };

    let mut pending = match auth::begin_challenge(cfg, ctx) {
        Ok(pending) => pending,
        // No bond, daemon down, socket unwritable: do not print a prompt we
        // cannot honour. The next module's password prompt is the honest thing
        // to show, exactly as before W-1.
        Err(outcome) => return Choice::Phone(outcome),
    };

    match tty {
        Some(mut tty) => race(&mut pending, &mut tty, window),
        None => Choice::Phone(pending.read_answer()),
    }
}

/// Poll the terminal and the daemon socket until one of them answers.
fn race(pending: &mut PendingChallenge, tty: &mut CallerTty, window: Duration) -> Choice {
    tty.write_prompt(CHOICE_PROMPT);

    let deadline = Instant::now() + window;
    let mut tty_live = true;
    let mut buf = [0u8; MAX_PASSWORD_LEN];

    loop {
        let now = Instant::now();
        if now >= deadline {
            // Neither side answered. The tty guard restores echo, ends our
            // line and flushes what was half-typed, so the password prompt the
            // next module prints is clean.
            return Choice::Deadline;
        }
        let remaining = deadline - now;
        let timeout_ms = u16::try_from(remaining.as_millis().min(u128::from(u16::MAX))).unwrap_or(u16::MAX);

        let (tty_ready, socket_ready) = {
            let mut fds: Vec<PollFd<'_>> = Vec::with_capacity(2);
            if tty_live {
                fds.push(PollFd::new(tty.as_fd(), PollFlags::POLLIN));
            }
            fds.push(PollFd::new(pending.stream.as_fd(), PollFlags::POLLIN));
            match poll(&mut fds, PollTimeout::from(timeout_ms)) {
                Ok(0) => (false, false),
                Ok(_) => {
                    let socket = fds.last().is_some_and(|fd| {
                        fd.revents()
                            .is_some_and(|ev| ev.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR))
                    });
                    let terminal = tty_live
                        && fds.first().is_some_and(|fd| {
                            fd.revents().is_some_and(|ev| ev.intersects(PollFlags::POLLIN | PollFlags::POLLHUP))
                        });
                    (terminal, socket)
                }
                // A signal interrupted the wait; the deadline above is the
                // only clock that matters, so just look again.
                Err(Errno::EINTR) => (false, false),
                // Poll itself is broken (closed fd, no memory). Stop waiting
                // for the phone; the password path must stay reachable.
                Err(_) => return Choice::Deadline,
            }
        };

        if socket_ready {
            return Choice::Phone(read_verdict(pending));
        }

        if tty_ready {
            match tty.read_line(&mut buf) {
                LineRead::Line(len) => {
                    // The line was consumed; nothing is left to discard.
                    tty.input_consumed();
                    return Choice::Password(SecretBytes::from_terminal(buf[..len].to_vec()));
                }
                // The operator's terminal went away mid-race (logout, ssh
                // drop). Keep waiting for the phone until the deadline.
                LineRead::Eof | LineRead::Failed => tty_live = false,
            }
        }
    }
}

/// Read one reply frame and map it to a verdict. A broken frame is a transport
/// error, not a decision — the stack then falls through to the password.
fn read_verdict(pending: &mut PendingChallenge) -> AuthOutcome {
    match read_frame_blocking::<_, Response>(&mut pending.stream) {
        Ok(response) => auth::resolve_response(&pending.peer_id, &pending.nonce, response),
        Err(_) => AuthOutcome::AuthInfoUnavail {
            reason: OUTCOME_REASON_TRANSPORT_ERROR,
            peer_id: Some(pending.peer_id.clone()),
        },
    }
}

/// Result of one terminal read.
enum LineRead {
    /// A complete line, of `usize` bytes, in the caller's buffer.
    Line(usize),
    /// The terminal reported end-of-file.
    Eof,
    /// The read failed for any other reason.
    Failed,
}

/// The caller's terminal, with echo off for as long as this value exists.
///
/// `Drop` is the only restore path: every early return, panic and error in
/// between leaves the operator's terminal exactly as it was found.
struct CallerTty {
    file: File,
    original: Termios,
    /// True once the prompt is on screen and our line is still open.
    prompt_open: bool,
    /// Whether unread bytes should be thrown away on the way out.
    discard_input: bool,
}

impl CallerTty {
    /// Open the caller's terminal and turn echo off.
    ///
    /// Which terminal, and whether we may use one at all:
    ///
    /// * `PAM_TTY` is an absolute path — that is the terminal the stack says it
    ///   is talking to (`sudo` sets it, so does `login`/`su`/`pamtester`). Use it.
    /// * `PAM_TTY` names something else — a GUI stack that invented a
    ///   pseudo-terminal name, e.g. a lock screen. No choice: its keyboard is a
    ///   window, not this tty.
    /// * `PAM_TTY` is absent — fall back to `/dev/tty`, but only when **we are
    ///   the foreground job** of that terminal. A GUI helper inherits the X
    ///   session's `/dev/tty` without owning its keyboard; printing a prompt
    ///   there would be invisible and reading it would race the application that
    ///   does own the keystrokes.
    ///
    /// Returns `None` in all the other cases: a pipe, `cron`, an sshd session
    /// without a pty, or a terminal that refuses echo-off. Half a password
    /// prompt is worse than none.
    fn open(pam_tty: Option<&str>) -> Option<Self> {
        match pam_tty {
            // A path is the caller naming its own terminal; trust it and do not
            // wander off to /dev/tty if it turns out not to be one.
            Some(path) if path.starts_with('/') => Self::open_path(path),
            // A bare name (or empty) is a stack that has no terminal to offer.
            Some(_) => None,
            None => {
                let file = Self::open_path("/dev/tty")?;
                // `/dev/tty` is only ours if our process group owns the
                // keyboard: `tcgetpgrp` reports the foreground group.
                let foreground = match nix::unistd::tcgetpgrp(file.as_fd()) {
                    Ok(pgrp) if pgrp == nix::unistd::getpgrp() => true,
                    // A tty with no session gets EIO; a tty owned by somebody
                    // else gets their pgroup. Both mean "not ours".
                    _ => false,
                };
                if foreground {
                    Some(file)
                } else {
                    None
                }
            }
        }
    }

    /// Open `path` and turn echo off, or `None` when it is not a terminal.
    fn open_path(path: &str) -> Option<Self> {
        // `O_NOCTTY`: opening the terminal must never make it our controlling
        // terminal.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(path)
            .ok()?;
        let original = tcgetattr(&file).ok()?;
        let mut quiet = original.clone();
        // Echo off exactly like a password prompt: ICANON stays on so the
        // kernel does the line editing, ISIG stays on so Ctrl-C still
        // interrupts, and ECHONL is off so the Enter key does not leak a
        // newline we did not write.
        quiet
            .local_flags
            .remove(LocalFlags::ECHO | LocalFlags::ECHOE | LocalFlags::ECHOK | LocalFlags::ECHONL);
        tcsetattr(&file, SetArg::TCSANOW, &quiet).ok()?;
        Some(Self {
            file,
            original,
            prompt_open: false,
            discard_input: true,
        })
    }

    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.file.as_fd()
    }

    fn write_prompt(&mut self, prompt: &str) {
        if (&self.file).write_all(prompt.as_bytes()).is_ok() {
            let _ = (&self.file).flush();
            self.prompt_open = true;
        }
    }

    /// One canonical-mode read. The caller only calls this after `poll` said
    /// the fd is readable, so the line is already in the queue.
    fn read_line(&mut self, buf: &mut [u8]) -> LineRead {
        match (&self.file).read(buf) {
            Ok(0) => LineRead::Eof,
            Ok(n) => LineRead::Line(n),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => LineRead::Failed,
            Err(_) => LineRead::Failed,
        }
    }

    /// The operator's line was read: nothing is left to discard.
    fn input_consumed(&mut self) {
        self.discard_input = false;
    }
}

impl Drop for CallerTty {
    fn drop(&mut self) {
        // Echo back on first: everything after this point may be read by the
        // next prompt in the stack.
        let _ = tcsetattr(&self.file, SetArg::TCSANOW, &self.original);
        if self.prompt_open {
            // ECHONL was off, so neither the Enter key nor the absence of one
            // left a newline behind. End our line ourselves.
            let _ = (&self.file).write_all(b"\n");
            let _ = (&self.file).flush();
        }
        if self.discard_input {
            // Half-typed bytes belong to nobody: a phone approval must not
            // leave the first characters of a password sitting in the queue
            // for whatever reads the terminal next.
            // SAFETY: `self.file` owns an open descriptor for the duration of
            // this call, and `tcflush` only reads that descriptor.
            unsafe {
                libc::tcflush(self.file.as_raw_fd(), libc::TCIFLUSH);
            }
        }
    }
}

// =============================================================================
// Tests — the parts that do not need a terminal
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The line is a deliverable: it is quoted in the plan and in the docs, and
    /// an operator-approved wording change must be a deliberate edit here.
    #[test]
    fn the_prompt_is_the_documented_line() {
        assert_eq!(CHOICE_PROMPT, "Confirm on your phone, or type your password: ");
    }

    #[test]
    fn the_phone_is_on_by_default() {
        assert!(phone_enabled(&[], None));
        assert!(phone_enabled(&["timeout=27000", "socket=/tmp/x.sock"], None));
        // "off" only when the value actually says so: `DEUNLOCK_OFF=0` is a
        // deliberate "leave it on".
        assert!(phone_enabled(&[], Some("0")));
        assert!(phone_enabled(&[], Some("")));
    }

    #[test]
    fn both_escape_hatches_disable_the_phone() {
        assert!(!phone_enabled(&[], Some("1")));
        assert!(!phone_enabled(&[], Some(" 1 ")));
        assert!(!phone_enabled(&["phone=off"], None));
        assert!(!phone_enabled(&["PHONE=OFF"], None));
        assert!(!phone_enabled(&["phone=off"], Some("1")));
        // A near miss is not an off switch.
        assert!(phone_enabled(&["phone"], None));
        assert!(phone_enabled(&["phone=on"], None));
    }

    #[test]
    fn the_window_defaults_and_is_bounded_by_the_module_timeout() {
        let timeout = Duration::from_millis(27_000);
        assert_eq!(choice_window(&[], timeout), DEFAULT_CHOICE_WINDOW);
        assert_eq!(choice_window(&["choice=3000"], timeout), Duration::from_millis(3_000));
        // Below the floor the argument is a typo, not a request.
        assert_eq!(choice_window(&["choice=10"], timeout), DEFAULT_CHOICE_WINDOW);
        assert_eq!(choice_window(&["choice=nonsense"], timeout), DEFAULT_CHOICE_WINDOW);
        // A window longer than the module's own budget is clipped.
        assert_eq!(
            choice_window(&["choice=9000"], Duration::from_millis(5_000)),
            Duration::from_millis(5_000)
        );
    }

    #[test]
    fn a_typed_line_loses_its_terminator() {
        assert_eq!(SecretBytes::from_terminal(b"hunter2\n".to_vec()).expose(), b"hunter2");
        assert_eq!(SecretBytes::from_terminal(b"hunter2\r\n".to_vec()).expose(), b"hunter2");
        assert_eq!(SecretBytes::from_terminal(b"hunter2".to_vec()).expose(), b"hunter2");
        assert!(SecretBytes::from_terminal(b"\n".to_vec()).is_empty());
    }

    /// A password must never reach a log line through `{:?}` on an error path.
    #[test]
    fn a_secret_never_prints_itself() {
        let secret = SecretBytes::from_terminal(b"correct-horse".to_vec());
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "SecretBytes(<redacted>)");
        assert!(!rendered.contains("correct"));
    }
}
