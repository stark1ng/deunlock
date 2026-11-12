//! W-1 acceptance, driven through a real pty.
//!
//! The deliverable is a race between a terminal and a phone, so the tests race
//! a real terminal against a mock daemon rather than trusting a unit-level
//! stand-in for `poll`. Each test owns a pty pair: the module opens the slave
//! (exactly as it opens `PAM_TTY` / `/dev/tty`), the test writes to the master
//! the way a human types.
//!
//! Covered, in the order the acceptance criterion lists them:
//!
//! 1. password first → the typed line comes back, the challenge is cancelled
//!    (the daemon sees the socket close), and the password never reaches the
//!    wire, the audit file or the terminal echo;
//! 2. phone first → the verdict is the phone's and a half-typed line is thrown
//!    away instead of leaking into the next prompt;
//! 3. neither → the window expires, the prompt line is closed, echo is back on
//!    and the terminal still works for the password prompt that follows;
//! 4. `phone=off` → no socket, no prompt, straight to the password path.

use std::{
    io::{Cursor, ErrorKind, Read as _, Write as _},
    os::{
        fd::AsFd as _,
        fd::AsRawFd as _,
        unix::net::UnixListener,
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use deunlock_core::{Bond, BondStatus, BondStore, SIGNATURE_LEN, peer_id_from_pubkey};
use deunlock_presenced::{Request, Response, read_frame_blocking, write_frame_blocking};
use nix::{
    fcntl::{FcntlArg, OFlag, fcntl},
    poll::{PollFd, PollFlags, PollTimeout, poll},
    pty::openpty,
    sys::termios::{LocalFlags, tcgetattr},
};
use pam_deunlock::{
    auth::PamContext,
    choice::{self, CHOICE_PROMPT, Choice},
    config::Config,
};
use tempfile::TempDir;
use time::OffsetDateTime;

// =============================================================================
// Mock daemon
// =============================================================================

/// How the mock daemon answers the one challenge it receives.
enum Mode {
    /// Read the request and then hold the connection until the caller hangs up.
    /// The hang-up is the cancellation signal under test.
    Silent,
    /// Answer `ok` after `delay`, echoing the caller's peer id and nonce.
    AnswerAfter(Duration),
}

/// What the mock daemon observed, in order.
#[derive(Debug)]
enum Event {
    /// A caller connected.
    Connected,
    /// The raw bytes of the first frame the caller wrote.
    Request(Vec<u8>),
    /// The caller closed the socket before the daemon answered.
    CallerClosed,
    /// The daemon wrote its verdict.
    Answered,
}

struct MockDaemon {
    events: mpsc::Receiver<Event>,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockDaemon {
    fn spawn(socket: &Path, mode: Mode) -> Self {
        let listener = UnixListener::bind(socket).expect("bind mock daemon");
        // Non-blocking accept with a stop flag: the `phone=off` and
        // `DEUNLOCK_OFF` tests must be able to drop a daemon nobody ever
        // connected to without waiting for a connection that will not come.
        listener.set_nonblocking(true).expect("nonblocking listener");
        let (tx, rx) = mpsc::channel();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&connections);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut stream = loop {
                if stop_flag.load(Ordering::SeqCst) {
                    return;
                }
                match listener.accept() {
                    Ok((stream, _addr)) => break stream,
                    Err(err) if err.kind() == ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(5)),
                    Err(_) => return,
                }
            };
            // The stream must block: the module writes once and waits, and a
            // non-blocking read would report WouldBlock instead of the frame.
            stream.set_nonblocking(false).expect("blocking connection");
            counter.fetch_add(1, Ordering::SeqCst);
            let _ = tx.send(Event::Connected);
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

            let mut raw = Vec::new();
            let mut buf = [0u8; 2048];
            if let Ok(n) = stream.read(&mut buf) {
                raw.extend_from_slice(&buf[..n]);
            }
            let _ = tx.send(Event::Request(raw.clone()));

            match mode {
                Mode::Silent => {
                    let mut sink = [0u8; 64];
                    loop {
                        match stream.read(&mut sink) {
                            // EOF is what the module's dropped socket looks
                            // like from here: the challenge was cancelled.
                            Ok(0) | Err(_) => {
                                let _ = tx.send(Event::CallerClosed);
                                break;
                            }
                            Ok(_) => continue,
                        }
                    }
                }
                Mode::AnswerAfter(delay) => {
                    thread::sleep(delay);
                    let Ok(Request::Challenge { peer_id, nonce, .. }) =
                        read_frame_blocking::<_, Request>(&mut Cursor::new(raw))
                    else {
                        return;
                    };
                    let response = Response::Challenge {
                        ok: true,
                        signature: Some(vec![0xAA; SIGNATURE_LEN]),
                        reason: "ok".to_string(),
                        peer_id,
                        nonce,
                    };
                    if write_frame_blocking(&mut stream, &response).is_ok() {
                        let _ = tx.send(Event::Answered);
                    }
                }
            }
        });
        Self {
            events: rx,
            connections,
            stop,
            handle: Some(handle),
        }
    }

    /// Collect events until `stop` (or a timeout) so a test can assert on the
    /// whole conversation rather than one message.
    fn events_until(&self, stop: Event, within: Duration) -> Vec<Event> {
        let deadline = Instant::now() + within;
        let mut seen = Vec::new();
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.events.recv_timeout(left) {
                Ok(event) => {
                    let done = std::mem::discriminant(&event) == std::mem::discriminant(&stop);
                    seen.push(event);
                    if done {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        seen
    }
}

impl Drop for MockDaemon {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

// =============================================================================
// pty fixture
// =============================================================================

/// A pty pair plus the slave's path — the string a PAM stack would hand us as
/// `PAM_TTY`.
struct Pty {
    master: std::fs::File,
    slave: std::fs::File,
    slave_path: PathBuf,
}

fn pty() -> Pty {
    let pair = openpty(None::<&nix::pty::Winsize>, None::<&nix::sys::termios::Termios>).expect("openpty");
    let slave_path = std::fs::read_link(format!("/proc/self/fd/{}", pair.slave.as_raw_fd())).expect("/proc fd symlink");
    Pty {
        master: std::fs::File::from(pair.master),
        slave: std::fs::File::from(pair.slave),
        slave_path,
    }
}

impl Pty {
    /// Write bytes to the terminal exactly as a human's keyboard would.
    fn type_str(&self, text: &str) {
        let mut master = &self.master;
        master.write_all(text.as_bytes()).expect("write to pty master");
        master.flush().expect("flush pty master");
    }

    /// Everything the module has written to the terminal so far.
    ///
    /// The module writes the prompt and its closing newline as separate
    /// `write` calls, so one `read` can return only the first — drain until the
    /// master goes quiet for a beat instead of assuming a single write.
    fn output(&self, within: Duration) -> Vec<u8> {
        let deadline = Instant::now() + within;
        let mut out = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let slice = left.min(Duration::from_millis(100));
            let mut fds = [PollFd::new(self.master.as_fd(), PollFlags::POLLIN)];
            let timeout = u16::try_from(slice.as_millis()).unwrap_or(u16::MAX);
            match poll(&mut fds, PollTimeout::from(timeout)) {
                Ok(ready) if ready > 0 => {
                    let mut buf = vec![0u8; 512];
                    let mut master = &self.master;
                    match master.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.truncate(n);
                            out.extend_from_slice(&buf);
                        }
                        Err(_) => break,
                    }
                }
                _ => break,
            }
        }
        out
    }

    fn echo_enabled(&self) -> bool {
        tcgetattr(&self.slave)
            .expect("tcgetattr on the pty slave")
            .local_flags
            .contains(LocalFlags::ECHO)
    }

    /// Assert nothing is queued for whatever reads the terminal next.
    fn assert_no_pending_input(&self) {
        let flags = OFlag::from_bits_truncate(fcntl(self.slave.as_raw_fd(), FcntlArg::F_GETFL).expect("F_GETFL"));
        fcntl(self.slave.as_raw_fd(), FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).expect("F_SETFL");
        let mut buf = [0u8; 64];
        let mut slave = &self.slave;
        match slave.read(&mut buf) {
            Err(err) if err.kind() == ErrorKind::WouldBlock => {}
            Ok(0) => {}
            other => panic!("typed bytes were not discarded; the terminal still had {other:?}"),
        }
    }
}

// =============================================================================
// Config fixture
// =============================================================================

fn tempdir_0o700() -> TempDir {
    use std::os::unix::fs::PermissionsExt as _;
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut perm = std::fs::metadata(tmp.path()).expect("stat").permissions();
    perm.set_mode(0o700);
    std::fs::set_permissions(tmp.path(), perm).expect("chmod");
    tmp
}

fn config_with_one_bonded_peer() -> (TempDir, Config) {
    let pubkey = [0x42u8; 32];
    let peer_id = peer_id_from_pubkey(&pubkey);
    let tmp = tempdir_0o700();
    let mut store = BondStore::empty();
    store
        .add(Bond {
            peer_id,
            pubkey,
            name: "test".to_string(),
            created_at: OffsetDateTime::now_utc(),
            status: BondStatus::Bonded,
        })
        .expect("add bond");
    store.save(&tmp.path().join("bonds.toml")).expect("save bonds");
    let cfg = Config::for_tests(tmp.path()).with_socket_path(tmp.path().join("auth.sock"));
    (tmp, cfg)
}

fn context() -> PamContext {
    PamContext {
        service: "sudo".to_string(),
        user: "romatest".to_string(),
    }
}

/// The escape hatches must not be inherited from the developer's shell, and
/// tests run in parallel: one process-wide lock keeps `DEUNLOCK_OFF` from
/// crossing between them.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn clear_disable_env() {
    // SAFETY: the caller holds ENV_LOCK, so no other test touches this
    // variable while we do.
    unsafe {
        std::env::remove_var(choice::DISABLE_ENV);
    }
}

// =============================================================================
// 1. password first — the phone is cancelled
// =============================================================================

#[test]
fn password_first_wins_and_cancels_the_challenge() {
    let _env = env_guard();
    clear_disable_env();
    let (tmp, cfg) = config_with_one_bonded_peer();
    let daemon = MockDaemon::spawn(&cfg.socket_path, Mode::Silent);
    let pty = pty();

    // Type 150 ms after the prompt appears: well inside the 6 s window.
    let typist = {
        let master = pty.master.try_clone().expect("clone master");
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            let mut out = &master;
            out.write_all(b"hunter2-no-such-password\n").expect("type");
            out.flush().expect("flush");
        })
    };

    let started = Instant::now();
    let choice = choice::run(&cfg, &context(), &[], Some(pty.slave_path.to_str().expect("utf8 path")));
    let elapsed = started.elapsed();
    typist.join().expect("typist thread");

    let Choice::Password(secret) = choice else {
        panic!("a typed password inside the window must win; got {choice:?}");
    };
    assert_eq!(secret.expose(), b"hunter2-no-such-password");
    assert!(
        elapsed < Duration::from_secs(2),
        "a typist must not wait for the phone budget; took {elapsed:?}"
    );

    // The prompt was printed, and the password was never echoed back.
    let screen = pty.output(Duration::from_millis(500));
    let screen = String::from_utf8_lossy(&screen);
    assert!(
        screen.starts_with(CHOICE_PROMPT),
        "the choice line must be printed first; screen was {screen:?}"
    );
    assert!(
        !screen.contains("hunter2"),
        "echo was off, so the password must not appear on the terminal; screen was {screen:?}"
    );

    // Echo is back on for whatever prompts next.
    assert!(pty.echo_enabled(), "echo must be restored before returning");

    // The daemon saw the caller hang up: that is the cancellation.
    let events = daemon.events_until(Event::CallerClosed, Duration::from_secs(3));
    let closed = events.iter().any(|e| matches!(e, Event::CallerClosed));
    assert!(closed, "dropping the challenge must close the daemon socket; saw {events:?}");

    // And the password never travelled: not in the request frame, not in the
    // audit file (which the password path must not write at all).
    let wire = events
        .iter()
        .find_map(|e| match e {
            Event::Request(raw) => Some(raw.clone()),
            _ => None,
        })
        .expect("the daemon received a request frame");
    assert!(
        !wire.windows(b"hunter2".len()).any(|w| w == b"hunter2"),
        "the typed password must never be forwarded to the daemon"
    );
    let audit = cfg.last_log_path();
    if audit.exists() {
        let logged = std::fs::read_to_string(&audit).expect("read last.log");
        assert!(
            !logged.contains("hunter2"),
            "the typed password must never reach last.log; file was {logged:?}"
        );
    }
    assert_eq!(daemon.connections.load(Ordering::SeqCst), 1);
    drop(tmp);
}

// =============================================================================
// 2. phone first — the half-typed line is discarded
// =============================================================================

#[test]
fn phone_first_wins_and_discards_what_was_typed() {
    let _env = env_guard();
    clear_disable_env();
    let (_tmp, cfg) = config_with_one_bonded_peer();
    let daemon = MockDaemon::spawn(&cfg.socket_path, Mode::AnswerAfter(Duration::from_millis(250)));
    let pty = pty();

    // A partial password — no newline, so nothing is submitted.
    let typist = {
        let master = pty.master.try_clone().expect("clone master");
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(80));
            let mut out = &master;
            out.write_all(b"hunter").expect("type");
            out.flush().expect("flush");
        })
    };

    let choice = choice::run(&cfg, &context(), &[], Some(pty.slave_path.to_str().expect("utf8 path")));
    typist.join().expect("typist thread");

    let Choice::Phone(outcome) = choice else {
        panic!("the phone answered first, so its verdict must win; got {choice:?}");
    };
    assert!(outcome.is_success(), "the mock daemon signed a valid answer; got {outcome:?}");

    // The half-typed bytes must not be left for the next prompt to consume.
    pty.assert_no_pending_input();
    assert!(pty.echo_enabled(), "echo must be restored before returning");

    let events = daemon.events_until(Event::Answered, Duration::from_secs(3));
    assert!(
        events.iter().any(|e| matches!(e, Event::Answered)),
        "the daemon should have delivered its verdict; saw {events:?}"
    );
}

// =============================================================================
// 3. neither answers — the deadline, then a usable terminal
// =============================================================================

#[test]
fn neither_side_answers_returns_the_deadline_with_a_clean_terminal() {
    let _env = env_guard();
    clear_disable_env();
    let (_tmp, cfg) = config_with_one_bonded_peer();
    let daemon = MockDaemon::spawn(&cfg.socket_path, Mode::Silent);
    let pty = pty();

    let started = Instant::now();
    // `choice=1000` keeps the test fast; the floor is 1 s by design.
    let choice = choice::run(&cfg, &context(), &["choice=1000"], Some(pty.slave_path.to_str().expect("utf8 path")));
    let elapsed = started.elapsed();

    assert!(matches!(choice, Choice::Deadline), "nobody answered; got {choice:?}");
    assert!(
        elapsed >= Duration::from_millis(900) && elapsed < Duration::from_secs(3),
        "the window must be honoured and bounded; took {elapsed:?}"
    );

    let screen = String::from_utf8_lossy(&pty.output(Duration::from_millis(500))).into_owned();
    assert!(screen.starts_with(CHOICE_PROMPT), "the choice line must be printed; screen was {screen:?}");
    assert!(
        screen.ends_with('\n'),
        "the prompt line must be closed before the password prompt; screen was {screen:?}"
    );

    // Echo is on again, and the terminal still works: this is what the next
    // module's password prompt depends on.
    assert!(pty.echo_enabled(), "echo must be restored");
    pty.type_str("x");
    let echoed = String::from_utf8_lossy(&pty.output(Duration::from_millis(500))).into_owned();
    assert!(echoed.contains('x'), "the terminal must echo again after the choice; got {echoed:?}");

    let events = daemon.events_until(Event::CallerClosed, Duration::from_secs(3));
    assert!(
        events.iter().any(|e| matches!(e, Event::CallerClosed)),
        "the expired challenge must be cancelled at the daemon; saw {events:?}"
    );
}

// =============================================================================
// 4. phone=off — no socket, no prompt
// =============================================================================

#[test]
fn phone_off_touches_neither_the_daemon_nor_the_terminal() {
    let _env = env_guard();
    clear_disable_env();
    let (_tmp, cfg) = config_with_one_bonded_peer();
    let daemon = MockDaemon::spawn(&cfg.socket_path, Mode::Silent);
    let pty = pty();

    let started = Instant::now();
    let choice = choice::run(&cfg, &context(), &["phone=off"], Some(pty.slave_path.to_str().expect("utf8 path")));
    let elapsed = started.elapsed();

    assert!(matches!(choice, Choice::PhoneDisabled), "phone=off must disable the phone; got {choice:?}");
    assert!(elapsed < Duration::from_millis(500), "phone=off must return at once; took {elapsed:?}");
    assert_eq!(
        daemon.connections.load(Ordering::SeqCst),
        0,
        "phone=off must not connect to the daemon at all"
    );
    assert!(
        pty.output(Duration::from_millis(200)).is_empty(),
        "phone=off must not print a choice prompt"
    );
}

// =============================================================================
// 5. the environment escape hatch behaves like the module argument
// =============================================================================

#[test]
fn deunlock_off_in_the_environment_disables_the_phone() {
    let _env = env_guard();
    let (_tmp, cfg) = config_with_one_bonded_peer();
    let daemon = MockDaemon::spawn(&cfg.socket_path, Mode::Silent);
    let pty = pty();

    // SAFETY: this test owns the variable; the crate's other tests clear it
    // before they run and none of them read it concurrently.
    unsafe {
        std::env::set_var(choice::DISABLE_ENV, "1");
    }
    let choice = choice::run(&cfg, &context(), &[], Some(pty.slave_path.to_str().expect("utf8 path")));
    // SAFETY: as above.
    unsafe {
        std::env::remove_var(choice::DISABLE_ENV);
    }

    assert!(matches!(choice, Choice::PhoneDisabled), "DEUNLOCK_OFF=1 must disable the phone; got {choice:?}");
    assert_eq!(daemon.connections.load(Ordering::SeqCst), 0);
}
