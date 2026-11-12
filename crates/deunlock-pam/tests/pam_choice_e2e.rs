//! W-1's security property, measured through the real `sudo` stack.
//!
//! The pty tests in `choice_pty.rs` drive the race itself. They cannot prove
//! the one thing that matters about the password path: that a typed password is
//! **not** an authentication by itself, and that the bytes reach `pam_unix`
//! without a second prompt.
//!
//! This test asks that question of the installed module inside the production
//! stack (`/etc/pam.d/sudo`: our `auth sufficient` line, then `@include
//! common-auth`, i.e. `pam_unix`). It types a password that is deliberately
//! wrong, which is why it needs no credential:
//!
//! * our line appears                       → the choice is offered;
//! * no `Password:` prompt appears after it → `pam_unix` read `PAM_AUTHTOK`
//!   instead of asking again, so the typed bytes really were handed over;
//! * pamtester fails                        → nothing authenticated the wrong
//!   password, i.e. the module returned `PAM_IGNORE` and not `PAM_SUCCESS`.
//!
//! A module that authenticated what it read would make this test pass green,
//! which is the whole point of typing nonsense.
//!
//! Gated on `DEUNLOCK_E2E=1` and on the module being installed:
//!
//! ```text
//! cargo build --release -p deunlock-pam
//! sudo install -m 0755 target/release/libpam_deunlock.so \
//!     /usr/lib/x86_64-linux-gnu/security/pam_deunlock.so
//! DEUNLOCK_E2E=1 cargo test -p deunlock-pam --test pam_choice_e2e
//! ```

use std::{
    env,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

/// Same gate as `tests/pam_smoke.rs`.
const E2E_GATE_VAR: &str = "DEUNLOCK_E2E";

/// The line the module prints before it reads anything.
const CHOICE_PROMPT: &str = "Confirm on your phone, or type your password:";

/// What `pam_unix` prints when it has to ask. Its absence is the proof that the
/// typed password travelled through `PAM_AUTHTOK`.
const SECOND_PROMPT: &str = "Password:";

/// A password that cannot be right for any account.
const WRONG_PASSWORD: &str = "deunlock-w1-not-a-real-password";

fn which(bin: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path).map(|dir| dir.join(bin)).find(|candidate| candidate.is_file())
}

/// The PAM module directory this distro uses.
fn installed_module() -> Option<PathBuf> {
    let candidates = [
        Path::new("/usr/lib/x86_64-linux-gnu/security/pam_deunlock.so"),
        Path::new("/usr/lib64/security/pam_deunlock.so"),
        Path::new("/lib/x86_64-linux-gnu/security/pam_deunlock.so"),
    ];
    candidates.iter().find(|path| path.is_file()).map(|path| path.to_path_buf())
}

/// Run `pamtester <service> <user> authenticate` under a pty and type at it.
fn drive(service: &str, user: &str, secret: &str) -> (String, bool) {
    let command = format!(
        "{} {} {} authenticate",
        which("pamtester").expect("pamtester on PATH").display(),
        service,
        user
    );
    let mut child = Command::new(which("script").expect("script on PATH"))
        .args(["-q", "-e", "-c", &command, "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn script");

    let mut stdin = child.stdin.take().expect("stdin");
    let typed = secret.to_owned();
    let typist = thread::spawn(move || {
        // The module offers its choice immediately; `pam_unix`'s own delay is
        // the only thing between us and a verdict. One second is generous for
        // the prompt to be printed and still inside the 6 s phone window.
        thread::sleep(Duration::from_millis(1_000));
        let _ = stdin.write_all(typed.as_bytes());
        let _ = stdin.write_all(b"\n");
        let _ = stdin.flush();
    });

    let out = child.wait_with_output().expect("wait for pamtester");
    typist.join().expect("typist thread");
    let screen = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (screen, out.status.success())
}

#[test]
fn a_typed_password_reaches_pam_unix_and_authenticates_nothing() {
    if env::var(E2E_GATE_VAR).as_deref() != Ok("1") {
        eprintln!("skipping pam_choice_e2e: set {E2E_GATE_VAR}=1 to run");
        return;
    }
    if which("pamtester").is_none() || which("script").is_none() {
        eprintln!("skipping pam_choice_e2e: pamtester and script are both required");
        return;
    }
    if installed_module().is_none() {
        eprintln!("skipping pam_choice_e2e: pam_deunlock.so is not installed (see the module docs)");
        return;
    }
    let user = env::var("USER").unwrap_or_else(|_| "nobody".to_string());

    let (screen, ok) = drive("sudo", &user, WRONG_PASSWORD);

    assert!(
        screen.contains(CHOICE_PROMPT),
        "the installed module must offer the choice inside the real sudo stack; screen:\n{screen}"
    );
    assert!(
        !screen.contains(SECOND_PROMPT),
        "pam_unix must read the typed password from PAM_AUTHTOK instead of prompting again; screen:\n{screen}"
    );
    assert!(
        !ok,
        "a wrong password must not authenticate — the module returned success instead of PAM_IGNORE; screen:\n{screen}"
    );
    assert!(
        !screen.contains(WRONG_PASSWORD),
        "the typed password must not be echoed back; screen:\n{screen}"
    );
}
