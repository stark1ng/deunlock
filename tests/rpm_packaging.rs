use std::{fs, path::Path};

fn spec() -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/fedora/deunlock.spec")).unwrap()
}

#[test]
fn rpm_builds_and_installs_the_presence_daemon() {
    let spec = spec();
    assert!(spec.contains("--package deunlock-presenced"));
    assert!(spec.contains("%{buildroot}%{_libexecdir}/deunlock-presenced"));
    assert!(spec.contains("%{_userunitdir}/deunlock-presenced.service"));
}

#[test]
fn rpm_does_not_reset_existing_bond_directory_ownership() {
    assert!(!spec().contains("%attr(0700, root, root) /var/lib/deunlock"));
}

#[test]
fn daemon_sandbox_permits_its_user_runtime_socket() {
    let unit =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("crates/deunlock-presenced/dist/deunlock-presenced.service")).unwrap();
    assert!(
        unit.lines()
            .any(|line| line.starts_with("ReadWritePaths=") && line.split_whitespace().any(|path| path == "%t"))
    );
}

#[test]
fn native_rpm_builder_documents_its_committed_source() {
    let output = std::process::Command::new("bash")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/build-rpm-native.sh"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("committed HEAD"));
}
