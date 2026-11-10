# One derivation for the whole workspace: the `deunlock` CLI, the
# `deunlock-presenced` daemon, and the PAM module cdylib.
{
  lib,
  stdenv,
  makeRustPlatform,
  autoPatchelfHook,
  pkg-config,
  dbus,
  python3,
  rustToolchain,
  writeShellScriptBin,
}:

let
  rustPlatform = makeRustPlatform {
    cargo = rustToolchain;
    rustc = rustToolchain;
  };

  # nixpkgs drives cargo with an explicit `--target <triple>`, so the release
  # artifacts land one directory deeper than a plain `cargo build --release`.
  releaseDir = "target/${stdenv.hostPlatform.rust.rustcTarget}/release";
in
rustPlatform.buildRustPackage {
  pname = "deunlock";
  version = (lib.importTOML ../Cargo.toml).workspace.package.version;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../crates
      ../src
      ../tests
      ../scripts
      ../deploy
      ../docs/perf-baselines.md
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;

  # BlueZ needs D-Bus and tests/bt_matrix.rs runs a Python test suite.
  # Rust binaries also link `libgcc_s.so.1` at runtime; list the compiler
  # runtime as an input so `autoPatchelfHook` searches it and puts it in RPATH.
  buildInputs = [
    dbus
    (lib.getLib stdenv.cc.cc)
  ];
  nativeBuildInputs = [
    autoPatchelfHook
    pkg-config
    python3
  ];

  # The root manifest is both a package and the workspace root.
  cargoBuildFlags = [ "--workspace" ];
  cargoTestFlags = [ "--workspace" ];
  doCheck = true;
  # The recovery test starts a session bus; the sandbox has no /etc/dbus-1.
  nativeCheckInputs = [
    (writeShellScriptBin "dbus-daemon" ''
      args=()
      for arg in "$@"; do
        case "$arg" in
          --session) args+=(--config-file=${dbus}/share/dbus-1/session.conf) ;;
          *) args+=("$arg") ;;
        esac
      done
      exec ${dbus}/bin/dbus-daemon "''${args[@]}"
    '')
  ];

  # The upstream integration test expects the daemon directly under target/release.
  #
  # Test binaries link against `libdbus-1.so.3` but only the installed files
  # get an ELF rpath, so the check phase needs the D-Bus library on the loader
  # search path for `cargo test` to start the `bluer`-backed tests.
  preCheck = ''
    export LD_LIBRARY_PATH="${lib.makeLibraryPath [ dbus ]}''${LD_LIBRARY_PATH:+:}''${LD_LIBRARY_PATH:-}"
    mkdir -p target/release
    ln -sfn ../${stdenv.hostPlatform.rust.rustcTarget}/release/deunlock-presenced target/release/deunlock-presenced
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/bin $out/lib/security
    install -m755 ${releaseDir}/deunlock $out/bin/deunlock
    install -m755 ${releaseDir}/deunlock-presenced $out/bin/deunlock-presenced
    install -m755 ${releaseDir}/libpam_deunlock.so $out/lib/security/pam_deunlock.so
    runHook postInstall
  '';

  meta = {
    description = "Phone-as-key unlock for Linux PAM";
    homepage = "https://github.com/Mewplane/deunlock";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
    mainProgram = "deunlock";
  };
}
