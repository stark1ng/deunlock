#!/usr/bin/python3
"""Compare the installed Arch PAM setup with an explicitly recorded baseline."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

BASELINE = Path("/var/lib/deunlock-update-check/baseline.json")
MODULE = "/usr/lib/security/pam_deunlock.so"
PACKAGES = ("kscreenlocker", "plasma-desktop", "pam", "pambase", "glibc", "sudo")
SERVICES = (
    "kde",
    "kde-fingerprint",
    "sudo",
    "system-auth",
    "system-login",
    "system-local-login",
)
PAM_FILES = tuple(
    f"{directory}/{service}"
    for directory in ("/etc/pam.d", "/usr/lib/pam.d")
    for service in SERVICES
)
FILES = (*PAM_FILES, MODULE)
COMMAND_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


def file_hash(path):
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except FileNotFoundError:
        return None


def package_versions():
    result = subprocess.run(
        ["/usr/bin/pacman", "-Q", *PACKAGES],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
        env=COMMAND_ENV,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(f"pacman package query failed: {result.stderr.strip()}")
    installed = dict(line.split(maxsplit=1) for line in result.stdout.splitlines())
    return {name: installed.get(name) for name in PACKAGES}


def snapshot(root=Path("/")):
    return {
        "files": {name: file_hash(root / name.lstrip("/")) for name in FILES},
        "packages": package_versions(),
    }


def pacnew_files(root=Path("/")):
    return [
        name + ".pacnew"
        for name in PAM_FILES
        if (root / (name.lstrip("/") + ".pacnew")).exists()
    ]


def check_dependencies(module):
    metadata = module.stat()
    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
        return [
            "The PAM module must be owned by root and not writable by group or others. Check its ownership and permissions."
        ]
    with module.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            return ["The PAM module is not an ELF library. Reinstall a trusted build."]
    # Only inspect a trusted, unchanged module. ldd runs the ELF loader;
    # no PAM entry point is called and no authentication request is sent.
    result = subprocess.run(
        ["/usr/bin/ldd", "-r", str(module)],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
        env=COMMAND_ENV,
    )
    output = result.stdout + result.stderr
    errors = [
        line.strip()
        for line in output.splitlines()
        if "not found" in line or "undefined symbol:" in line
    ]
    if result.returncode or errors:
        detail = (
            "\n".join(errors)
            or output.strip()
            or f"ldd exited with {result.returncode}"
        )
        return [
            f"The PAM module has a loader or dependency problem. Restore its libraries or rebuild/reinstall it:\n{detail}"
        ]
    return []


def read_baseline(path):
    data = json.loads(path.read_text())
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("files"), dict)
        or not isinstance(data.get("packages"), dict)
        or set(data["files"]) != set(FILES)
        or set(data["packages"]) != set(PACKAGES)
    ):
        raise ValueError(
            "Baseline does not match this checker. Review and test the setup, then record a new baseline."
        )
    for digest in data["files"].values():
        if digest is not None and (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            raise ValueError(
                "Baseline contains an invalid file hash. Review and record a new baseline."
            )
    if any(
        version is not None and not isinstance(version, str)
        for version in data["packages"].values()
    ):
        raise ValueError(
            "Baseline contains an invalid package version. Review and record a new baseline."
        )
    if not data["files"][MODULE]:
        raise ValueError(
            "Baseline contains no PAM module. Restore the module and record a tested baseline."
        )
    return data


def check(baseline, root=Path("/")):
    current = snapshot(root)
    findings = []
    for name in FILES:
        if current["files"][name] == baseline["files"][name]:
            continue
        if name == MODULE:
            action = "Inspect the installed build and retest authentication before accepting it."
        elif name.startswith("/usr/lib/pam.d/"):
            action = "Review the packaged PAM changes and merge them into local overrides if needed."
        else:
            action = "Review the local PAM change and restore or adjust the configuration if needed."
        state = "missing" if current["files"][name] is None else "changed"
        findings.append(f"{name} is {state}. {action}")
    for name in PACKAGES:
        old, new = baseline["packages"][name], current["packages"][name]
        if old != new:
            findings.append(
                f"{name}: {old or 'absent'} -> {new or 'absent'}. Retest sudo, empty-Enter phone unlock, password unlock, and timeout fallback."
            )
    for name in pacnew_files(root):
        findings.append(
            f"Review and merge or remove {name} before accepting a new baseline."
        )
    if current["files"][MODULE] == baseline["files"][MODULE]:
        findings.extend(check_dependencies(root / MODULE.lstrip("/")))
    return findings


def record_baseline(path, root=Path("/")):
    current = snapshot(root)
    if current["files"][MODULE] is None:
        raise ValueError("Cannot record a baseline without the PAM module.")
    if any(version is None for version in current["packages"].values()):
        raise ValueError("Cannot record a baseline while a watched package is missing.")
    pending = pacnew_files(root)
    if pending:
        raise ValueError("Review and resolve these files first: " + ", ".join(pending))
    problems = check_dependencies(root / MODULE.lstrip("/"))
    if problems:
        raise ValueError("\n".join(problems))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    # Replace only after a complete write; failed checks leave the old baseline intact.
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(current, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, default=BASELINE)
    parser.add_argument(
        "--record-baseline",
        action="store_true",
        help="Record the current setup after reviewing changes and testing unlock.",
    )
    args = parser.parse_args(argv)
    try:
        if args.record_baseline:
            record_baseline(args.baseline)
            print(f"deunlock: recorded baseline at {args.baseline}.")
            return 0
        findings = check(read_baseline(args.baseline))
        if findings:
            print("deunlock: update check needs attention:", file=sys.stderr)
            for finding in findings:
                print(f"- {finding}", file=sys.stderr)
            print(
                "After review and successful unlock tests, run: sudo /usr/local/libexec/deunlock-update-check --record-baseline",
                file=sys.stderr,
            )
            return 1
        print(
            "deunlock: update check passed; tracked files and package versions are unchanged, and module dependencies resolve."
        )
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"deunlock: update check could not complete: {error}", file=sys.stderr)
        print(
            "Resolve the issue, review the setup, and test unlock before recording a baseline with --record-baseline.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
