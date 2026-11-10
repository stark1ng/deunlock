"""Release payload contracts. Journey: specs/journeys/JOURNEY-release-publication.md."""

import importlib.util
from pathlib import Path
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]


class PackageTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "packages", REPO / "scripts/build-linux-packages.py"
        )
        self.packages = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.packages)

    def test_debian_payload_has_daemon_and_multiarch_pam(self):
        config = self.packages.package_config("0.1.1", "x86_64", "deb", REPO / "target/release")
        destinations = {item["dst"] for item in config["contents"]}
        self.assertIn("/usr/libexec/deunlock-presenced", destinations)
        self.assertIn("/usr/lib/x86_64-linux-gnu/security/pam_deunlock.so", destinations)

    def test_architecture_specific_layouts_and_permissions(self):
        for arch, multiarch in (("x86_64", "x86_64-linux-gnu"), ("aarch64", "aarch64-linux-gnu")):
            for kind, directory in (("deb", f"/usr/lib/{multiarch}/security"),
                                    ("rpm", "/usr/lib64/security"), ("archlinux", "/usr/lib/security")):
                with self.subTest(arch=arch, kind=kind):
                    config = self.packages.package_config("1.2.3", arch, kind, REPO / "target/release")
                    contents = {item["dst"]: item for item in config["contents"]}
                    self.assertEqual(contents[f"{directory}/pam_deunlock.so"]["file_info"]["mode"], 0o644)
                    self.assertEqual(contents["/usr/libexec/deunlock-presenced"]["file_info"]["mode"], 0o755)
                    self.assertFalse(any(path.startswith(("/etc/", "/var/")) for path in contents))
                    self.assertNotIn("preremove", config["scripts"])
                    self.assertNotIn("postremove", config["scripts"])

    def test_artifact_names_match_native_conventions(self):
        for arch, debarch in (("x86_64", "amd64"), ("aarch64", "arm64")):
            self.assertEqual(self.packages.artifact_name("1.2.3", arch, "deb"), f"deunlock_1.2.3_{debarch}.deb")
            self.assertEqual(self.packages.artifact_name("1.2.3", arch, "rpm"), f"deunlock-1.2.3-4.{arch}.rpm")
            self.assertEqual(self.packages.artifact_name("1.2.3", arch, "archlinux"), f"deunlock-1.2.3-1-{arch}.pkg.tar.zst")

    def test_invalid_version_and_missing_payload_fail_before_packaging(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            output = directory / "dist"
            for version in ("../../1", "1.2", "1.2.3;id"):
                with self.assertRaises(ValueError):
                    self.packages.build(version, "x86_64", directory, output, "missing-nfpm")
            with self.assertRaisesRegex(ValueError, "missing release binary"):
                self.packages.build("1.2.3", "x86_64", directory, output, "missing-nfpm")
            self.assertFalse(output.exists())

    def test_full_builder_stages_correct_service_without_mutating_source(self):
        import tarfile
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for name in ("deunlock", "deunlock-presenced", "libpam_deunlock.so"):
                (directory / name).write_bytes(b"payload")
            fake = directory / "nfpm"
            fake.write_text('''#!/usr/bin/env python3
import json, sys
from pathlib import Path
args = sys.argv
config = json.loads(Path(args[args.index("--config") + 1]).read_text())
for item in config["contents"]:
    if item["dst"].endswith(".service"):
        assert "ExecStart=/usr/libexec/deunlock-presenced" in Path(item["src"]).read_text()
Path(args[args.index("--target") + 1]).write_text(json.dumps(config))
''')
            fake.chmod(0o755)
            source = REPO / "crates/deunlock-presenced/dist/deunlock-presenced.service"
            original = source.read_bytes()
            self.packages.build("1.2.3", "x86_64", directory, directory / "dist", str(fake))
            self.assertEqual(source.read_bytes(), original)
            artifacts = list((directory / "dist").iterdir())
            self.assertEqual(len(artifacts), 4)
            archive = directory / "dist/deunlock-1.2.3-linux-x86_64.tar.gz"
            with tarfile.open(archive) as tar:
                service = tar.extractfile("usr/lib/systemd/user/deunlock-presenced.service").read()
                self.assertIn(b"ExecStart=/usr/libexec/deunlock-presenced", service)
                self.assertEqual(tar.getmember("usr/lib/security/pam_deunlock.so").mode, 0o644)


if __name__ == "__main__":
    unittest.main()
