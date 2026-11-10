"""Exercise Android release signing without exposing signing credentials.

Journey: specs/journeys/JOURNEY-release-publication.md
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/build-release-apk.sh"
FINGERPRINT = "25585e641edb3da87b989056b3d165cac2afaf2aaedd35875666b521ecc0221c"


class ReleaseApkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.script = self.root / "scripts/build-release-apk.sh"
        self.script.parent.mkdir()
        self.script.write_bytes(SCRIPT.read_bytes())
        self.keystore = self.root / "release.jks"
        self.keystore.touch()
        self.env = dict(
            os.environ,
            VERSION="0.1.0",
            DEUNLOCK_RELEASE_KEYSTORE=str(self.keystore),
            DEUNLOCK_RELEASE_KEYSTORE_PASSWORD="private-test-password",
        )

    def run_build(self, env=None):
        return subprocess.run(
            ["bash", str(self.script)],
            env=self.env if env is None else env,
            capture_output=True,
            text=True,
        )

    def test_missing_keystore_file_rejected_before_any_build(self):
        self.keystore.unlink()
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Signing keystore does not exist", result.stderr)

    def test_invalid_version_rejected_before_any_build(self):
        env = dict(self.env, VERSION="../escape")
        result = self.run_build(env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("VERSION must be a numeric major.minor.patch", result.stderr)
        self.assertNotIn("private", result.stderr + result.stdout)

    def test_missing_signing_credentials_fails_closed(self):
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("DEUNLOCK_RELEASE_")
        }
        result = self.run_build(env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DEUNLOCK_RELEASE_KEYSTORE is required", result.stderr)

    def test_missing_android_sdk_fails_before_building(self):
        self.env.update(
            ANDROID_HOME=str(self.root / "missing-sdk"), ANDROID_SDK_ROOT=""
        )
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Android build tools are missing", result.stderr)

    def signing_tools(self, verify_status=0):
        sdk = self.root / "sdk/build-tools/34.0.0"
        sdk.mkdir(parents=True)
        self.env.update(
            ANDROID_HOME=str(self.root / "sdk"), TOOL_LOG=str(self.root / "tools.log")
        )
        gradle = self.root / "deunlock-android/gradlew"
        gradle.parent.mkdir()
        gradle.write_text('''#!/bin/sh
mkdir -p app/build/outputs/apk/release
printf unsigned > app/build/outputs/apk/release/app-release-unsigned.apk
echo gradle >> "$TOOL_LOG"
''')
        (sdk / "zipalign").write_text('''#!/bin/sh
echo "zipalign $*" >> "$TOOL_LOG"
if [ "$1" = -p ]; then cp "$4" "$5"; fi
''')
        (sdk / "apksigner").write_text(f'''#!/bin/sh
echo "apksigner $*" >> "$TOOL_LOG"
if [ "$1" = verify ]; then
    echo "Signer #1 certificate SHA-256 digest: {FINGERPRINT}"
    exit {verify_status}
fi
while [ "$1" != --out ]; do shift; done
cp "$3" "$2"
''')
        for tool in [gradle, sdk / "zipalign", sdk / "apksigner"]:
            tool.chmod(0o755)
        certificate = self.root / "deploy/android-release-signing.pem"
        certificate.parent.mkdir()
        certificate.write_bytes(
            (ROOT / "deploy/android-release-signing.pem").read_bytes()
        )

    def test_aligns_then_signs_and_verifies_before_publishing(self):
        self.signing_tools()
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        artifact = self.root / "target/release-artifacts/deunlock-0.1.0-android.apk"
        self.assertTrue(artifact.is_file())
        log = (self.root / "tools.log").read_text()
        self.assertLess(log.index("zipalign -p"), log.index("apksigner sign"))
        self.assertLess(log.index("apksigner sign"), log.index("apksigner verify"))
        self.assertLess(log.index("apksigner verify"), log.index("zipalign -c"))
        self.assertIn("env:DEUNLOCK_RELEASE_KEYSTORE_PASSWORD", log)
        self.assertNotIn("private-test-password", log + result.stdout + result.stderr)
        self.assertTrue((artifact.parent / "android-signing-certificate.txt").is_file())
        self.assertEqual(
            (artifact.parent / "android-signing-certificate.pem").read_bytes(),
            (ROOT / "deploy/android-release-signing.pem").read_bytes(),
        )

    def test_invalid_signature_never_publishes_an_apk(self):
        self.signing_tools(verify_status=1)
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(list((self.root / "target/release-artifacts").glob("*.apk")))
        self.assertFalse(
            list((self.root / "target/release-artifacts").glob(".android-sign.*"))
        )

    def test_unexpected_signing_certificate_never_publishes_an_apk(self):
        self.signing_tools()
        signer = self.root / "sdk/build-tools/34.0.0/apksigner"
        signer.write_text(signer.read_text().replace(FINGERPRINT, "0" * 64))
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Signing certificate does not match", result.stderr)
        self.assertFalse(list((self.root / "target/release-artifacts").glob("*.apk")))


if __name__ == "__main__":
    unittest.main()
