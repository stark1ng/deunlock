# Regression: test installed PAM and daemon together in a disposable VM.
import json, shlex
start_all()
machine.wait_for_unit("multi-user.target")
base = machine.succeed("readlink -f /run/current-system").strip()
package = "@deunlock@"
def alice(command, ok=True):
    run = "su - alice -c " + shlex.quote(command)
    return (machine.succeed if ok else machine.fail)(run)
def bob(command, ok=True):
    run = "su - bob -c " + shlex.quote(command)
    return (machine.succeed if ok else machine.fail)(run)
def sudo(password, ok=True):
    return alice("printf '%s\\n' " + shlex.quote(password) + " | sudo -k -S -p '' true", ok)
def switch(name=None):
    path = base if name is None else base + "/specialisation/" + name
    machine.succeed(path + "/bin/switch-to-configuration test")
def userctl(command, ok=True):
    return alice("XDG_RUNTIME_DIR=/run/user/1100 systemctl --user " + command, ok)
def ready():
    machine.wait_until_succeeds("su - alice -c 'XDG_RUNTIME_DIR=/run/user/1100 deunlock status --json' | grep -q '\"transport_ready\": true'", timeout=60)
with subtest("installed binaries and PAM loader closure"):
    assert machine.succeed("deunlock --version").strip() == "deunlock @version@"
    machine.succeed(package + "/bin/deunlock-presenced --help | grep -- --socket")
    machine.succeed("ldd " + package + "/lib/security/pam_deunlock.so | tee /root/pam-loader.txt; ! grep -q 'not found' /root/pam-loader.txt")
    machine.succeed("test -f " + package + "/lib/security/pam_deunlock.so")
    machine.succeed("grep -F 'auth sufficient " + package + "/lib/security/pam_deunlock.so socket=/run/user/1100/deunlock/auth.sock' /etc/pam.d/sudo")
with subtest("private storage and per-user service isolation"):
    assert machine.succeed("stat -c '%a %U %G' /var/lib/deunlock").strip() == "700 alice users"
    machine.succeed("loginctl enable-linger alice; loginctl enable-linger bob")
    machine.wait_for_unit("user@1100.service")
    machine.wait_for_unit("user@1101.service")
    assert userctl("show deunlock-presenced -p StartLimitIntervalUSec --value").strip() == "0"
    machine.wait_until_succeeds("test $(su - alice -c 'XDG_RUNTIME_DIR=/run/user/1100 systemctl --user show deunlock-presenced -p NRestarts --value') -ge 3", timeout=60)
    machine.succeed("journalctl _UID=1100 --no-pager | grep -q 'Bluetooth transport unavailable'")
    assert bob("XDG_RUNTIME_DIR=/run/user/1101 systemctl --user show deunlock-presenced -p ConditionResult --value").strip() == "no"
    assert bob("XDG_RUNTIME_DIR=/run/user/1101 systemctl --user show deunlock-presenced -p MainPID --value").strip() == "0"
    bob("test -r /var/lib/deunlock/bonds.toml", False)
with subtest("missing phone still requires a valid Unix password"):
    sudo("wrong-password", False)
    sudo("vm-alice-test")
    assert machine.succeed("stat -c '%a %U %G' /var/lib/deunlock/last.log").strip() == "600 alice users"
with subtest("synthetic signed response traverses real daemon and installed PAM"):
    userctl("stop deunlock-presenced")
    machine.succeed("@python@/bin/python @fixture@")
    data = json.loads(machine.succeed("cat /root/fixture.json"))
    daemon = package + "/bin/deunlock-presenced --peripheral fake --test-fixed-nonce " + data["nonce"] + " --inject-response " + data["peer"] + ":" + data["signature"]
    def inject(command):
        unit = "[Service]\\nExecStart=\\nExecStart=" + command + "\\n"
        alice("mkdir -p ~/.config/systemd/user/deunlock-presenced.service.d; printf '%b' " + shlex.quote(unit) + " > ~/.config/systemd/user/deunlock-presenced.service.d/vm-fixture.conf")
        userctl("daemon-reload")
        userctl("restart deunlock-presenced")
        ready()
    inject(daemon)
    sudo("wrong-password")
    machine.succeed("grep -q ',ok,' /var/lib/deunlock/last.log")
    assert machine.succeed("stat -c '%a %U %G' /var/lib/deunlock/last.log").strip() == "600 alice users"
    machine.fail("journalctl _UID=1100 --no-pager | grep -q 'audit log open failed'")
    assert json.loads(alice("XDG_RUNTIME_DIR=/run/user/1100 deunlock status --json"))["daemon"]["transport_ready"] is True
    bob("cat /var/lib/deunlock/bonds.toml", False)
    bob("cat /var/lib/deunlock/keys/" + data["peer"] + ".bin", False)
with subtest("bad signature is rejected before password fallback"):
    inject(package + "/bin/deunlock-presenced --peripheral fake --test-fixed-nonce " + data["nonce"] + " --inject-response " + data["peer"] + ":" + "00" * 64)
    sudo("wrong-password", False)
    machine.succeed("grep -q 'bad-signature' /var/lib/deunlock/last.log")
    sudo("vm-alice-test")
with subtest("explicit socket override and automatic default both authenticate"):
    inject(daemon)
    switch("explicitArgs")
    ready()
    sudo("wrong-password")
    switch()
    userctl("restart deunlock-presenced")
    ready()
    sudo("wrong-password")
with subtest("required control retains failure despite a correct password"):
    userctl("stop deunlock-presenced")
    switch("required")
    userctl("stop deunlock-presenced")
    machine.succeed("grep -F 'auth required ' /etc/pam.d/sudo | grep pam_deunlock")
    sudo("vm-alice-test", False)
    switch()
with subtest("sudo-rs consumes the generated PAM rules"):
    switch("sudoRs")
    userctl("stop deunlock-presenced")
    sudo("wrong-password", False)
    sudo("vm-alice-test")
    switch()
with subtest("profile install and removal is independent of module activation"):
    bob("nix profile install " + package)
    assert bob("~/.nix-profile/bin/deunlock --version").strip() == "deunlock @version@"
    bob("test -f ~/.nix-profile/lib/security/pam_deunlock.so")
    profile = json.loads(bob("nix profile list --json"))
    entry = next(iter(profile["elements"]))
    bob("nix profile remove " + shlex.quote(entry))
    bob("test -e ~/.nix-profile/bin/deunlock", False)
with subtest("disable and rollback preserve the existing bond store"):
    alice("rm ~/.config/systemd/user/deunlock-presenced.service.d/vm-fixture.conf")
    userctl("daemon-reload")
    before = machine.succeed("find /var/lib/deunlock -type f -exec sha256sum {} + | sort")
    switch("noPam")
    machine.fail("grep -q pam_deunlock /etc/pam.d/sudo")
    sudo("vm-alice-test")
    switch("disabled")
    machine.fail("command -v deunlock")
    machine.fail("grep -q pam_deunlock /etc/pam.d/sudo")
    assert machine.succeed("find /var/lib/deunlock -type f -exec sha256sum {} + | sort") == before
    switch()
    machine.succeed("command -v deunlock")
    assert machine.succeed("stat -c '%a %U %G' /var/lib/deunlock").strip() == "700 alice users"
    assert machine.succeed("find /var/lib/deunlock -type f -exec sha256sum {} + | sort") == before
machine.succeed("journalctl --no-pager > /root/deunlock-vm-journal.txt")

print("DEUNLOCK_NIXOS_VM_CHECKS_PASSED")
