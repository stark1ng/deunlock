# Journey: specs/journeys/JOURNEY-S-023-nix-modules.md
{
  pkgs,
  module,
  package,
}:
let
  python = pkgs.python3.withPackages (p: [
    p.cryptography
    p.blake3
  ]);
  fixture = pkgs.writeText "deunlock-vm-fixture.py" (builtins.readFile ./fixture.py);
in
pkgs.testers.runNixOSTest {
  name = "deunlock-installation-and-policy";
  nodes.machine = { lib, ... }: {
    imports = [ module ];
    system.stateVersion = "25.11";
    virtualisation = {
      memorySize = 2048;
      cores = 2;
      diskSize = 6144;
      writableStore = true;
    };
    nix.settings.experimental-features = [
      "nix-command"
      "flakes"
    ];
    hardware.bluetooth.enable = true;
    users.users.alice = {
      isNormalUser = true;
      uid = 1100;
      extraGroups = [ "wheel" ];
      password = "vm-alice-test";
    };
    users.users.bob = {
      isNormalUser = true;
      uid = 1101;
      password = "vm-bob-test";
    };
    security.sudo = {
      enable = true;
      wheelNeedsPassword = true;
    };
    security.sudo-rs.enable = false;
    environment.systemPackages = [ python ];
    services.deunlock = {
      enable = true;
      desktopUser = "alice";
      inherit package;
      pam.services = [
        "sudo"
        "sudo-i"
      ];
    };
    specialisation = {
      noPam.configuration.services.deunlock.pam.services = lib.mkForce [ ];
      disabled.configuration.services.deunlock.enable = lib.mkForce false;
      explicitArgs.configuration.services.deunlock.pam.moduleArgs = lib.mkForce [
        "socket=/run/user/1100/deunlock/auth.sock"
      ];
      required.configuration.services.deunlock.pam.control = lib.mkForce "required";
      sudoRs.configuration = {
        security.sudo.enable = lib.mkForce false;
        security.sudo-rs.enable = lib.mkForce true;
      };
    };
  };
  testScript =
    builtins.replaceStrings
      [ "@deunlock@" "@python@" "@fixture@" "@version@" ]
      [ "${package}" "${python}" "${fixture}" package.version ]
      (builtins.readFile ./installation.py);
}
