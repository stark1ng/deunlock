{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.deunlock;
  store = "/var/lib/deunlock";
  account = config.users.users.${cfg.desktopUser} or { };
  pamModule = "${cfg.package}/lib/security/pam_deunlock.so";
  desktopUid = account.uid or null;

  anchorOrder =
    name:
    let
      # Exclude the injected rule because its order depends on this lookup.
      rules = removeAttrs config.security.pam.services.${name}.rules.auth [ "deunlock" ];
      orders = lib.mapAttrsToList (_: rule: rule.order) (lib.filterAttrs (_: rule: rule.enable) rules);
    in
    if rules.unix.enable or false then
      rules.unix.order
    else if orders != [ ] then
      lib.head (lib.sort builtins.lessThan orders)
    else
      throw "services.deunlock.pam.services: ${name} has no enabled auth rule to anchor deunlock to.";

  hasDeUnlockRule =
    text:
    lib.any (
      line:
      builtins.match "[[:blank:]]*auth[[:blank:]]+([[][^]]+[]]|[^[:blank:]]+)[[:blank:]]+([^[:blank:]]*/)?pam_deunlock[.]so([[:blank:]].*)?" line
      != null
    ) (lib.splitString "\n" text);
in
{
  options.services.deunlock = {
    enable = lib.mkEnableOption "deunlock for one desktop account";

    desktopUser = lib.mkOption {
      type = lib.types.str;
      example = "alice";
      description = "Account that pairs phones, owns the bond store, and runs the user service.";
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.deunlock;
      defaultText = lib.literalExpression "self.packages.\${system}.deunlock";
      description = "Package providing the CLI, daemon, and PAM module.";
    };

    installCli = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Add the deunlock package to the system PATH.";
    };

    pam = {
      services = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [
          "sudo"
          "sudo-i"
        ];
        description = "PAM services to configure for phone authentication.";
      };

      control = lib.mkOption {
        type = lib.types.str;
        default = "sufficient";
        description = "PAM control field used for the deunlock rule in the selected services.";
      };

      moduleArgs = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = lib.optional (
          desktopUid != null
        ) "socket=/run/user/${toString desktopUid}/deunlock/auth.sock";
        defaultText = lib.literalExpression ''[ "socket=/run/user/<desktopUser UID>/deunlock/auth.sock" ] when the UID is declared, otherwise [ ]'';
        example = [ "socket=/run/user/1000/deunlock/auth.sock" ];
        description = "Arguments passed to pam_deunlock.so in each selected service.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = config.users.users ? ${cfg.desktopUser};
        message = "services.deunlock.desktopUser must name an account declared in users.users.";
      }
      {
        assertion = cfg.pam.services == [ ] || lib.any (lib.hasPrefix "socket=/") cfg.pam.moduleArgs;
        message = "services.deunlock.pam.moduleArgs requires an absolute socket= path when PAM is enabled. Declare users.users.<desktopUser>.uid or set pam.moduleArgs explicitly.";
      }
    ]
    ++ map (name: {
      assertion = hasDeUnlockRule config.security.pam.services.${name}.text;
      message = "PAM service ${name} lacks an auth rule for pam_deunlock.so. Check security.pam.services.${name}.text.";
    }) cfg.pam.services;

    systemd.tmpfiles.rules = [ "d ${store} 0700 ${cfg.desktopUser} ${account.group or "-"} -" ];
    environment.systemPackages = lib.optional cfg.installCli cfg.package;

    systemd.user.services.deunlock-presenced = {
      description = "deunlock phone-as-key presence daemon";
      wantedBy = [ "default.target" ];
      unitConfig = {
        ConditionUser = cfg.desktopUser;
        ConditionPathIsDirectory = "%t";
        StartLimitIntervalSec = 0;
      };
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/deunlock-presenced";
        Restart = "on-failure";
        RestartSec = 2;
        TimeoutStopSec = 5;
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        ReadWritePaths = [
          store
          "%t"
        ];
      };
    };

    security.pam.services = lib.genAttrs cfg.pam.services (name: {
      rules.auth.deunlock = {
        inherit (cfg.pam) control;
        modulePath = pamModule;
        order = anchorOrder name - 10;
        args = cfg.pam.moduleArgs;
      };
    });
  };
}
