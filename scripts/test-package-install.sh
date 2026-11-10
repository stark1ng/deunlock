#!/bin/sh
# Real native-manager installation, upgrade, loader, and state-preservation probes.
set -eu
if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
    echo 'Usage: test-package-install.sh ARTIFACT_DIR VERSION ARCH [debian|ubuntu|fedora|arch|opensuse]' >&2
    exit 2
fi
packages=$(CDPATH='' cd -- "$1" && pwd)
version=$2
arch=$3
case "$arch" in x86_64) deb_arch=amd64;; aarch64) deb_arch=arm64;; *) exit 2;; esac
engine=${CONTAINER_ENGINE:-docker}
distros=${4:-'debian ubuntu fedora arch opensuse'}
for distro in $distros; do
    case "$distro" in
        debian) image=docker.io/library/debian:12; asset=deunlock_${version}_${deb_arch}.deb; pam=/usr/lib/${arch}-linux-gnu/security/pam_deunlock.so;;
        ubuntu) image=docker.io/library/ubuntu:24.04; asset=deunlock_${version}_${deb_arch}.deb; pam=/usr/lib/${arch}-linux-gnu/security/pam_deunlock.so;;
        fedora) image=registry.fedoraproject.org/fedora:44; asset=deunlock-${version}-4.${arch}.rpm; pam=/usr/lib64/security/pam_deunlock.so;;
        opensuse) image=registry.opensuse.org/opensuse/tumbleweed:latest; asset=deunlock-${version}-4.${arch}.rpm; pam=/usr/lib64/security/pam_deunlock.so;;
        arch)
            [ "$arch" = x86_64 ] || { echo 'Arch Linux official image supports x86_64; skipping'; continue; }
            image=docker.io/library/archlinux:base; asset=deunlock-${version}-1-${arch}.pkg.tar.zst; pam=/usr/lib/security/pam_deunlock.so;;
        *) echo "Unknown smoke distribution: $distro" >&2; exit 2;;
    esac
    [ -f "$packages/$asset" ] || { echo "Missing artifact: $packages/$asset" >&2; exit 1; }
    printf '\nTesting %s with %s\n' "$asset" "$image"
    "$engine" run --rm -i --security-opt label=disable -v "$packages:/packages:ro" \
        -e "PACKAGE=/packages/$asset" -e "PAM_MODULE=$pam" -e "DISTRO=$distro" "$image" sh -euxs <<'CONTAINER'
        export DEBIAN_FRONTEND=noninteractive
        mkdir -p /etc/pam.d /var/lib/deunlock
        printf "auth required pam_deny.so\n" > /etc/pam.d/deunlock-package-sentinel
        for file in /etc/pam.d/*; do
            if [ -f "$file" ]; then sha256sum "$file"; fi
        done > /tmp/pam-before
        printf "bond-preservation-marker\n" > /var/lib/deunlock/bonds.toml
        chmod 0700 /var/lib/deunlock
        chown 123:123 /var/lib/deunlock
        case "$DISTRO" in
            debian|ubuntu) apt-get update -qq; apt-get install -y --no-install-recommends "$PACKAGE";;
            fedora) dnf install -y "$PACKAGE";;
            opensuse) zypper --non-interactive --gpg-auto-import-keys refresh; zypper --non-interactive install --allow-unsigned-rpm "$PACKAGE";;
            arch) pacman -Sy --noconfirm; pacman -U --noconfirm "$PACKAGE";;
        esac
        /usr/bin/deunlock --help | grep pair
        /usr/libexec/deunlock-presenced --help | grep -- --socket
        test -f "$PAM_MODULE"
        test "$(stat -c %a "$PAM_MODULE")" = 644
        grep -Fx ExecStart=/usr/libexec/deunlock-presenced /usr/lib/systemd/user/deunlock-presenced.service
        for binary in /usr/bin/deunlock /usr/libexec/deunlock-presenced "$PAM_MODULE"; do
            ldd "$binary" > /tmp/loader
            cat /tmp/loader
            if grep -q "not found" /tmp/loader; then exit 1; fi
        done
        # Dependency installation can add its own PAM files. Our sentinel must remain intact.
        sha256sum --check /tmp/pam-before
        case "$DISTRO" in
            debian|ubuntu) apt-get install --reinstall -y "$PACKAGE";;
            fedora) dnf reinstall -y "$PACKAGE";;
            opensuse) zypper --non-interactive install --allow-unsigned-rpm --force "$PACKAGE";;
            arch) pacman -U --noconfirm "$PACKAGE";;
        esac
        test "$(cat /var/lib/deunlock/bonds.toml)" = bond-preservation-marker
        test "$(stat -c %u:%g /var/lib/deunlock)" = 123:123
        test "$(stat -c %a /var/lib/deunlock)" = 700
        case "$DISTRO" in
            debian|ubuntu) dpkg --remove deunlock;;
            fedora|opensuse) rpm -e deunlock;;
            arch) pacman -R --noconfirm deunlock;;
        esac
        test "$(cat /var/lib/deunlock/bonds.toml)" = bond-preservation-marker
        sha256sum --check /tmp/pam-before
CONTAINER
done
