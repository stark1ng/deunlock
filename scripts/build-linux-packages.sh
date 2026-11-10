#!/bin/sh
# Install a checksum-pinned nFPM in a disposable build directory, then package.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
case "$(uname -m)" in
    x86_64) tool_arch=x86_64; digest=0660ca602b2d2d2ae4781a06c692b3eeb9d437ffea05b831d76e41f4a3188783;;
    aarch64|arm64) tool_arch=arm64; digest=1c0f5f2999b9a974bfb04fdb0cc3306096de530ac5dbb25d739cc5f5219c919c;;
    *) echo 'Unsupported nFPM build-host architecture' >&2; exit 1;;
esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
url=https://github.com/goreleaser/nfpm/releases/download/v2.47.0/nfpm_2.47.0_Linux_${tool_arch}.tar.gz
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --retry 3 --connect-timeout 15 --max-time 180 "$url" --output "$work/nfpm.tar.gz"
printf '%s  %s\n' "$digest" "$work/nfpm.tar.gz" | sha256sum --check
tar -xzf "$work/nfpm.tar.gz" -C "$work" nfpm
python3 "$root/scripts/build-linux-packages.py" --nfpm "$work/nfpm" "$@"
