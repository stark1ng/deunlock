#!/usr/bin/env bash
# Privileged half: install pam_deunlock.so and wire it into a PAM service.
#
# Run with sudo. Defaults to the `sudo` service — the phone then answers
# `sudo`, and a refusal falls straight through to the password prompt because
# the module is inserted as `sufficient`.
#
# Usage: sudo bash scripts/install-pam-system.sh [service]
#
# Safety: the service file is backed up before the edit, the module is inserted
# *before* any existing auth line, and the script refuses to continue if the
# backup already exists (that would mean a half-finished earlier run).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE="${1:-sudo}"
PAM_DIR=/etc/pam.d
SERVICE_FILE="${PAM_DIR}/${SERVICE}"
BACKUP="${SERVICE_FILE}.deunlock.bak"
MODULE_DIR="$(pkg-config --variable=libdir pam 2>/dev/null || echo /usr/lib/x86_64-linux-gnu)/security"
MODULE="${MODULE_DIR}/pam_deunlock.so"
MODULE_ARGS="timeout=27000"

if [ "$(id -u)" -ne 0 ]; then
    echo "run this with sudo" >&2
    exit 1
fi
if [ ! -f "${SERVICE_FILE}" ]; then
    echo "no PAM service named ${SERVICE} (${SERVICE_FILE})" >&2
    exit 1
fi
if [ -e "${BACKUP}" ]; then
    echo "refusing: ${BACKUP} already exists — a previous run left it behind." >&2
    echo "Inspect it, then remove it to retry." >&2
    exit 1
fi

SO="${ROOT}/target/release/libpam_deunlock.so"
if [ ! -f "${SO}" ]; then
    echo "build first: cargo build --release -p deunlock-pam" >&2
    exit 1
fi

install -m 0755 -D "${SO}" "${MODULE}"
echo "installed ${MODULE}"

cp -a "${SERVICE_FILE}" "${BACKUP}"

# Insert the insufficient-until-proven line above the first auth directive so it
# runs before the password prompt, and never duplicate an existing line.
LINE="auth    sufficient    pam_deunlock.so ${MODULE_ARGS}"
if grep -q "pam_deunlock.so" "${SERVICE_FILE}"; then
    echo "${SERVICE_FILE} already mentions pam_deunlock.so — leaving it alone"
else
    tmp="$(mktemp)"
    { echo "${LINE}"; cat "${BACKUP}"; } >"${tmp}"
    # `#%PAM-1.0` must stay the first line of the file.
    if head -1 "${BACKUP}" | grep -q '^#%PAM'; then
        { head -1 "${BACKUP}"; echo "${LINE}"; tail -n +2 "${BACKUP}"; } >"${tmp}"
    fi
    chmod --reference="${BACKUP}" "${tmp}"
    mv "${tmp}" "${SERVICE_FILE}"
fi

echo
echo "--- ${SERVICE_FILE} ---"
cat "${SERVICE_FILE}"
echo "-----------------------"
echo "backup: ${BACKUP}"
echo "rollback: sudo cp -a ${BACKUP} ${SERVICE_FILE}"
echo
echo "Test it — the phone should ask for a fingerprint, and Ctrl-C / a refusal"
echo "falls through to the password prompt:"
echo "    sudo true"
