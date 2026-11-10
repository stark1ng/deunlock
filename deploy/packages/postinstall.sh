#!/bin/sh
set -eu
# Preserve existing state, ownership, permissions, and PAM configuration.
if [ ! -e /var/lib/deunlock ]; then
    install -d -m 0700 /var/lib/deunlock
fi
# Enablement and a user-manager reload are explicit per-user setup steps.
