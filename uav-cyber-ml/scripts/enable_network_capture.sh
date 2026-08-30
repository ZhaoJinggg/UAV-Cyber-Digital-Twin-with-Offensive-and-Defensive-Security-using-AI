#!/usr/bin/env bash
# One-time setup: allow passwordless tcpdump so the dashboard can record the
# network (cyber) layer without priming sudo each time.
#
# Installs a scoped sudoers rule for THIS user permitting only tcpdump/kill/pkill
# to run as root without a password. Run once; you'll be asked for your password
# a single time to install the rule.
set -euo pipefail

USER_NAME="$(id -un)"
TCPDUMP_BIN="$(command -v tcpdump || echo /usr/sbin/tcpdump)"
KILL_BIN="/bin/kill"
PKILL_BIN="$(command -v pkill || echo /usr/bin/pkill)"
SUDOERS_FILE="/etc/sudoers.d/uav-cyber-capture"

RULE="${USER_NAME} ALL=(root) NOPASSWD: ${TCPDUMP_BIN}, ${KILL_BIN}, ${PKILL_BIN}"

echo "==> This will let '${USER_NAME}' run tcpdump/kill/pkill as root without a password."
echo "    File:  ${SUDOERS_FILE}"
echo "    Rule:  ${RULE}"
echo

TMP="$(mktemp)"
printf '%s\n' "$RULE" > "$TMP"

# Validate syntax before installing, then install with strict perms.
if sudo visudo -cf "$TMP" >/dev/null; then
  sudo install -m 0440 -o root -g 0 "$TMP" "$SUDOERS_FILE"
  rm -f "$TMP"
  echo "==> Installed. Verifying passwordless tcpdump…"
  if sudo -n "$TCPDUMP_BIN" --version >/dev/null 2>&1; then
    echo "==> OK — network capture is enabled. Restart the dashboard if it's running."
  else
    echo "!! Verification failed. Check ${SUDOERS_FILE}."
    exit 1
  fi
else
  rm -f "$TMP"
  echo "!! sudoers syntax check failed; nothing was installed."
  exit 1
fi
