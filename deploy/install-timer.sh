#!/usr/bin/env bash
# Install the 08:00 / 20:00 (Europe/London) systemd user timer for this checkout.
# Requires lingering for unattended runs: `loginctl enable-linger "$USER"`.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
unit_dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
mkdir -p "$unit_dir"

sed "s|@REPO@|${repo}|" "$repo/deploy/systemd/ti-pipeline.service" > "$unit_dir/ti-pipeline.service"
cp "$repo/deploy/systemd/ti-pipeline.timer" "$unit_dir/ti-pipeline.timer"

systemctl --user daemon-reload
systemctl --user enable --now ti-pipeline.timer
systemctl --user list-timers ti-pipeline.timer --no-pager
