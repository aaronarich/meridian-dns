#!/usr/bin/env bash
set -euo pipefail

REPO="aaronarich/meridian-dns"
ASSET="meridian-linux-aarch64"
BINARY="/usr/local/bin/meridian"
SERVICE="meridian.service"
VERSION_FILE="/home/aaronarich/apps/meridian-dns/.deployed-version"
LOG_TAG="meridian-update"

log() { logger -t "$LOG_TAG" "$*"; echo "$*"; }

# Get latest release tag
latest=$(gh release view --repo "$REPO" --json tagName -q '.tagName' 2>/dev/null) || {
    log "No releases found or gh failed"
    exit 0
}

# Check if already deployed
current=""
[[ -f "$VERSION_FILE" ]] && current=$(cat "$VERSION_FILE")

if [[ "$latest" == "$current" ]]; then
    log "Already on $latest, nothing to do"
    exit 0
fi

log "New release found: $latest (currently: ${current:-none})"

# Download to temp file
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

gh release download "$latest" --repo "$REPO" --pattern "$ASSET" --dir "$tmpdir" || {
    log "Failed to download $ASSET from $latest"
    exit 1
}

chmod +x "$tmpdir/$ASSET"

# Verify it's a real binary
file "$tmpdir/$ASSET" | grep -q "ELF.*aarch64" || {
    log "Downloaded file is not a valid aarch64 binary"
    exit 1
}

# Deploy
log "Installing $latest to $BINARY"
sudo cp "$tmpdir/$ASSET" "$BINARY"
sudo systemctl restart "$SERVICE"

# Verify service started
sleep 2
if systemctl is-active --quiet "$SERVICE"; then
    echo "$latest" > "$VERSION_FILE"
    log "Successfully deployed $latest"
else
    log "ERROR: Service failed to start after update to $latest"
    sudo journalctl -u "$SERVICE" --no-pager -n 10
    exit 1
fi
