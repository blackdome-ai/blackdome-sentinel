#!/bin/bash
set -euo pipefail

TOOLKIT_DIR="/opt/blackdome-sentinel/toolkit"
mkdir -p "$TOOLKIT_DIR"

BINARIES="chattr kill ps ss lsof rm cp sha256sum iptables"
for bin in $BINARIES; do
    src=$(which "$bin" 2>/dev/null || true)
    if [ -n "$src" ] && [ -f "$src" ]; then
        cp "$src" "$TOOLKIT_DIR/"
        echo "Cached: $bin -> $TOOLKIT_DIR/$bin"
    else
        echo "WARNING: $bin not found on system"
    fi
done

cd "$TOOLKIT_DIR"
sha256sum * > .toolkit.sha256 2>/dev/null || true

chattr +i "$TOOLKIT_DIR" 2>/dev/null || chmod 555 "$TOOLKIT_DIR"
echo "Toolkit vault ready at $TOOLKIT_DIR"
