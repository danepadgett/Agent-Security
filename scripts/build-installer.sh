#!/usr/bin/env bash
# =============================================================================
# Hound — Build Installer
# =============================================================================
# Builds release binaries and packages them into a distributable .dmg installer.
#
# Output:
#   dist/Hound.app                — App bundle (ready for /Applications)
#   dist/uninstall.sh             — Clean uninstaller
#   dist/install.sh               — Post-install setup (LaunchAgents + autostart)
#   dist/Hound-0.1.0.dmg          — Final distributable
#
# Usage:
#   ./scripts/build-installer.sh
#
# Requirements:
#   - Xcode Command Line Tools
#   - Node.js + npm
#   - Rust (stable)
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

VERSION="0.1.0"
APP_NAME="Hound"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST="$ROOT/dist"
APP_BUNDLE="$DIST/$APP_NAME.app"
MACOS_DIR="$APP_BUNDLE/Contents/MacOS"
LAUNCH_AGENT_DIR="$APP_BUNDLE/Contents/LaunchAgent"

print_step() { echo -e "  ${CYAN}▶${RESET}  $*"; }
print_ok()   { echo -e "  ${GREEN}✓${RESET}  $*"; }
die()        { echo -e "\n  ${RED}✗  ERROR: $*${RESET}" >&2; exit 1; }

echo ""
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  Hound — Installer Build${RESET}  v${VERSION}"
echo -e "${BOLD}${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

# ── [1/6] Build Rust binaries ─────────────────────────────────────────────────
print_step "[1/6] Building Rust release binaries…"
(
  cd "$ROOT/agents/core-agent"
  cargo build --release --bin core-agent --bin watchdog 2>&1
) || die "cargo build failed — ensure 'rustup' and 'cargo' are available"
print_ok "core-agent and watchdog built"

# ── [2/6] Build Tauri desktop app ─────────────────────────────────────────────
print_step "[2/6] Building Tauri desktop app…"
(
  cd "$ROOT/apps/desktop"
  npm install 2>&1
  npm run tauri build 2>&1
) || die "Tauri build failed — ensure node, npm, and Xcode CLT are installed"
print_ok "Tauri app built"

# ── [3/6] Assemble app bundle ─────────────────────────────────────────────────
print_step "[3/6] Assembling app bundle…"

TAURI_APP="$ROOT/apps/desktop/src-tauri/target/release/bundle/macos/$APP_NAME.app"
[[ -d "$TAURI_APP" ]] || die "Tauri app bundle not found at: $TAURI_APP"

# Start fresh
rm -rf "$DIST"
mkdir -p "$DIST"

# Copy Tauri app bundle as the base
cp -R "$TAURI_APP" "$APP_BUNDLE"

# Add core-agent and watchdog to the MacOS directory
cp "$ROOT/agents/core-agent/target/release/core-agent" "$MACOS_DIR/core-agent"
cp "$ROOT/agents/core-agent/target/release/watchdog"   "$MACOS_DIR/watchdog"
chmod +x "$MACOS_DIR/core-agent" "$MACOS_DIR/watchdog"

# Create LaunchAgent directory inside the bundle
mkdir -p "$LAUNCH_AGENT_DIR"

print_ok "App bundle assembled at: $APP_BUNDLE"

# ── [4/6] Create LaunchAgent plists ───────────────────────────────────────────
print_step "[4/6] Creating LaunchAgent plists…"

cat > "$LAUNCH_AGENT_DIR/com.hound.agent.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.hound.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Applications/Hound.app/Contents/MacOS/core-agent</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>~/Library/Logs/Hound/agent.log</string>
  <key>StandardErrorPath</key>
  <string>~/Library/Logs/Hound/agent-error.log</string>
</dict>
</plist>
PLIST

cat > "$LAUNCH_AGENT_DIR/com.hound.watchdog.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.hound.watchdog</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Applications/Hound.app/Contents/MacOS/watchdog</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>~/Library/Logs/Hound/watchdog.log</string>
  <key>StandardErrorPath</key>
  <string>~/Library/Logs/Hound/watchdog-error.log</string>
</dict>
</plist>
PLIST

print_ok "LaunchAgent plists created"

# ── [5/6] Create install and uninstall scripts ────────────────────────────────
print_step "[5/6] Creating install and uninstall scripts…"

# install.sh — run after dragging app to /Applications
cat > "$DIST/install.sh" << 'SCRIPT'
#!/bin/bash
# Hound — Post-Install Setup
# Run this after dragging "Hound" to your Applications folder.
set -euo pipefail

APP="/Applications/Hound.app"
LAUNCH_DIR="$HOME/Library/LaunchAgents"

[[ -d "$APP" ]] || { echo "Error: $APP not found. Drag it to /Applications first."; exit 1; }

echo "Setting up Hound…"

mkdir -p "$LAUNCH_DIR"
mkdir -p "$HOME/Library/Logs/Hound"

cp "$APP/Contents/LaunchAgent/com.hound.agent.plist"    "$LAUNCH_DIR/"
cp "$APP/Contents/LaunchAgent/com.hound.watchdog.plist" "$LAUNCH_DIR/"

launchctl load "$LAUNCH_DIR/com.hound.agent.plist"    2>/dev/null || true
launchctl load "$LAUNCH_DIR/com.hound.watchdog.plist" 2>/dev/null || true

echo "Hound is running and will start automatically on login."
open "$APP"
SCRIPT
chmod +x "$DIST/install.sh"

# uninstall.sh
cat > "$DIST/uninstall.sh" << 'SCRIPT'
#!/bin/bash
# Hound — Uninstaller
set -euo pipefail

echo "Uninstalling Hound…"

launchctl unload "$HOME/Library/LaunchAgents/com.hound.agent.plist"    2>/dev/null || true
launchctl unload "$HOME/Library/LaunchAgents/com.hound.watchdog.plist" 2>/dev/null || true

rm -f "$HOME/Library/LaunchAgents/com.hound.agent.plist"
rm -f "$HOME/Library/LaunchAgents/com.hound.watchdog.plist"

rm -rf "/Applications/Hound.app"
rm -rf "$HOME/Library/Logs/Hound"

echo ""
echo "Hound has been uninstalled."
echo "Your security history has been preserved at:"
echo "  ~/Projects/Hound/runtime/"
echo "To also remove your security history, delete that folder manually."
SCRIPT
chmod +x "$DIST/uninstall.sh"

print_ok "install.sh and uninstall.sh created"

# ── [6/6] Create DMG ──────────────────────────────────────────────────────────
print_step "[6/6] Creating DMG…"

DMG_STAGING="$DIST/.dmg-staging"
rm -rf "$DMG_STAGING"
mkdir -p "$DMG_STAGING"

cp -R "$APP_BUNDLE"        "$DMG_STAGING/"
cp    "$DIST/install.sh"   "$DMG_STAGING/Install Hound.command"
cp    "$DIST/uninstall.sh" "$DMG_STAGING/Uninstall.command"
ln -s /Applications        "$DMG_STAGING/Applications"

DMG="$DIST/Hound-${VERSION}.dmg"
hdiutil create \
  -volname "$APP_NAME" \
  -srcfolder "$DMG_STAGING" \
  -ov \
  -format UDZO \
  "$DMG" > /dev/null 2>&1 || die "hdiutil failed"

rm -rf "$DMG_STAGING"

print_ok "DMG created: $DMG"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}Build complete.${RESET}"
echo ""
echo -e "  ${DIM}App bundle:${RESET}  $APP_BUNDLE"
echo -e "  ${DIM}Installer:${RESET}   $DIST/install.sh"
echo -e "  ${DIM}Uninstaller:${RESET} $DIST/uninstall.sh"
echo -e "  ${DIM}DMG:${RESET}         $DMG"
echo ""
echo -e "  ${DIM}To distribute: share $DMG${RESET}"
echo -e "  ${DIM}To install:    open the DMG → drag app to Applications → run 'Install Hound.command'${RESET}"
echo ""
