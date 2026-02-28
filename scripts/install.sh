#!/usr/bin/env bash
# install.sh — Install CodeAtlas as global Claude Code commands
#
# This copies commands to ~/.claude/commands/codeatlas/ so you can
# use /codeatlas:analyze, /codeatlas:scan, and /codeatlas:report
# from any project directory.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

COMMANDS_DIR="$HOME/.claude/commands/codeatlas"
CODEATLAS_DIR="$HOME/.claude/codeatlas"

echo "CodeAtlas Installer"
echo "==================="
echo ""
echo "Source:  $PROJECT_ROOT"
echo "Commands -> $COMMANDS_DIR"
echo "Data     -> $CODEATLAS_DIR"
echo ""

# Create directories
mkdir -p "$COMMANDS_DIR"
mkdir -p "$CODEATLAS_DIR/references"
mkdir -p "$CODEATLAS_DIR/scripts"

# Copy command files
cp "$PROJECT_ROOT/.claude/commands/codeatlas/"*.md "$COMMANDS_DIR/"
echo "Installed commands:"
for f in "$COMMANDS_DIR"/*.md; do
    echo "  /codeatlas:$(basename "$f" .md)"
done

# Copy reference files
cp "$PROJECT_ROOT/references/"*.md "$CODEATLAS_DIR/references/"
echo ""
echo "Installed references:"
for f in "$CODEATLAS_DIR/references/"*.md; do
    echo "  $(basename "$f")"
done

# Copy scripts
cp "$PROJECT_ROOT/scripts/repo-scanner.sh" "$CODEATLAS_DIR/scripts/"
chmod +x "$CODEATLAS_DIR/scripts/repo-scanner.sh"
echo ""
echo "Installed scripts:"
echo "  repo-scanner.sh"

echo ""
echo "Done. You can now use /codeatlas:analyze, /codeatlas:scan,"
echo "and /codeatlas:report from any project in Claude Code."
