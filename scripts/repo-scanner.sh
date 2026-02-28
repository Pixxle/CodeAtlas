#!/usr/bin/env bash
# repo-scanner.sh — Discover and fingerprint repositories in a workspace
# Usage: bash repo-scanner.sh <root-folder>

set -euo pipefail

ROOT="${1:-.}"

if [ ! -d "$ROOT" ]; then
    echo "ERROR: Directory '$ROOT' does not exist."
    exit 1
fi

echo "=============================================="
echo "  REPOSITORY DISCOVERY REPORT"
echo "  Root: $(cd "$ROOT" && pwd)"
echo "  Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=============================================="
echo ""

# Find all git roots
GIT_ROOTS=()
while IFS= read -r gitdir; do
    GIT_ROOTS+=("$(dirname "$gitdir")")
done < <(find "$ROOT" -name ".git" -type d -maxdepth 4 2>/dev/null)

NUM_REPOS=${#GIT_ROOTS[@]}

if [ "$NUM_REPOS" -eq 0 ]; then
    echo "NO GIT REPOSITORIES FOUND in $ROOT (searched up to depth 4)"
    echo ""
    echo "Directory structure:"
    find "$ROOT" -type d -maxdepth 2 -not -path '*/.git/*' | head -30
    exit 0
fi

# Classify layout
if [ "$NUM_REPOS" -eq 1 ]; then
    REPO_PATH="${GIT_ROOTS[0]}"
    # Check if it's a mono-repo by looking for multiple service/package dirs
    PACKAGE_DIRS=$(find "$REPO_PATH" -maxdepth 2 -name "package.json" -o -name "pyproject.toml" -o -name "go.mod" -o -name "Cargo.toml" -o -name "pom.xml" -o -name "build.gradle" 2>/dev/null | grep -v node_modules | wc -l)
    if [ "$PACKAGE_DIRS" -gt 2 ]; then
        LAYOUT="MONO-REPO ($PACKAGE_DIRS package manifests detected)"
    else
        LAYOUT="SINGLE REPOSITORY"
    fi
else
    LAYOUT="MULTI-REPO ($NUM_REPOS repositories)"
fi

echo "LAYOUT: $LAYOUT"
echo "REPOSITORIES: $NUM_REPOS"
echo ""

# Analyze each repo
for repo in "${GIT_ROOTS[@]}"; do
    REPO_NAME=$(basename "$repo")
    echo "----------------------------------------------"
    echo "REPO: $REPO_NAME"
    echo "PATH: $repo"
    echo ""

    # Language breakdown by file extension
    echo "  LANGUAGE BREAKDOWN (by file count):"
    find "$repo" -type f \
        -not -path '*/.git/*' \
        -not -path '*/node_modules/*' \
        -not -path '*/__pycache__/*' \
        -not -path '*/venv/*' \
        -not -path '*/.venv/*' \
        -not -path '*/vendor/*' \
        -not -path '*/dist/*' \
        -not -path '*/build/*' \
        -not -path '*/.next/*' \
        -not -name "*.lock" \
        -not -name "*.min.*" \
        2>/dev/null | \
        sed 's/.*\.//' | sort | uniq -c | sort -rn | head -15 | \
        while read count ext; do
            printf "    %-20s %s files\n" ".$ext" "$count"
        done
    echo ""

    # Lines of code (rough)
    echo "  APPROXIMATE LOC (excluding vendor/generated):"
    TOTAL_LOC=$(find "$repo" -type f \
        \( -name "*.py" -o -name "*.ts" -o -name "*.tsx" -o -name "*.js" -o -name "*.jsx" \
           -o -name "*.go" -o -name "*.java" -o -name "*.rb" -o -name "*.rs" \
           -o -name "*.c" -o -name "*.cpp" -o -name "*.h" -o -name "*.cs" \
           -o -name "*.php" -o -name "*.swift" -o -name "*.kt" \) \
        -not -path '*/.git/*' \
        -not -path '*/node_modules/*' \
        -not -path '*/vendor/*' \
        -not -path '*/dist/*' \
        -not -path '*/build/*' \
        -not -path '*/.next/*' \
        -not -name "*.min.*" \
        -not -name "*.generated.*" \
        2>/dev/null | xargs wc -l 2>/dev/null | tail -1 | awk '{print $1}')
    echo "    ${TOTAL_LOC:-0} lines"
    echo ""

    # Git stats
    if git -C "$repo" rev-parse HEAD &>/dev/null; then
        echo "  GIT STATS:"
        LAST_COMMIT=$(git -C "$repo" log -1 --format="%ai" 2>/dev/null || echo "unknown")
        TOTAL_COMMITS=$(git -C "$repo" rev-list --count HEAD 2>/dev/null || echo "unknown")
        CONTRIBUTORS=$(git -C "$repo" shortlog -sn --no-merges 2>/dev/null | wc -l | tr -d ' ')
        echo "    Last commit:   $LAST_COMMIT"
        echo "    Total commits: $TOTAL_COMMITS"
        echo "    Contributors:  $CONTRIBUTORS"
        echo ""

        echo "  TOP CONTRIBUTORS:"
        git -C "$repo" shortlog -sn --no-merges 2>/dev/null | head -5 | while read count name; do
            printf "    %-30s %s commits\n" "$name" "$count"
        done
        echo ""

        echo "  RECENT COMMITS:"
        git -C "$repo" log --oneline -5 2>/dev/null | sed 's/^/    /'
    fi

    echo ""

    # Top-level structure
    echo "  DIRECTORY STRUCTURE (depth 2):"
    find "$repo" -maxdepth 2 -type d \
        -not -path '*/.git/*' \
        -not -path '*/node_modules/*' \
        -not -path '*/__pycache__/*' \
        -not -path '*/venv/*' \
        -not -path '*/.venv/*' \
        2>/dev/null | sed "s|$repo|.|" | sort | head -40 | sed 's/^/    /'

    echo ""

    # Key config files present
    echo "  KEY FILES DETECTED:"
    for f in Dockerfile docker-compose.yml .github/workflows Makefile package.json pyproject.toml go.mod Cargo.toml pom.xml .eslintrc.json .prettierrc tsconfig.json jest.config.js pytest.ini .env.example README.md LICENSE; do
        if [ -e "$repo/$f" ] || ls "$repo/$f"* &>/dev/null 2>&1; then
            echo "    ✓ $f"
        fi
    done

    echo ""
done

echo "=============================================="
echo "  DISCOVERY COMPLETE"
echo "=============================================="
