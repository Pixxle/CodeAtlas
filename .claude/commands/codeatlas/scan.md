You are performing a repository discovery scan for technical due diligence.

**Target path**: $ARGUMENTS

If no target path was provided, ask the user which directory to scan.

## Discovery Steps

### 1. Find Repositories

Look for the scanner script at `~/.claude/codeatlas/scripts/repo-scanner.sh` or `./scripts/repo-scanner.sh`. If found, run it:

```bash
bash <script-path> <target-path>
```

If the script isn't available, perform manual discovery:

```bash
# Find all git roots
find <target-path> -name ".git" -type d -maxdepth 4 | sed 's/\/.git$//'
```

### 2. For Each Repository, Gather

- **Languages**: File extensions and counts (excluding node_modules, .git, vendor, dist, build)
- **LOC**: Approximate lines of code in source files
- **Git stats**: Last commit date, total commits, contributor count
- **Top contributors**: Top 5 by commit count
- **Recent commits**: Last 5 commits
- **Directory structure**: Top 2 levels
- **Key files**: Dockerfile, docker-compose, CI configs, package manifests, linter configs, README, LICENSE

### 3. Classify Layout

| Layout | Signal |
|--------|--------|
| **Single repo** | One `.git` root |
| **Mono-repo** | One `.git` root, multiple distinct services/packages under it |
| **Multi-repo** | Multiple `.git` roots as sibling folders |

### 4. Present Results

Show the user a clear summary:
- Layout classification
- Number of repositories
- Per-repo: name, languages, LOC, contributors, last activity
- Key observations (e.g., "2 repos appear inactive — no commits in 6+ months")

Save the full discovery output to `codeatlas-output/discovery.md`.

Suggest next steps: run `/codeatlas:analyze <path>` for a full technical due diligence analysis.
