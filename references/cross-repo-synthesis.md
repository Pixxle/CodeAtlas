# Cross-Repo Synthesis — Agent Instructions

You are the synthesis agent. Your job is to read all per-repo, per-dimension analysis files
and produce a unified view that captures patterns, inconsistencies, and systemic risks
that no single-repo analysis would reveal.

## Inputs

You receive a directory structure like:

```
analysis/
├── repo-a/
│   ├── architecture.md
│   ├── code-quality.md
│   ├── dependencies.md
│   └── ...
├── repo-b/
│   ├── architecture.md
│   ├── code-quality.md
│   └── ...
└── repo-c/
    └── ...
```

Read every `.md` file across all repos.

## Analysis Steps

### 1. Cross-Cutting Patterns

For each dimension, compare findings across repos and note:

- **Consistent strengths**: Practices that all repos follow well (signals engineering culture)
- **Consistent weaknesses**: Systemic gaps that all repos share (signals organizational blind spots)
- **Outliers**: Repos that are significantly better or worse than the median on a given dimension

### 2. Inter-Service Dependencies

Map how services depend on each other:

- Shared databases or data stores
- API calls between services (look for HTTP clients, gRPC stubs, message queue publishers/consumers)
- Shared libraries or packages (in mono-repos, check internal package references)
- Shared infrastructure (same Docker base images, same CI templates)

Identify:
- **Circular dependencies** between services
- **Single points of failure** — one service that everything depends on
- **Contract risk** — services that communicate but have no shared schema or contract tests
- **Version drift** — shared dependencies at different versions across repos

### 3. Consistency Assessment

Check for consistency in:

| Area | What to compare |
|---|---|
| Language/framework versions | Same language at different versions across repos? |
| Dependency management | Same approach (npm vs yarn vs pnpm) across repos? |
| Linting/formatting | Same rules? Same tools? |
| Testing strategy | Same frameworks? Similar coverage levels? |
| CI/CD | Same pipeline structure? Same deployment targets? |
| Error handling | Same patterns? Same logging format? |
| Auth | Same auth mechanism across services? |
| Monitoring | Same APM/metrics across services? |

Inconsistency isn't always bad — but it increases cognitive load for engineers moving between repos
and suggests either deliberate polyglot choices or lack of coordination.

### 4. Organizational Signals

From the aggregate data, infer:

- **Team structure**: Do contributor patterns suggest team-per-repo or cross-functional teams?
- **Engineering maturity trajectory**: Are newer repos better than older ones (improving culture) or worse (declining standards)?
- **Technical debt awareness**: Are there TODOs/FIXMEs that reference tickets? Or orphaned TODOs with no tracking?
- **Upgrade discipline**: When one repo upgrades a shared dependency, do the others follow?

## Output

Produce a file `analysis/cross-repo-synthesis.md` with:

```markdown
# Cross-Repository Synthesis

## Systemic Strengths
[Patterns that appear consistently across repos that indicate healthy engineering culture]

## Systemic Risks
[Patterns that appear consistently across repos that indicate organizational-level problems]

## Inter-Service Dependency Map
[How services connect. Highlight circular deps, SPOFs, and contract risks]

## Consistency Matrix
| Area | Consistent? | Notes |
|---|---|---|
| ... | Yes/No/Partial | ... |

## Organizational Signals
[What the aggregate data tells us about the engineering team and culture]

## Cross-Cutting Recommendations
[Recommendations that apply across the entire codebase, not just individual repos.
These are typically process or tooling changes.]
```
