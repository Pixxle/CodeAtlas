# Analysis Dimensions — Investigative Playbook

Each section below is a self-contained guide for one analysis dimension.
Sub-agents: navigate to your assigned dimension and follow its instructions.

---

## Table of Contents

1. [Architecture & Design](#1-architecture--design)
2. [Code Quality & Standards](#2-code-quality--standards)
3. [Dependency & Supply Chain](#3-dependency--supply-chain)
4. [Security Posture](#4-security-posture)
5. [Testing & Quality Assurance](#5-testing--quality-assurance)
6. [CI/CD & DevOps](#6-cicd--devops)
7. [Documentation & Knowledge](#7-documentation--knowledge)
8. [Git Health & Team Dynamics](#8-git-health--team-dynamics)
9. [Performance & Scalability](#9-performance--scalability)
10. [Infrastructure & Configuration](#10-infrastructure--configuration)

---

## 1. Architecture & Design

**Goal**: Assess whether the system's structure supports its current and likely future requirements.

### What to investigate

- **High-level structure**: Identify the architectural pattern (monolith, microservices, modular monolith, serverless, event-driven, etc.). Check if the actual code matches the stated architecture.
- **Module boundaries**: Are there clear boundaries between components? Look for `packages/`, `services/`, `modules/`, or similar directory structures. Check if imports respect boundaries or if there's spaghetti cross-referencing.
- **Coupling & cohesion**: Trace import graphs. Are there god-modules that everything depends on? Are related concerns grouped together?
- **Data flow**: How does data move through the system? Identify the primary data stores, message brokers, caches, and API boundaries.
- **Scalability patterns**: Are there horizontal scaling bottlenecks? Stateful components that can't scale? Single points of failure?
- **API design**: For services with APIs, assess consistency, versioning strategy, and contract definition (OpenAPI specs, GraphQL schemas, protobuf definitions).

### Commands to run

```bash
# Directory tree (depth 3, ignore common noise)
find . -type d -not -path '*/.git/*' -not -path '*/node_modules/*' -not -path '*/__pycache__/*' -not -path '*/venv/*' -not -path '*/.venv/*' | head -100

# Import/dependency graph for Python
grep -rn "^from \|^import " --include="*.py" | awk -F: '{print $1, $2}' | head -100

# Import graph for TypeScript/JavaScript
grep -rn "^import \|require(" --include="*.ts" --include="*.tsx" --include="*.js" --include="*.jsx" | head -100

# Find API route definitions
grep -rn "app\.\(get\|post\|put\|delete\|patch\)\|@app\.route\|@router\.\|\.controller\|@Controller\|@Get\|@Post" --include="*.py" --include="*.ts" --include="*.js" | head -50

# Find shared/common modules
find . -type d -name "shared" -o -name "common" -o -name "utils" -o -name "lib" -o -name "core" | grep -v node_modules | grep -v .git
```

### Rating guide

| Rating | Criteria |
|---|---|
| **Strong** | Clear boundaries, low coupling, documented architecture decisions, scalability considered |
| **Acceptable** | Reasonable structure with some coupling issues, architecture is implicit but consistent |
| **Concerning** | Unclear boundaries, high coupling, architecture doesn't match stated design |
| **Critical** | No discernible architecture, circular dependencies, fundamental scalability blockers |

---

## 2. Code Quality & Standards

**Goal**: Assess code readability, maintainability, and adherence to established patterns.

### What to investigate

- **Consistency**: Is there a unified coding style? Look for linter configs (`.eslintrc`, `.flake8`, `pyproject.toml [tool.ruff]`, `.prettierrc`, etc.).
- **Complexity**: Identify overly complex functions. Functions over 50 lines, deeply nested conditionals, high cyclomatic complexity.
- **Anti-patterns**: Dead code, commented-out code blocks, copy-paste duplication, magic numbers/strings, overly broad exception handling.
- **Type safety**: For dynamically typed languages, is there type annotation usage (Python type hints, TypeScript strict mode, JSDoc)?
- **Error handling**: How are errors propagated? Are there catch-all handlers that swallow errors? Is there structured error reporting?
- **Naming conventions**: Are names descriptive? Consistent casing? Do variable names communicate intent?

### Commands to run

```bash
# Find linter/formatter configs
find . -maxdepth 3 -name ".eslintrc*" -o -name ".prettierrc*" -o -name ".flake8" -o -name "pyproject.toml" -o -name ".rubocop.yml" -o -name ".editorconfig" -o -name "biome.json" -o -name "deno.json" | grep -v node_modules

# Longest files (often problematic)
find . -name "*.py" -o -name "*.ts" -o -name "*.js" -o -name "*.go" -o -name "*.java" -o -name "*.rb" | grep -v node_modules | grep -v .git | xargs wc -l 2>/dev/null | sort -rn | head -20

# Find TODO/FIXME/HACK comments
grep -rn "TODO\|FIXME\|HACK\|XXX\|WORKAROUND" --include="*.py" --include="*.ts" --include="*.js" --include="*.go" --include="*.java" --include="*.rb" | wc -l

# Find commented-out code blocks (rough heuristic)
grep -rn "^[[:space:]]*//.*function\|^[[:space:]]*//.*class\|^[[:space:]]*//.*def \|^[[:space:]]*#.*def \|^[[:space:]]*#.*class " --include="*.py" --include="*.ts" --include="*.js" | head -20

# Find functions longer than 50 lines (Python)
awk '/^def /{name=$0; start=NR} /^[^ \t]/ && NR>start+50 && start>0{print FILENAME":"start": "name" ("NR-start" lines)"; start=0}' $(find . -name "*.py" -not -path "*/node_modules/*" -not -path "*/.git/*") 2>/dev/null | head -20

# Duplication detection (rough — find files with similar names)
find . -type f \( -name "*.py" -o -name "*.ts" -o -name "*.js" \) -not -path "*/node_modules/*" -not -path "*/.git/*" | xargs -I{} basename {} | sort | uniq -d
```

### Rating guide

| Rating | Criteria |
|---|---|
| **Strong** | Enforced linting, consistent style, low complexity, good naming, minimal dead code |
| **Acceptable** | Linting present but not strict, some inconsistencies, moderate complexity in places |
| **Concerning** | No linting, inconsistent style, high complexity, significant dead code |
| **Critical** | Unreadable code, massive functions, pervasive anti-patterns, no discernible standards |

---

## 3. Dependency & Supply Chain

**Goal**: Assess the health, security, and maintainability of third-party dependencies.

### What to investigate

- **Manifest files**: Identify `package.json`, `requirements.txt`, `Pipfile`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `Gemfile`, `pom.xml`, `build.gradle`, etc.
- **Lock files**: Are they present and committed? Missing lock files mean non-reproducible builds.
- **Outdated dependencies**: How far behind are major dependencies? Are there dependencies pinned to versions with known CVEs?
- **Dependency count**: Is the dependency tree reasonable for the project's complexity? Excessive deps increase attack surface.
- **License risk**: Are there copyleft licenses (GPL, AGPL) in the dependency tree that could affect commercial use?
- **Internal vs. external**: In mono-repos, are internal packages properly referenced, or are there brittle path-based imports?
- **Abandoned dependencies**: Are critical deps maintained? Check last publish date and open issue count if possible.

### Commands to run

```bash
# Find all manifest files
find . -maxdepth 4 -name "package.json" -o -name "requirements*.txt" -o -name "Pipfile" -o -name "pyproject.toml" -o -name "go.mod" -o -name "Cargo.toml" -o -name "Gemfile" -o -name "pom.xml" -o -name "build.gradle*" | grep -v node_modules

# Check for lock files
find . -maxdepth 4 -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" -o -name "Pipfile.lock" -o -name "poetry.lock" -o -name "Cargo.lock" -o -name "go.sum" -o -name "Gemfile.lock" | grep -v node_modules

# Count direct dependencies (Node)
cat package.json 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print('deps:', len(d.get('dependencies',{})), 'devDeps:', len(d.get('devDependencies',{})))" 2>/dev/null

# Check for known vulnerabilities (if npm/pip available)
# npm audit --json 2>/dev/null | head -50
# pip-audit 2>/dev/null | head -50

# Look for pinning strategy
head -30 requirements*.txt 2>/dev/null
cat package.json 2>/dev/null | python3 -c "import sys,json; deps=json.load(sys.stdin).get('dependencies',{}); [print(k,v) for k,v in list(deps.items())[:20]]" 2>/dev/null
```

### Rating guide

| Rating | Criteria |
|---|---|
| **Strong** | Lock files committed, deps regularly updated, no known CVEs, reasonable dep count, license-clean |
| **Acceptable** | Lock files present, some outdated deps but no critical CVEs, minor license concerns |
| **Concerning** | Missing lock files, significantly outdated deps, unpatched CVEs, license ambiguity |
| **Critical** | No dependency management, known critical CVEs, GPL contamination in commercial product |

---

## 4. Security Posture

**Goal**: Identify security risks, both in code patterns and in operational configuration.

### What to investigate

- **Secrets in code**: API keys, tokens, passwords, connection strings committed to the repo. Check both current files and git history.
- **Authentication & authorization**: How is auth implemented? Are there proper access controls? Is session management secure?
- **Input validation**: Are user inputs validated and sanitized? Look for SQL injection, XSS, command injection patterns.
- **Cryptography**: Are modern algorithms used? Are there hardcoded keys or IVs? Is HTTPS enforced?
- **Security headers & CORS**: For web services, check CORS configuration, CSP, HSTS.
- **Logging & audit**: Is there security-relevant logging? Are sensitive data fields masked in logs?
- **Known vulnerability classes**: OWASP Top 10 relevant patterns for the tech stack.

### Commands to run

```bash
# Scan for potential secrets (high-signal patterns)
grep -rn "AKIA[0-9A-Z]\{16\}\|password\s*=\s*['\"].\+['\"]\|api_key\s*=\s*['\"].\+['\"]\|secret\s*=\s*['\"].\+['\"]\|token\s*=\s*['\"].\+['\"]" --include="*.py" --include="*.ts" --include="*.js" --include="*.yaml" --include="*.yml" --include="*.json" --include="*.env" --include="*.cfg" --include="*.conf" | grep -v node_modules | grep -v ".git/" | grep -v "test" | head -30

# Check for .env files committed
find . -name ".env" -o -name ".env.local" -o -name ".env.production" | grep -v node_modules | grep -v .git

# Check .gitignore for secret exclusions
cat .gitignore 2>/dev/null | grep -i "env\|secret\|key\|credential"

# Check for SQL query construction (injection risk)
grep -rn "f\".*SELECT\|f\".*INSERT\|f\".*UPDATE\|f\".*DELETE\|\.format(.*SELECT\|%s.*SELECT\|execute(.*+\|query(.*+" --include="*.py" | grep -v node_modules | head -20

# Check for eval/exec usage
grep -rn "eval(\|exec(\|os\.system(\|subprocess\.call(\|child_process\|shell=True" --include="*.py" --include="*.ts" --include="*.js" | grep -v node_modules | grep -v test | head -20

# CORS configuration
grep -rn "cors\|CORS\|Access-Control" --include="*.py" --include="*.ts" --include="*.js" --include="*.yaml" --include="*.yml" | grep -v node_modules | head -20

# Check for security-related dependencies
grep -i "helmet\|cors\|csrf\|bcrypt\|argon\|jwt\|oauth\|passport\|auth0\|keycloak" package.json requirements*.txt pyproject.toml 2>/dev/null
```

### Rating guide

| Rating | Criteria |
|---|---|
| **Strong** | No secrets in code, proper auth framework, input validation throughout, security deps present |
| **Acceptable** | No secrets in current code (check history), auth present but could be stronger, some validation gaps |
| **Concerning** | Secrets found in history, auth has bypass risks, inconsistent input validation |
| **Critical** | Active secrets in code, no auth framework, SQL injection or RCE vectors present |

---

## 5. Testing & Quality Assurance

**Goal**: Assess test coverage, test quality, and the testing culture of the team.

### What to investigate

- **Test existence**: Are there test files? What percentage of source files have corresponding tests?
- **Test types**: Unit tests, integration tests, end-to-end tests, contract tests, snapshot tests? What's the distribution?
- **Test quality**: Are tests actually asserting meaningful behavior, or are they trivial? Do they test edge cases?
- **Coverage configuration**: Is there a coverage tool configured? What are the thresholds?
- **Test infrastructure**: Are there test fixtures, factories, mocks? Is there a test database setup?
- **Flaky test signals**: Look for retry logic, `skip`/`xfail` markers, or comments about flakiness.

### Commands to run

```bash
# Find test files
find . -type f \( -name "*test*" -o -name "*spec*" -o -path "*/tests/*" -o -path "*/__tests__/*" \) \( -name "*.py" -o -name "*.ts" -o -name "*.js" -o -name "*.go" -o -name "*.java" -o -name "*.rb" \) | grep -v node_modules | grep -v .git | wc -l

# Count test vs source files
echo "Source files:"; find . -type f \( -name "*.py" -o -name "*.ts" -o -name "*.js" \) -not -path "*/node_modules/*" -not -path "*/.git/*" -not -name "*test*" -not -name "*spec*" -not -path "*/tests/*" -not -path "*/__tests__/*" | wc -l
echo "Test files:"; find . -type f \( -name "*test*" -o -name "*spec*" -o -path "*/tests/*" -o -path "*/__tests__/*" \) \( -name "*.py" -o -name "*.ts" -o -name "*.js" \) -not -path "*/node_modules/*" -not -path "*/.git/*" | wc -l

# Check for coverage config
find . -maxdepth 3 -name ".coveragerc" -o -name "coverage.config.*" -o -name "jest.config.*" -o -name "pytest.ini" -o -name "setup.cfg" -o -name ".nycrc*" | grep -v node_modules

# Look for test framework usage
grep -rn "describe(\|it(\|test(\|expect(\|assert\|pytest\|unittest\|@Test\|func Test" --include="*.py" --include="*.ts" --include="*.js" --include="*.go" --include="*.java" | grep -v node_modules | head -5

# Find skipped/disabled tests
grep -rn "skip\|xfail\|xit(\|xdescribe(\|\.skip(\|@Disabled\|@Ignore\|pending(" --include="*.py" --include="*.ts" --include="*.js" --include="*.go" --include="*.java" | grep -v node_modules | wc -l

# Check for E2E test frameworks
find . -name "cypress.config.*" -o -name "playwright.config.*" -o -name ".puppeteerrc*" -o -name "wdio.conf.*" | grep -v node_modules
```

### Rating guide

| Rating | Criteria |
|---|---|
| **Strong** | >70% test ratio, multiple test types, coverage configured with thresholds, CI-enforced |
| **Acceptable** | Tests exist for core paths, some coverage tracking, at least unit + some integration |
| **Concerning** | Sparse tests, no coverage tracking, only happy-path testing |
| **Critical** | No tests, or tests exist but are all skipped/broken |

---

## 6. CI/CD & DevOps

**Goal**: Assess the maturity of the build, test, and deployment pipeline.

### What to investigate

- **CI configuration**: GitHub Actions, GitLab CI, Jenkins, CircleCI, etc. What runs on each trigger?
- **Pipeline stages**: Does the pipeline lint, test, build, scan, and deploy? Or just build?
- **Deployment strategy**: Blue/green, canary, rolling, or yolo-push-to-main?
- **Environment management**: How are staging/production environments defined? Is there environment parity?
- **Artifact management**: Are build artifacts versioned and stored? Are Docker images tagged properly?
- **Rollback capability**: Can a bad deploy be rolled back quickly? Is there evidence this has been done?

### Commands to run

```bash
# Find CI config files
find . -maxdepth 3 -name "*.yml" -o -name "*.yaml" | xargs grep -l "jobs:\|stages:\|pipeline:\|steps:" 2>/dev/null | head -20
find . -name ".github" -type d
find . -name ".gitlab-ci.yml" -o -name "Jenkinsfile" -o -name ".circleci" -type d -o -name ".travis.yml" -o -name "bitbucket-pipelines.yml"

# Read CI config
cat .github/workflows/*.yml 2>/dev/null | head -100
cat .gitlab-ci.yml 2>/dev/null | head -100

# Check for Dockerfiles
find . -name "Dockerfile*" -o -name "docker-compose*.yml" -o -name ".dockerignore" | grep -v node_modules

# Check for infrastructure as code
find . -name "*.tf" -o -name "*.tfvars" -o -name "serverless.yml" -o -name "cdk.json" -o -name "pulumi.*" -o -name "*.bicep" | grep -v node_modules | head -20

# Check for deployment scripts
find . -name "deploy*" -o -name "release*" | grep -v node_modules | grep -v .git | head -10
```

### Rating guide

| Rating | Criteria |
|---|---|
| **Strong** | Full CI/CD pipeline, automated tests in CI, staged deployments, rollback capability |
| **Acceptable** | CI runs tests and builds, manual deploy process but documented |
| **Concerning** | CI exists but doesn't run tests, no staging environment |
| **Critical** | No CI/CD, manual FTP deployments, no build process |

---

## 7. Documentation & Knowledge

**Goal**: Assess how well the codebase communicates its purpose, design, and usage to developers.

### What to investigate

- **README quality**: Does the root README explain what the project does, how to set it up, and how to contribute?
- **API documentation**: For services with APIs, are they documented (OpenAPI, GraphQL introspection, API docs)?
- **Architecture Decision Records (ADRs)**: Are important decisions documented with context and rationale?
- **Inline documentation**: Are complex functions documented? Is there a balance (not over-documented boilerplate, not zero docs on complex logic)?
- **Onboarding**: Could a new developer get the project running from the README alone?
- **Changelog / release notes**: Is there a changelog? Are releases documented?

### Commands to run

```bash
# Check for documentation files
find . -maxdepth 3 -name "README*" -o -name "CONTRIBUTING*" -o -name "CHANGELOG*" -o -name "ADR-*" -o -name "adr-*" -o -name "ARCHITECTURE*" | grep -v node_modules

# Check README length and quality signals
wc -l README* 2>/dev/null
grep -c "## \|### \|```\|http" README.md 2>/dev/null

# Check for API docs
find . -maxdepth 4 -name "openapi*" -o -name "swagger*" -o -name "*.graphql" -o -name "schema.graphql" | grep -v node_modules

# Check for docs directory
find . -type d -name "docs" -o -name "documentation" -o -name "wiki" | grep -v node_modules | grep -v .git

# Check for ADR directory
find . -type d -name "adr" -o -name "adrs" -o -name "decisions" | grep -v node_modules
```

### Rating guide

| Rating | Criteria |
|---|---|
| **Strong** | Comprehensive README, API docs, ADRs present, good onboarding path |
| **Acceptable** | README covers basics, some API docs, setup instructions work |
| **Concerning** | Minimal README, no API docs, tribal knowledge dominant |
| **Critical** | No README or outdated/wrong README, no documentation of any kind |

---

## 8. Git Health & Team Dynamics

**Goal**: Understand the development culture, contributor health, and collaboration patterns from git metadata.

### What to investigate

- **Bus factor**: How many contributors account for >80% of commits? Is knowledge concentrated?
- **Commit frequency**: Is development active? When was the last commit? Are there long dormant periods?
- **PR/merge practices**: Are there merge commits suggesting PR reviews? Or direct pushes to main?
- **Branch strategy**: Is there a discernible branching model (trunk-based, git-flow, etc.)?
- **Commit quality**: Are commit messages meaningful? Are there atomic commits or massive "fix everything" commits?
- **Code review signals**: Look for merge commits with multiple authors, co-authored-by trailers, or PR templates.

### Commands to run

```bash
# Contributor distribution (bus factor)
git shortlog -sn --no-merges | head -15

# Commit frequency over last 12 months
git log --since="12 months ago" --format="%ai" | cut -d'-' -f1-2 | sort | uniq -c

# Last commit date
git log -1 --format="%ai"

# Average commits per week (last 6 months)
echo "Commits in last 6 months:"; git log --since="6 months ago" --oneline | wc -l

# Branch analysis
git branch -r | head -20

# Merge vs direct commit ratio
echo "Merge commits:"; git log --merges --oneline | wc -l
echo "Total commits:"; git log --oneline | wc -l

# Commit message quality (sample)
git log --oneline -20

# Check for PR templates
find . -name "pull_request_template*" -o -name "PULL_REQUEST_TEMPLATE*" | head -5

# Large commits (potential code dumps)
git log --format="%h %s" --shortstat | head -60
```

### Rating guide

| Rating | Criteria |
|---|---|
| **Strong** | Multiple active contributors, consistent commit history, PR-based workflow, meaningful messages |
| **Acceptable** | Small team but consistent, some PR practice, reasonable commit messages |
| **Concerning** | Single contributor dominance, erratic commit patterns, no review evidence |
| **Critical** | Single contributor, dormant repo, massive infrequent commits, no review process |

---

## 9. Performance & Scalability

**Goal**: Identify obvious performance risks and assess whether the codebase is built for growth.

### What to investigate

- **Database patterns**: N+1 queries, missing indexes, unoptimized queries, connection pooling.
- **Caching**: Is there a caching strategy? Redis/Memcached usage? HTTP caching headers?
- **Async patterns**: Are I/O-heavy operations async? Are there blocking calls in hot paths?
- **Resource management**: Are connections/files/streams properly closed? Look for resource leaks.
- **Pagination**: Are list endpoints paginated? Or do they return unbounded result sets?
- **Rate limiting**: Is there rate limiting on public endpoints?
- **Monitoring**: Are there performance monitoring hooks (APM, metrics, tracing)?

### Commands to run

```bash
# Check for ORM usage and query patterns
grep -rn "\.query\|\.execute\|\.find(\|\.findAll\|\.findMany\|SELECT.*FROM\|\.all()\|\.objects\." --include="*.py" --include="*.ts" --include="*.js" | grep -v node_modules | grep -v test | head -20

# Check for caching
grep -rn "redis\|memcache\|cache\|Redis(\|createClient\|CACHE_TTL\|@cache\|lru_cache" --include="*.py" --include="*.ts" --include="*.js" --include="*.yaml" | grep -v node_modules | head -15

# Check for async patterns
grep -rn "async def\|async function\|await \|Promise\.\|\.then(\|asyncio" --include="*.py" --include="*.ts" --include="*.js" | grep -v node_modules | grep -v test | wc -l

# Check for monitoring/APM
grep -rn "datadog\|newrelic\|sentry\|prometheus\|opentelemetry\|statsd\|metrics\.\|trace\.\|span\." --include="*.py" --include="*.ts" --include="*.js" --include="*.yaml" | grep -v node_modules | head -15

# Check for pagination
grep -rn "offset\|limit\|page_size\|pageSize\|per_page\|cursor\|skip.*take" --include="*.py" --include="*.ts" --include="*.js" | grep -v node_modules | grep -v test | head -15
```

### Rating guide

| Rating | Criteria |
|---|---|
| **Strong** | Caching strategy, async I/O, pagination everywhere, monitoring in place, connection pooling |
| **Acceptable** | Basic caching, mostly async, pagination on main endpoints |
| **Concerning** | No caching, blocking I/O in hot paths, unbounded queries |
| **Critical** | N+1 everywhere, no pagination, synchronous blocking calls, no monitoring |

---

## 10. Infrastructure & Configuration

**Goal**: Assess how infrastructure is managed and how configuration flows from development to production.

### What to investigate

- **Infrastructure as Code (IaC)**: Terraform, CloudFormation, CDK, Pulumi, Ansible? Or manually provisioned?
- **Configuration management**: How are config values managed? Environment variables, config files, secrets managers?
- **Environment parity**: Do dev/staging/production environments use similar configurations?
- **Container strategy**: Are Dockerfiles well-structured? Multi-stage builds? Minimal base images?
- **Secret management**: Are secrets managed via a vault/secrets manager, or hardcoded/env-file based?
- **Database migrations**: Is there a migration framework? Are migrations version-controlled?

### Commands to run

```bash
# IaC files
find . -name "*.tf" -o -name "*.tfvars" -o -name "*.cfn.*" -o -name "cdk.json" -o -name "pulumi.*" -o -name "*.bicep" -o -name "*.ansible.*" | grep -v node_modules | head -20

# Config management
find . -name "*.env*" -o -name "config.*" -o -name "settings.*" | grep -v node_modules | grep -v .git | head -20

# Dockerfile analysis
find . -name "Dockerfile*" | grep -v node_modules | while read f; do echo "=== $f ==="; head -5 "$f"; echo "Lines: $(wc -l < "$f")"; done

# Database migrations
find . -type d -name "migrations" -o -name "migrate" | grep -v node_modules
find . -name "alembic.ini" -o -name "knexfile.*" -o -name "sequelize*" -o -name "*migrate*" | grep -v node_modules | head -10

# Secret management signals
grep -rn "vault\|aws.*secrets.*manager\|KMS\|SOPS\|sealed-secret\|external-secret" --include="*.yaml" --include="*.yml" --include="*.tf" --include="*.py" --include="*.ts" --include="*.js" | grep -v node_modules | head -10
```

### Rating guide

| Rating | Criteria |
|---|---|
| **Strong** | Full IaC, secrets in vault, multi-stage Docker builds, migration framework, env parity |
| **Acceptable** | Partial IaC, env-based config, Dockerized but not optimized, migrations present |
| **Concerning** | No IaC, secrets in env files, monolithic Dockerfiles, manual DB changes |
| **Critical** | Manually provisioned infra, hardcoded secrets, no containers, no migration strategy |
