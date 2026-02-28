# Technical Due Diligence Report — Template

This template defines the structure of the final deliverable.
When generating the report, replace all `[PLACEHOLDER]` values with actual findings.

---

## Report Metadata

```
Title: Technical Due Diligence Report — [PROJECT/COMPANY NAME]
Date: [DATE]
Prepared by: Claude (AI-assisted technical analysis)
Scope: [BRIEF DESCRIPTION OF WHAT WAS ANALYZED]
Classification: [CONFIDENTIAL / INTERNAL / etc. — ask the user]
```

---

## Section 1: Executive Summary

**Length**: 1 page maximum. This is the most important section — many readers will stop here.

**Structure**:

### Overall Assessment

[One paragraph. Start with the overall verdict: is this codebase in good shape for its stage?
Contextualize — a seed-stage startup will look different from a Series C company.
End with a clear recommendation: proceed / proceed with conditions / significant concerns.]

### Key Strengths

[3-5 bullet points. Each strength should be specific and evidence-backed.
Example: "Well-structured API layer with OpenAPI specs and contract tests across all 4 services"]

### Critical Risks

[3-5 bullet points. Each risk should include severity and potential business impact.
Example: "No automated testing (0 test files found across 45k LOC) — high regression risk during scaling"]

### Scoring Summary

| Dimension | Rating | Confidence |
|---|---|---|
| Architecture & Design | [Rating] | [High/Medium/Low] |
| Code Quality | [Rating] | [High/Medium/Low] |
| Dependencies | [Rating] | [High/Medium/Low] |
| Security | [Rating] | [High/Medium/Low] |
| Testing | [Rating] | [High/Medium/Low] |
| CI/CD | [Rating] | [High/Medium/Low] |
| Documentation | [Rating] | [High/Medium/Low] |
| Git Health | [Rating] | [High/Medium/Low] |
| Performance | [Rating] | [High/Medium/Low] |
| Infrastructure | [Rating] | [High/Medium/Low] |

Confidence reflects how thoroughly the dimension could be assessed given the available information.

---

## Section 2: Scope & Methodology

### What Was Analyzed

[List all repositories/services analyzed with basic stats:
- Repo name, primary language(s), approximate LOC, number of contributors
- Date range of git history examined
- Layout classification (mono-repo, multi-repo, single)]

### What Was NOT Analyzed

[Be explicit about limitations:
- Deployed infrastructure (we only analyzed code)
- Runtime behavior / production metrics
- Third-party integrations that couldn't be tested
- Any repos/services that were excluded and why]

### Methodology

[Brief description:
- Static analysis of source code, configuration, and git history
- No dynamic testing or penetration testing was performed
- Findings rated on a 4-point scale: Critical / Concerning / Acceptable / Strong
- Evidence-based: every finding references specific files, metrics, or patterns]

---

## Section 3: Scoring Matrix

For multi-repo or mono-repo with multiple services, present a matrix:

| Dimension | [Service A] | [Service B] | [Service C] | Overall |
|---|---|---|---|---|
| Architecture | [Rating] | [Rating] | [Rating] | [Rating] |
| Code Quality | [Rating] | [Rating] | [Rating] | [Rating] |
| Dependencies | [Rating] | [Rating] | [Rating] | [Rating] |
| Security | [Rating] | [Rating] | [Rating] | [Rating] |
| Testing | [Rating] | [Rating] | [Rating] | [Rating] |
| CI/CD | [Rating] | [Rating] | [Rating] | [Rating] |
| Documentation | [Rating] | [Rating] | [Rating] | [Rating] |
| Git Health | [Rating] | [Rating] | [Rating] | [Rating] |
| Performance | [Rating] | [Rating] | [Rating] | [Rating] |
| Infrastructure | [Rating] | [Rating] | [Rating] | [Rating] |

For single-repo analysis, use a simpler vertical format.

---

## Section 4: Detailed Findings

Repeat this structure for each dimension:

### 4.N — [Dimension Name]

**Rating**: [Critical / Concerning / Acceptable / Strong]

#### Summary

[2-3 paragraph assessment. What's the overall picture? How does this compare to
industry norms for a project of this size/stage?]

#### Evidence

[Specific findings with file references:
- "The project uses ESLint with a strict configuration (`.eslintrc.json`, line 14) that enforces..."
- "We identified 12 functions exceeding 100 lines in `src/services/` (see Appendix B for full list)"
- "The CI pipeline (`/.github/workflows/ci.yml`) runs linting and unit tests on every PR"]

#### Per-Repository Breakdown

[If multi-repo, note differences:
- "Service A has 85% test coverage; Service B has 12%"
- "Only the API gateway implements rate limiting; backend services do not"]

#### Risks Identified

| ID | Risk | Severity | Affected | Remediation Effort |
|---|---|---|---|---|
| [DIM]-R1 | [Description] | High/Med/Low | [Repos] | [Hours/Days/Weeks] |
| [DIM]-R2 | [Description] | High/Med/Low | [Repos] | [Hours/Days/Weeks] |

#### Recommendations

[Ordered by priority:
1. [Most impactful recommendation with concrete action]
2. [Next recommendation]
3. ...]

---

## Section 5: Risk Register

Consolidated view of all risks from all dimensions:

| ID | Dimension | Risk Description | Severity | Affected Repos | Business Impact | Remediation Effort | Priority |
|---|---|---|---|---|---|---|---|
| ARCH-R1 | Architecture | [desc] | High | [repos] | [impact] | [effort] | P1 |
| SEC-R1 | Security | [desc] | Critical | [repos] | [impact] | [effort] | P0 |
| ... | ... | ... | ... | ... | ... | ... | ... |

Priority assignments:
- **P0**: Must fix before any transaction / immediate action required
- **P1**: Fix within 30 days / condition of investment
- **P2**: Fix within 90 days / part of technical roadmap
- **P3**: Nice to have / long-term improvement

---

## Section 6: Recommendations Roadmap

### Immediate (Pre-Close / Week 1-2)

[Actions that must happen before or immediately after a transaction:
- Critical security fixes
- License compliance issues
- Anything that could block business operations]

### Short-Term (Month 1-3)

[High-impact improvements that establish a solid foundation:
- CI/CD pipeline hardening
- Test coverage for critical paths
- Dependency updates for CVE remediation]

### Medium-Term (Month 3-6)

[Structural improvements:
- Architecture refactoring
- Documentation catch-up
- Monitoring and observability setup]

### Long-Term (Month 6-12)

[Strategic technical investments:
- Platform migrations
- Major dependency upgrades
- Performance optimization at scale]

### Estimated Total Remediation Investment

[Rough estimate of engineering effort to address all P0-P2 items.
Express in person-months or FTE-weeks. Caveat appropriately — this is a static analysis estimate.]

---

## Section 7: Appendices

### Appendix A: Repository Statistics

[Raw metrics per repo: LOC, file counts, language breakdown, contributor counts, commit counts]

### Appendix B: Detailed File References

[For findings that reference many files, list them here instead of cluttering the main text]

### Appendix C: Tool Outputs

[Raw outputs from any automated tools that were run — npm audit, pip-audit, etc.]

### Appendix D: Glossary

[For non-technical readers: brief definitions of technical terms used in the report]
