# CodeAtlas

Technical due diligence for code repositories, powered by [Claude Code](https://docs.anthropic.com/en/docs/agents-and-tools/claude-code/overview).

Analyzes architecture, code quality, security, dependencies, testing, CI/CD, documentation, git health, performance, and infrastructure — producing a structured report backed by concrete evidence.

## Install

```bash
bash scripts/install.sh
```

## Usage

```
/codeatlas:scan <path>       # Discover repositories
/codeatlas:analyze <path>    # Full technical due diligence
/codeatlas:report [dir]      # Generate report from existing analysis
```

## License

[MIT](LICENSE)
