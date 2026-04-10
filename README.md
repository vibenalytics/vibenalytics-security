# cc-vibeguard

Security audit & risk dashboard for Claude Code sessions.

![cc-vibeguard demo](assets/demo.gif)

Scans your local Claude Code transcripts and generates a visual security report - secrets leaked in tool outputs, destructive commands executed, permission bypass patterns, SSH remote access, agent oversight gaps, and more.

```
npx cc-vibeguard
```

Opens a self-contained HTML report in your browser. No data leaves your machine.

## What it analyzes

**Secret exposure** - Detects API keys, tokens, database URLs, private keys, AWS credentials, Ethereum keys, and seed phrases that appeared in tool results. Distinguishes real credentials from placeholders, local dev URLs, and false positives.

**Destructive commands** - Flags `rm -rf`, `DELETE FROM` without WHERE, `curl | sh`, force pushes, `sudo`, IAM escalation, terraform destroy, package publishing, and 30+ other risky patterns. Each finding is classified as critical/high/medium/low with context (local dev vs SSH remote).

**Permission discipline** - Tracks how often you use bypass mode vs default mode, broken down by hour and day. Identifies which projects have the highest bypass rates.

**SSH & remote access** - Enumerates hosts accessed, command types, and timeline of remote activity.

**Autonomous agents** - Counts subagent spawns, how many ran in bypass mode, and which models were used.

**Human overrides** - Measures denial rate, interrupts, and destructive command catches - how often you actually stopped the AI from doing something risky.

**User sentiment** - Detects frustration and satisfaction patterns in your prompts.

**Security score** - Weighted composite score (0-100) across five dimensions: secrets (30%), permissions (25%), remote access (20%), commands (15%), agent oversight (10%).

**Persona** - Assigns a behavioral persona based on your patterns. 25+ personas ranging from "Fort Knox" and "Zero Trust Human" to "Permission Anarchist" and "YOLO Deployer".

## Usage

```bash
npx cc-vibeguard
```

That's it. Scans `~/.claude/projects`, writes a self-contained HTML report to `~/Downloads/cc-vibeguard-report.html`, and opens it in your browser.

Requires Node.js 18+. Prebuilt binaries for macOS (ARM64, x64) and Linux (x64, ARM64).

## Report sections

| Section | What it shows |
|---------|--------------|
| Hero | Transcript count, project count, date range, total prompts |
| Persona | Behavioral archetype with key stats |
| Scores | Overall + per-dimension security scores with weights |
| Secret exposure | Secret types, most exposed keys, exposure by project |
| Destructive commands | Severity distribution, categories, critical findings, git safety |
| Permission discipline | Bypass %, mode distribution by hour/day, riskiest projects |
| SSH & remote access | Hosts, command count, daily timeline |
| Autonomous agents | Spawn count, bypass mode agents, models used |
| Human overrides | Denials, interrupts, destructive catches, most rejected tools |
| User sentiment | Negative/positive rates, top keywords, per-project breakdown |
| Prioritized risks | Actionable risk items + what's working well |

## How it works

1. Discovers all `.jsonl` transcript files in `~/.claude/projects/`
2. Parses each session: user prompts, tool calls, tool results, assistant responses
3. Runs security analysis across all parsed sessions
4. Generates a self-contained HTML dashboard with the data embedded
5. Opens the report in your browser

All analysis runs locally. No network requests. No telemetry.

## Built with

Rust CLI + prebuilt binaries distributed via npm optional dependencies.

## License

MIT
