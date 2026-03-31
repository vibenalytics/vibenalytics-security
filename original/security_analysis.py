#!/usr/bin/env python3
"""
Reconstructed security analysis for Claude Code transcript JSONL files.

This script is a best-effort rebuild of the missing analysis behind
`security-metrics.html` / `raw-metrics.html`.

What is grounded in repo evidence:
- Transcript parsing model and field names from `docs/transcript-format.md`
- Permission-mode and rejection handling from `planning_delegation_analysis.py`
- Metric families and labels from `raw-metrics.html` and `security-metrics.html`

What is heuristic:
- Secret regex coverage
- Sensitive-file heuristics
- Risky Bash severity/category rules
- Gauge scoring formulas

Outputs:
- `behavioral-research/security_report.md`
- `behavioral-research/security_report.json`
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


DEFAULT_PROJECTS_DIR = os.path.expanduser("~/.claude/projects")
BASE_DIR = os.path.dirname(__file__)
OUTPUT_MD = os.path.join(BASE_DIR, "security_report.md")
OUTPUT_JSON = os.path.join(BASE_DIR, "security_report.json")

REJECTED_PHRASES = [
    "the user doesn't want to proceed with this tool use",
    "the tool use was rejected",
    "the user denied this tool use",
    "user denied",
    "permission denied",
]

INTERRUPT_MARKERS = {
    "[Request interrupted by user]",
    "[Request interrupted by user for tool use]",
}

SECRET_PATTERNS = [
    ("secret_assignments", re.compile(r"\b[A-Z0-9_]*SECRET[A-Z0-9_]*\s*=\s*[^\s\"'`;]+")),
    ("key_assignments", re.compile(r"\b[A-Z0-9_]*KEY[A-Z0-9_]*\s*=\s*[^\s\"'`;]+")),
    ("postgres_urls", re.compile(r"\bpostgres(?:ql)?://[^\s\"'`]+", re.IGNORECASE)),
    ("anthropic_tokens", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]+\b")),
    ("bearer_tokens", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]+\b", re.IGNORECASE)),
    ("mysql_urls", re.compile(r"\bmysql://[^\s\"'`]+", re.IGNORECASE)),
]

SENSITIVE_PATH_RE = re.compile(
    r"(^|/)(\.env(?:\.[^/\s]+)?|docker-compose[^/\s]*\.ya?ml|secrets?[^/\s]*|"
    r"credentials?[^/\s]*|id_rsa|id_ed25519|\.npmrc|\.pypirc|\.netrc)$",
    re.IGNORECASE,
)

ENV_PATH_RE = re.compile(r"(^|/)\.env(?:\.[^/\s]+)?$", re.IGNORECASE)

PROD_HOST_HINTS = (
    "prod",
    "production",
    "live",
    "www",
    "vibenalytics",
    "genboard",
    "orb",
    "webgate",
)

LOW_RISK_PATTERNS = [
    ("npx execution", re.compile(r"\bnpx\b")),
]

MEDIUM_RISK_PATTERNS = [
    ("curl post", re.compile(r"\bcurl\b.*\s(-X\s+POST|--request\s+POST)\b", re.IGNORECASE)),
    ("docker rm", re.compile(r"\bdocker\s+(rm|compose\s+down)\b", re.IGNORECASE)),
    ("write redirect", re.compile(r"(?:^|\s)(?:tee|cat)\b.*[>]{1,2}\s*\S+")),
]

HIGH_RISK_PATTERNS = [
    ("push to main", re.compile(r"\bgit\s+push(?:\s+\S+)?\s+(?:main|master)\b")),
    ("rm -rf", re.compile(r"\brm\s+-[^\n]*r[^\n]*f\b")),
    ("sudo", re.compile(r"\bsudo\b")),
    ("db reset", re.compile(r"\b(drop\s+database|dropdb|truncate\s+table)\b", re.IGNORECASE)),
]

CRITICAL_RISK_PATTERNS = [
    ("delete without where", re.compile(r"\bDELETE\s+FROM\s+[A-Za-z0-9_.$]+\b(?!.*\bWHERE\b)", re.IGNORECASE)),
    ("pipe to shell", re.compile(r"\bcurl\b[^\n|]*\|\s*(?:sh|bash)\b", re.IGNORECASE)),
]


@dataclass
class ToolCall:
    timestamp: str | None
    tool_id: str
    name: str
    input: dict[str, Any]
    permission_mode: str | None
    project: str
    session_id: str


def discover_parent_files(projects_dir: str) -> list[str]:
    pattern = os.path.join(projects_dir, "*", "*.jsonl")
    files = glob.glob(pattern)
    return sorted(f for f in files if "/subagents/" not in f)


def extract_project_name(filepath: str) -> str:
    parent = os.path.basename(os.path.dirname(filepath))
    name = parent.lstrip("-").replace("-", "/")
    parts = [p for p in name.split("/") if p not in ("Users", "martinvanco", "Documents")]
    return "/".join(parts[-3:]) if parts else parent


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(normalize_text(item) for item in value)
    if isinstance(value, dict):
        if value.get("type") == "text":
            return str(value.get("text", ""))
        return " ".join(normalize_text(v) for v in value.values())
    return str(value)


def iter_human_texts(msg: dict[str, Any]) -> list[str]:
    content = msg.get("message", {}).get("content", "")
    texts: list[str] = []
    if isinstance(content, str):
        texts.append(content)
    elif isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                texts.append(str(item.get("text", "")))
    return [t for t in texts if t]


def parse_session(filepath: str) -> dict[str, Any] | None:
    session_id = os.path.splitext(os.path.basename(filepath))[0]
    project = extract_project_name(filepath)

    messages: list[dict[str, Any]] = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                messages.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not messages:
        return None

    session = {
        "session_id": session_id,
        "project": project,
        "filepath": filepath,
        "messages": messages,
        "start_time": None,
        "tool_calls": [],
        "user_prompts": [],
        "tool_results": [],
        "permission_modes": [],
        "interrupts": [],
        "api_errors": 0,
        "compactions": 0,
    }

    current_mode: str | None = None
    timestamps: list[str] = []
    last_tool_uses: dict[str, ToolCall] = {}

    for msg in messages:
        ts = msg.get("timestamp")
        if ts:
            timestamps.append(ts)

        msg_type = msg.get("type")
        if msg_type == "system":
            subtype = msg.get("subtype")
            if subtype == "api_error":
                session["api_errors"] += 1
            elif subtype == "compact_boundary":
                session["compactions"] += 1
            continue

        if msg_type == "user":
            permission_mode = msg.get("permissionMode")
            if permission_mode:
                current_mode = permission_mode
                session["permission_modes"].append((ts, permission_mode))

            content = msg.get("message", {}).get("content", "")
            if isinstance(content, str):
                session["user_prompts"].append((ts, content, current_mode))
                if content in INTERRUPT_MARKERS:
                    session["interrupts"].append((ts, content))
            elif isinstance(content, list):
                for item in content:
                    if not isinstance(item, dict) or item.get("type") != "tool_result":
                        continue
                    result_text = normalize_text(item.get("content", ""))
                    tool_use_id = item.get("tool_use_id", "")
                    source_call = last_tool_uses.get(tool_use_id)
                    session["tool_results"].append(
                        {
                            "timestamp": ts,
                            "tool_use_id": tool_use_id,
                            "tool_name": source_call.name if source_call else "unknown",
                            "project": project,
                            "permission_mode": source_call.permission_mode if source_call else current_mode,
                            "text": result_text,
                            "is_error": bool(item.get("is_error")),
                            "toolUseResult": msg.get("toolUseResult"),
                        }
                    )
            continue

        if msg_type == "assistant":
            content = msg.get("message", {}).get("content", [])
            if not isinstance(content, list):
                continue
            for item in content:
                if not isinstance(item, dict) or item.get("type") != "tool_use":
                    continue
                call = ToolCall(
                    timestamp=ts,
                    tool_id=str(item.get("id", "")),
                    name=str(item.get("name", "")),
                    input=item.get("input", {}) if isinstance(item.get("input", {}), dict) else {},
                    permission_mode=current_mode,
                    project=project,
                    session_id=session_id,
                )
                session["tool_calls"].append(call)
                last_tool_uses[call.tool_id] = call

    if timestamps:
        session["start_time"] = min(timestamps)

    return session


def extract_path_from_tool(call: ToolCall) -> str:
    for key in ("file_path", "path", "filepath", "target_file"):
        value = call.input.get(key)
        if isinstance(value, str):
            return value
    return ""


def extract_command(call: ToolCall) -> str:
    for key in ("command", "cmd"):
        value = call.input.get(key)
        if isinstance(value, str):
            return value
    return ""


def is_sensitive_path(path: str) -> bool:
    return bool(path and SENSITIVE_PATH_RE.search(path))


def is_env_path(path: str) -> bool:
    return bool(path and ENV_PATH_RE.search(path))


def count_secret_matches(text: str) -> Counter:
    counts = Counter()
    if not text:
        return counts
    for name, pattern in SECRET_PATTERNS:
        counts[name] += len(pattern.findall(text))
    return counts


def classify_host(host: str) -> str:
    if not host:
        return "unknown"
    return "production" if any(hint in host.lower() for hint in PROD_HOST_HINTS) else "other"


def parse_ssh_target(command: str) -> str:
    m = re.search(r"\bssh\s+(?:-[A-Za-z]\s+\S+\s+)*([A-Za-z0-9_.@-]+)", command)
    return m.group(1) if m else ""


def classify_bash_risk(command: str) -> tuple[str | None, str | None]:
    for category, pattern in CRITICAL_RISK_PATTERNS:
        if pattern.search(command):
            return "critical", category
    for category, pattern in HIGH_RISK_PATTERNS:
        if pattern.search(command):
            return "high", category
    for category, pattern in MEDIUM_RISK_PATTERNS:
        if pattern.search(command):
            return "medium", category
    for category, pattern in LOW_RISK_PATTERNS:
        if pattern.search(command):
            return "low", category
    return None, None


def hour_from_ts(ts: str | None) -> int | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).hour
    except ValueError:
        return None


def score_secrets(total_secrets: int) -> int:
    return max(0, min(100, round(100 * (1 - total_secrets / 600))))


def score_remote(prod_hits: int) -> int:
    return max(0, min(100, round(100 * (1 - prod_hits / 112))))


def score_permissions(bypass_pct: float) -> int:
    return max(0, min(100, round(100 * (1 - bypass_pct / 70))))


def score_commands(severity_counts: Counter) -> int:
    risk_points = (
        severity_counts["critical"] * 25
        + severity_counts["high"] * 5
        + severity_counts["medium"] * 1
        + severity_counts["low"] * 0.25
    )
    return max(0, min(100, round(100 * (1 - risk_points / 1250))))


def score_agents(bypass_agents: int) -> int:
    return max(0, min(100, round(100 * (1 - bypass_agents / 560))))


def analyze(projects_dir: str) -> dict[str, Any]:
    files = discover_parent_files(projects_dir)
    sessions = [s for fp in files if (s := parse_session(fp))]
    sessions.sort(key=lambda s: s["start_time"] or "")

    secret_counts = Counter()
    secrets_by_project = Counter()
    sensitive_reads = 0
    env_paths = set()
    env_writes = 0
    sensitive_read_paths = Counter()

    ssh_hosts = Counter()
    ssh_days = set()
    prod_hits = 0

    severity_counts = Counter()
    category_counts = Counter()
    risky_commands: list[dict[str, Any]] = []

    permission_mode_counts = Counter()
    bypass_by_hour = Counter()
    prompts_by_project = Counter()
    bypass_by_project = Counter()

    agent_total = 0
    agent_bypass = 0
    agent_by_project = Counter()

    denials = 0
    denied_tools = Counter()
    interrupts = 0

    compactions = 0
    api_errors = 0

    for session in sessions:
        project = session["project"]
        compactions += session["compactions"]
        api_errors += session["api_errors"]
        interrupts += len(session["interrupts"])

        for ts, prompt, mode in session["user_prompts"]:
            permission_mode_counts[mode or "unknown"] += 1
            prompts_by_project[project] += 1
            if mode == "bypassPermissions":
                bypass_by_project[project] += 1
                hour = hour_from_ts(ts)
                if hour is not None:
                    bypass_by_hour[hour] += 1

            prompt_secret_counts = count_secret_matches(prompt)
            if prompt_secret_counts:
                secret_counts.update(prompt_secret_counts)
                secrets_by_project[project] += sum(prompt_secret_counts.values())

        for call in session["tool_calls"]:
            if call.name == "Read":
                path = extract_path_from_tool(call)
                if is_sensitive_path(path):
                    sensitive_reads += 1
                    sensitive_read_paths[path] += 1
                    if is_env_path(path):
                        env_paths.add(path)
            elif call.name in {"Write", "Edit", "MultiEdit"}:
                path = extract_path_from_tool(call)
                if is_env_path(path):
                    env_writes += 1
                    env_paths.add(path)
            elif call.name == "Bash":
                command = extract_command(call)
                if re.search(r"\bssh\b", command):
                    host = parse_ssh_target(command) or "unknown"
                    ssh_hosts[host] += 1
                    if classify_host(host) == "production":
                        prod_hits += 1
                    if call.timestamp:
                        ssh_days.add(call.timestamp[:10])

                severity, category = classify_bash_risk(command)
                if severity:
                    severity_counts[severity] += 1
                    if category:
                        category_counts[category] += 1
                    risky_commands.append(
                        {
                            "timestamp": call.timestamp,
                            "project": project,
                            "command": command,
                            "severity": severity,
                            "category": category,
                            "permission_mode": call.permission_mode,
                        }
                    )
            elif call.name == "Agent":
                agent_total += 1
                agent_by_project[project] += 1
                if call.permission_mode == "bypassPermissions":
                    agent_bypass += 1

        for result in session["tool_results"]:
            text = result["text"]
            result_secret_counts = count_secret_matches(text)
            if result_secret_counts:
                secret_counts.update(result_secret_counts)
                secrets_by_project[project] += sum(result_secret_counts.values())

            rejected = result["is_error"] or any(p in text.lower() for p in REJECTED_PHRASES)
            if rejected:
                denials += 1
                denied_tools[result["tool_name"]] += 1

    total_prompts = sum(permission_mode_counts.values())
    bypass_pct = (permission_mode_counts["bypassPermissions"] / total_prompts * 100) if total_prompts else 0.0
    total_secrets = sum(secret_counts.values())

    scores = {
        "secrets": score_secrets(total_secrets),
        "remote": score_remote(prod_hits),
        "permissions": score_permissions(bypass_pct),
        "commands": score_commands(severity_counts),
        "agents": score_agents(agent_bypass),
    }
    scores["overall"] = round(
        scores["secrets"] * 0.30
        + scores["permissions"] * 0.25
        + scores["remote"] * 0.20
        + scores["commands"] * 0.15
        + scores["agents"] * 0.10
    )

    start_date = sessions[0]["start_time"][:10] if sessions and sessions[0]["start_time"] else None
    end_date = sessions[-1]["start_time"][:10] if sessions and sessions[-1]["start_time"] else None

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source": {
            "projects_dir": projects_dir,
            "transcript_files": len(files),
            "sessions": len(sessions),
            "projects": len({s["project"] for s in sessions}),
            "date_range": {"start": start_date, "end": end_date},
        },
        "scores": scores,
        "secrets": {
            "total": total_secrets,
            "by_type": dict(secret_counts),
            "sensitive_reads": sensitive_reads,
            "env_writes": env_writes,
            "env_paths": sorted(env_paths),
            "project_totals": dict(secrets_by_project.most_common()),
            "sensitive_read_paths": dict(sensitive_read_paths.most_common(20)),
        },
        "remote_access": {
            "ssh_total": sum(ssh_hosts.values()),
            "production_hits": prod_hits,
            "unique_hosts": len(ssh_hosts),
            "active_days": len(ssh_days),
            "hosts": dict(ssh_hosts.most_common()),
        },
        "risky_commands": {
            "total": sum(severity_counts.values()),
            "severity_counts": dict(severity_counts),
            "category_counts": dict(category_counts),
            "examples": risky_commands[:25],
        },
        "permissions": {
            "prompt_total": total_prompts,
            "mode_counts": dict(permission_mode_counts),
            "bypass_pct": round(bypass_pct, 2),
            "bypass_by_hour": dict(sorted(bypass_by_hour.items())),
            "bypass_by_project": {
                project: {
                    "bypass_prompts": bypass_by_project[project],
                    "total_prompts": prompts_by_project[project],
                    "bypass_pct": round(
                        bypass_by_project[project] / prompts_by_project[project] * 100, 2
                    ) if prompts_by_project[project] else 0.0,
                }
                for project in sorted(prompts_by_project)
            },
        },
        "agents": {
            "total": agent_total,
            "bypass": agent_bypass,
            "bypass_pct": round(agent_bypass / agent_total * 100, 2) if agent_total else 0.0,
            "by_project": dict(agent_by_project.most_common()),
        },
        "human_overrides": {
            "denials": denials,
            "interrupts": interrupts,
            "denied_tools": dict(denied_tools.most_common()),
            "override_rate": round((denials + interrupts) / total_prompts * 100, 2) if total_prompts else 0.0,
        },
        "stability": {
            "compactions": compactions,
            "api_errors": api_errors,
        },
    }


def render_markdown(data: dict[str, Any]) -> str:
    lines: list[str] = []
    src = data["source"]
    scores = data["scores"]
    secrets = data["secrets"]
    remote = data["remote_access"]
    risky = data["risky_commands"]
    perms = data["permissions"]
    agents = data["agents"]
    overrides = data["human_overrides"]
    stability = data["stability"]

    lines.append("# Security Analysis Report")
    lines.append("")
    lines.append(f"Generated: {data['generated_at']}")
    lines.append(f"Transcript files: {src['transcript_files']}")
    lines.append(f"Sessions: {src['sessions']}")
    lines.append(f"Projects: {src['projects']}")
    lines.append(f"Date range: {src['date_range']['start']} to {src['date_range']['end']}")
    lines.append("")
    lines.append("## Scores")
    lines.append("")
    lines.append(f"- Overall: {scores['overall']}")
    lines.append(f"- Secrets: {scores['secrets']}")
    lines.append(f"- Remote access: {scores['remote']}")
    lines.append(f"- Permissions: {scores['permissions']}")
    lines.append(f"- Commands: {scores['commands']}")
    lines.append(f"- Agent oversight: {scores['agents']}")
    lines.append("")
    lines.append("## Secrets")
    lines.append("")
    lines.append(f"- Total matches: {secrets['total']}")
    lines.append(f"- Sensitive reads: {secrets['sensitive_reads']}")
    lines.append(f"- .env writes: {secrets['env_writes']}")
    lines.append(f"- Unique .env paths: {len(secrets['env_paths'])}")
    lines.append("")
    lines.append("| Type | Count |")
    lines.append("|---|---:|")
    for key, value in sorted(secrets["by_type"].items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"| {key} | {value} |")
    lines.append("")
    lines.append("## Remote Access")
    lines.append("")
    lines.append(f"- SSH commands: {remote['ssh_total']}")
    lines.append(f"- Production hits: {remote['production_hits']}")
    lines.append(f"- Unique hosts: {remote['unique_hosts']}")
    lines.append(f"- Active days: {remote['active_days']}")
    lines.append("")
    lines.append("| Host | Count |")
    lines.append("|---|---:|")
    for host, count in remote["hosts"].items():
        lines.append(f"| {host} | {count} |")
    lines.append("")
    lines.append("## Risky Commands")
    lines.append("")
    lines.append(f"- Total flagged Bash commands: {risky['total']}")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    for severity in ("critical", "high", "medium", "low"):
        lines.append(f"| {severity} | {risky['severity_counts'].get(severity, 0)} |")
    lines.append("")
    lines.append("| Category | Count |")
    lines.append("|---|---:|")
    for category, count in sorted(risky["category_counts"].items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"| {category} | {count} |")
    lines.append("")
    lines.append("## Permissions")
    lines.append("")
    lines.append(f"- Prompt total: {perms['prompt_total']}")
    lines.append(f"- Bypass rate: {perms['bypass_pct']}%")
    lines.append("")
    lines.append("| Mode | Count |")
    lines.append("|---|---:|")
    for mode, count in sorted(perms["mode_counts"].items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"| {mode} | {count} |")
    lines.append("")
    lines.append("## Agents")
    lines.append("")
    lines.append(f"- Total agents: {agents['total']}")
    lines.append(f"- Agents in bypass mode: {agents['bypass']} ({agents['bypass_pct']}%)")
    lines.append("")
    lines.append("## Human Overrides")
    lines.append("")
    lines.append(f"- Denials: {overrides['denials']}")
    lines.append(f"- Interrupts: {overrides['interrupts']}")
    lines.append(f"- Override rate: {overrides['override_rate']}%")
    lines.append("")
    lines.append("| Tool | Denials |")
    lines.append("|---|---:|")
    for tool, count in overrides["denied_tools"].items():
        lines.append(f"| {tool} | {count} |")
    lines.append("")
    lines.append("## Stability")
    lines.append("")
    lines.append(f"- Context compactions: {stability['compactions']}")
    lines.append(f"- API errors: {stability['api_errors']}")
    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- Secret detection is regex-based and intentionally broad.")
    lines.append("- Risk scoring is heuristic and calibrated to match the metric families in the existing HTML reports.")
    lines.append("- Permission mode attached to a tool call is inferred from the latest prior human prompt in the session.")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Reconstructed security analysis for Claude Code transcripts.")
    parser.add_argument("--projects-dir", default=DEFAULT_PROJECTS_DIR, help="Directory containing Claude transcript projects")
    parser.add_argument("--json-out", default=OUTPUT_JSON, help="Path for JSON output")
    parser.add_argument("--md-out", default=OUTPUT_MD, help="Path for Markdown output")
    args = parser.parse_args()

    data = analyze(args.projects_dir)

    with open(args.json_out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")

    with open(args.md_out, "w", encoding="utf-8") as f:
        f.write(render_markdown(data))

    print(f"Wrote {args.json_out}")
    print(f"Wrote {args.md_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
