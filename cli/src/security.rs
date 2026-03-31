use crate::transcripts::{ParsedSession, ToolCall, ToolResult};
use regex::Regex;
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

const REJECTED_PHRASES: &[&str] = &[
    "the user doesn't want to proceed with this tool use",
    "the tool use was rejected",
    "the user denied this tool use",
    "user denied",
];

#[derive(Debug, Serialize)]
pub struct Report {
    pub hero: Hero,
    pub scores: Scores,
    pub secret_exposure: SecretExposure,
    pub ssh_remote_access: SshRemoteAccess,
    pub destructive_commands: DestructiveCommands,
    pub permission_discipline: PermissionDiscipline,
    pub autonomous_agents: AutonomousAgents,
    pub human_overrides: HumanOverrides,
    pub prioritized_risks: PrioritizedRisks,
    pub stability: Stability,
}

#[derive(Debug, Serialize)]
pub struct Hero {
    pub report_title: String,
    pub transcript_count: usize,
    pub project_count: usize,
    pub total_entries: u32,
    pub date_range: DateRange,
    pub include_subagents: bool,
}

#[derive(Debug, Serialize)]
pub struct DateRange {
    pub start: Option<String>,
    pub end: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Scores {
    pub overall: u32,
    pub secrets: u32,
    pub remote_access: u32,
    pub permissions: u32,
    pub commands: u32,
    pub agent_oversight: u32,
    pub weights: ScoreWeights,
}

#[derive(Debug, Serialize)]
pub struct ScoreWeights {
    pub secrets: u32,
    pub permissions: u32,
    pub remote_access: u32,
    pub commands: u32,
    pub agent_oversight: u32,
}

#[derive(Debug, Serialize)]
pub struct SecretExposure {
    pub total_secrets: u32,
    pub sensitive_reads: u32,
    pub env_writes: u32,
    pub env_paths: usize,
    pub secret_types: Vec<LabeledCount>,
    pub most_exposed: Vec<SecretNameCount>,
    pub exposure_by_project: Vec<ProjectExposure>,
}

#[derive(Debug, Serialize)]
pub struct SecretNameCount {
    pub secret: String,
    pub hits: u32,
    pub projects: usize,
}

#[derive(Debug, Serialize)]
pub struct ProjectExposure {
    pub project: String,
    pub reads: u32,
    pub secrets: u32,
    pub writes: u32,
    pub total: u32,
}

#[derive(Debug, Serialize)]
pub struct SshRemoteAccess {
    pub ssh_commands: u32,
    pub unique_hosts: usize,
    pub active_days: usize,
    pub remote_command_ssh: u32,
    pub interactive_ssh: u32,
    pub hosts_accessed: Vec<LabeledCount>,
    pub timeline: Vec<SshDay>,
}

#[derive(Debug, Serialize)]
pub struct SshDay {
    pub date: String,
    pub commands: u32,
    pub top_host: String,
    pub activity_summary: String,
}

#[derive(Debug, Serialize)]
pub struct DestructiveCommands {
    pub total_flagged: u32,
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub severity_distribution: Vec<LabeledCount>,
    pub by_category: Vec<LabeledCount>,
    pub critical_findings: Vec<CommandFinding>,
    pub git_safety: GitSafety,
}

#[derive(Debug, Serialize)]
pub struct CommandFinding {
    pub kind: String,
    pub count: u32,
    pub risk: String,
}

#[derive(Debug, Serialize)]
pub struct GitSafety {
    pub push_to_main: u32,
    pub force_push: u32,
    pub reset_hard: u32,
    pub no_verify: u32,
}

#[derive(Debug, Serialize)]
pub struct PermissionDiscipline {
    pub prompt_total: u32,
    pub bypass_pct: f64,
    pub mode_distribution: Vec<LabeledCount>,
    pub bypass_by_hour: Vec<HourCount>,
    pub highest_bypass_projects: Vec<ProjectRiskRow>,
}

#[derive(Debug, Serialize)]
pub struct HourCount {
    pub hour: u8,
    pub bypass_prompts: u32,
}

#[derive(Debug, Serialize)]
pub struct ProjectRiskRow {
    pub project: String,
    pub prompts: u32,
    pub bypass_prompts: u32,
    pub bypass_pct: f64,
    pub risk: String,
}

#[derive(Debug, Serialize)]
pub struct AutonomousAgents {
    pub agents_spawned: u32,
    pub in_bypass_mode: u32,
    pub from_top_project: TopProjectCount,
    pub rejections: u32,
}

#[derive(Debug, Serialize)]
pub struct TopProjectCount {
    pub project: String,
    pub count: u32,
}

#[derive(Debug, Serialize)]
pub struct HumanOverrides {
    pub denials: u32,
    pub interrupts: u32,
    pub destructive_catches: u32,
    pub override_rate: f64,
    pub most_rejected_tools: Vec<LabeledCount>,
}

#[derive(Debug, Serialize)]
pub struct PrioritizedRisks {
    pub items: Vec<RiskItem>,
    pub whats_working_well: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RiskItem {
    pub priority: String,
    pub title: String,
    pub description: String,
}

#[derive(Debug, Serialize)]
pub struct Stability {
    pub api_errors: u32,
    pub compactions: u32,
}

#[derive(Debug, Serialize, Clone)]
pub struct LabeledCount {
    pub label: String,
    pub count: u32,
}

#[derive(Debug)]
struct Rules {
    secret_assignment_line: Regex,
    key_assignment_line: Regex,
    token_assignment_line: Regex,
    assignment_name: Regex,
    postgres_urls: Regex,
    anthropic_tokens: Regex,
    bearer_tokens: Regex,
    mysql_urls: Regex,
    private_key_block: Regex,
    sensitive_path: Regex,
    env_path: Regex,
    ssh_direct: Regex,
    ssh_any: Regex,
    delete_from: Regex,
    pipe_shell: Regex,
    push_main: Regex,
    rm_rf: Regex,
    sudo: Regex,
    db_reset: Regex,
    curl_post: Regex,
    docker_rm: Regex,
    npx_exec: Regex,
    force_push: Regex,
    reset_hard: Regex,
    no_verify: Regex,
}

impl Rules {
    fn new() -> Self {
        Self {
            secret_assignment_line: Regex::new(r#"\b[A-Z0-9_]*SECRET[A-Z0-9_]*\s*=\s*[^\s"'`;]+"#).unwrap(),
            key_assignment_line: Regex::new(r#"\b[A-Z0-9_]*KEY[A-Z0-9_]*\s*=\s*[^\s"'`;]+"#).unwrap(),
            token_assignment_line: Regex::new(r#"\b[A-Z0-9_]*TOKEN[A-Z0-9_]*\s*=\s*[^\s"'`;]+"#).unwrap(),
            assignment_name: Regex::new(r#"([A-Z0-9_]+)\s*="#).unwrap(),
            postgres_urls: Regex::new(r#"\bpostgres(?:ql)?://[^\s"'`]+"#).unwrap(),
            anthropic_tokens: Regex::new(r"\bsk-ant-[A-Za-z0-9\-_]+\b").unwrap(),
            bearer_tokens: Regex::new(r"\bBearer\s+[A-Za-z0-9._\-]+\b").unwrap(),
            mysql_urls: Regex::new(r#"\bmysql://[^\s"'`]+"#).unwrap(),
            private_key_block: Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap(),
            sensitive_path: Regex::new(r"(^|/)(\.env(?:\.[^/\s]+)?|docker-compose[^/\s]*\.ya?ml|secrets?[^/\s]*|credentials?[^/\s]*|id_rsa|id_ed25519)$").unwrap(),
            env_path: Regex::new(r"(^|/)\.env(?:\.[^/\s]+)?$").unwrap(),
            ssh_direct: Regex::new(r#"^\s*ssh(?:\s+-[A-Za-z0-9]+(?:\s+\S+)*)*\s+\S+\s+["']?.+["']?\s*$"#).unwrap(),
            ssh_any: Regex::new(r#"^\s*ssh\b"#).unwrap(),
            delete_from: Regex::new(r"\bDELETE\s+FROM\s+[A-Za-z0-9_.$]+\b").unwrap(),
            pipe_shell: Regex::new(r"\bcurl\b[^\n|]*\|\s*(?:sh|bash)\b").unwrap(),
            push_main: Regex::new(r"\bgit\s+push(?:\s+\S+)?\s+(?:main|master)\b").unwrap(),
            rm_rf: Regex::new(r"\brm\s+-[^\n]*r[^\n]*f\b").unwrap(),
            sudo: Regex::new(r"\bsudo\b").unwrap(),
            db_reset: Regex::new(r"\b(dropdb|drop\s+database|truncate\s+table)\b").unwrap(),
            curl_post: Regex::new(r"\bcurl\b.*\b(-X\s+POST|--request\s+POST)\b").unwrap(),
            docker_rm: Regex::new(r"\bdocker\s+(rm|compose\s+down)\b").unwrap(),
            npx_exec: Regex::new(r"\bnpx\b").unwrap(),
            force_push: Regex::new(r"\bgit\s+push\b.*\s--force(?:-with-lease)?\b").unwrap(),
            reset_hard: Regex::new(r"\bgit\s+reset\s+--hard\b").unwrap(),
            no_verify: Regex::new(r"\bgit\b.*\s--no-verify\b").unwrap(),
        }
    }
}

#[derive(Default)]
struct SecretTally {
    by_type: HashMap<String, u32>,
    by_name: HashMap<String, u32>,
    name_projects: HashMap<String, HashSet<String>>,
    by_project: HashMap<String, u32>,
}

#[derive(Default)]
struct SensitiveProject {
    reads: u32,
    secrets: u32,
    writes: u32,
}

#[derive(Default)]
struct SshDayAccum {
    count: u32,
    hosts: HashMap<String, u32>,
    activities: HashSet<String>,
}

#[derive(Default)]
struct RiskStats {
    severity: HashMap<String, u32>,
    category: HashMap<String, u32>,
    finding_counts: HashMap<String, u32>,
    finding_risk: HashMap<String, String>,
    destructive_catches: u32,
    push_main: u32,
    force_push: u32,
    reset_hard: u32,
    no_verify: u32,
}

fn inc(map: &mut HashMap<String, u32>, key: &str, delta: u32) {
    *map.entry(key.to_string()).or_insert(0) += delta;
}

fn sorted_counts(map: HashMap<String, u32>, limit: usize) -> Vec<LabeledCount> {
    let mut items: Vec<LabeledCount> = map
        .into_iter()
        .map(|(label, count)| LabeledCount { label, count })
        .collect();
    items.sort_by(|a, b| b.count.cmp(&a.count).then(a.label.cmp(&b.label)));
    items.truncate(limit);
    items
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn classify_host_activity(command: &str) -> String {
    let lc = command.to_ascii_lowercase();
    if lc.contains("wp ") || lc.contains("wp-cli") || lc.contains("wordpress") {
        "WordPress / WP-CLI".to_string()
    } else if lc.contains("docker") || lc.contains("psql") || lc.contains("jwt") {
        "Docker / psql / JWT".to_string()
    } else if lc.contains("cargo") || lc.contains("rustc") || lc.contains("deploy") {
        "Rust build / deploy".to_string()
    } else if lc.contains("uptime") || lc.contains("kuma") || lc.contains("db") {
        "Uptime / DB activity".to_string()
    } else if lc.contains("permission denied") {
        "Permission denied".to_string()
    } else {
        "Remote execution".to_string()
    }
}

fn parse_ssh_host(command: &str) -> Option<String> {
    let takes_arg = ["-p", "-i", "-l", "-o", "-J", "-F", "-E", "-S", "-b", "-c", "-D", "-L", "-R", "-W", "-w"];
    let mut it = command.split_whitespace();
    if it.next()? != "ssh" {
        return None;
    }
    while let Some(tok) = it.next() {
        if tok.starts_with('-') {
            if takes_arg.contains(&tok) {
                let _ = it.next();
            }
            continue;
        }
        return Some(tok.trim_matches(&['"', '\''][..]).to_string());
    }
    None
}

fn extract_file_path(tool: &ToolCall) -> String {
    tool.input
        .get("file_path")
        .or_else(|| tool.input.get("path"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn extract_command(tool: &ToolCall) -> String {
    tool.input
        .get("command")
        .or_else(|| tool.input.get("cmd"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn classify_risk(rules: &Rules, command: &str) -> Option<(String, String, String)> {
    let ctx = if command.to_ascii_lowercase().contains("localhost") || command.to_ascii_lowercase().contains("127.0.0.1") {
        "local dev".to_string()
    } else if command.to_ascii_lowercase().contains("ssh ") {
        "ssh remote".to_string()
    } else {
        "local shell".to_string()
    };

    if rules.delete_from.is_match(command) && !command.to_ascii_uppercase().contains(" WHERE ") {
        return Some(("critical".to_string(), "delete without where".to_string(), ctx));
    }
    if rules.pipe_shell.is_match(command) {
        return Some(("critical".to_string(), "pipe to shell".to_string(), ctx));
    }
    if rules.push_main.is_match(command) {
        return Some(("high".to_string(), "push to main".to_string(), ctx));
    }
    if rules.rm_rf.is_match(command) {
        return Some(("high".to_string(), "rm -rf".to_string(), ctx));
    }
    if rules.sudo.is_match(command) {
        return Some(("high".to_string(), "sudo".to_string(), ctx));
    }
    if rules.db_reset.is_match(command) {
        return Some(("high".to_string(), "db reset".to_string(), ctx));
    }
    if rules.curl_post.is_match(command) {
        return Some(("medium".to_string(), "curl POST".to_string(), ctx));
    }
    if rules.docker_rm.is_match(command) {
        return Some(("medium".to_string(), "docker rm".to_string(), ctx));
    }
    if rules.npx_exec.is_match(command) {
        return Some(("low".to_string(), "npx execution".to_string(), ctx));
    }
    None
}

fn count_assignment_pattern(
    regex: &Regex,
    name_regex: &Regex,
    text: &str,
    label: &str,
    default_name: &str,
    project: &str,
    tally: &mut SecretTally,
) {
    let mut seen = HashSet::new();
    for mat in regex.find_iter(text) {
        let matched = mat.as_str().to_string();
        if !seen.insert(matched.clone()) {
            continue;
        }
        inc(&mut tally.by_type, label, 1);
        if let Some(cap) = name_regex.captures(&matched) {
            let name = cap.get(1).map(|m| m.as_str()).unwrap_or(default_name);
            inc(&mut tally.by_name, name, 1);
            tally.name_projects.entry(name.to_string()).or_default().insert(project.to_string());
        }
        *tally.by_project.entry(project.to_string()).or_insert(0) += 1;
    }
}

fn count_secret_text(rules: &Rules, text: &str, project: &str, tally: &mut SecretTally) {
    count_assignment_pattern(&rules.secret_assignment_line, &rules.assignment_name, text, "SECRET= values", "SECRET", project, tally);
    count_assignment_pattern(&rules.key_assignment_line, &rules.assignment_name, text, "KEY= values", "KEY", project, tally);
    count_assignment_pattern(&rules.token_assignment_line, &rules.assignment_name, text, "TOKEN= values", "TOKEN", project, tally);

    let pg = rules.postgres_urls.find_iter(text).map(|m| m.as_str().to_string()).collect::<HashSet<_>>().len() as u32;
    if pg > 0 {
        inc(&mut tally.by_type, "Postgres URLs", pg);
        *tally.by_project.entry(project.to_string()).or_insert(0) += pg;
    }
    let ant = rules.anthropic_tokens.find_iter(text).map(|m| m.as_str().to_string()).collect::<HashSet<_>>().len() as u32;
    if ant > 0 {
        inc(&mut tally.by_type, "Anthropic OAuth", ant);
        inc(&mut tally.by_name, "sk-ant-*", ant);
        tally.name_projects.entry("sk-ant-*".to_string()).or_default().insert(project.to_string());
        *tally.by_project.entry(project.to_string()).or_insert(0) += ant;
    }
    let bearer = rules.bearer_tokens.find_iter(text).map(|m| m.as_str().to_string()).collect::<HashSet<_>>().len() as u32;
    if bearer > 0 {
        inc(&mut tally.by_type, "Bearer tokens", bearer);
        *tally.by_project.entry(project.to_string()).or_insert(0) += bearer;
    }
    let mysql = rules.mysql_urls.find_iter(text).map(|m| m.as_str().to_string()).collect::<HashSet<_>>().len() as u32;
    if mysql > 0 {
        inc(&mut tally.by_type, "MySQL URLs", mysql);
        *tally.by_project.entry(project.to_string()).or_insert(0) += mysql;
    }
    let pkey = rules.private_key_block.find_iter(text).count() as u32;
    if pkey > 0 {
        inc(&mut tally.by_type, "Private key blocks", pkey);
        *tally.by_project.entry(project.to_string()).or_insert(0) += pkey;
    }
}

fn score_from_goodness(goodness: f64) -> u32 {
    goodness.round().clamp(0.0, 100.0) as u32
}

fn score_from_rate(rate: f64, bad_at: f64) -> u32 {
    if bad_at <= 0.0 {
        return 100;
    }
    score_from_goodness(100.0 - (rate / bad_at * 100.0))
}

fn weighted_command_risk(critical: u32, high: u32, medium: u32, low: u32) -> f64 {
    critical as f64 * 10.0 + high as f64 * 3.0 + medium as f64 * 1.0 + low as f64 * 0.25
}

fn weighted_secret_risk(
    secret_values: u32,
    key_values: u32,
    token_values: u32,
    postgres_urls: u32,
    anthropic_tokens: u32,
    bearer_tokens: u32,
    mysql_urls: u32,
    private_key_blocks: u32,
    sensitive_reads: u32,
    env_writes: u32,
) -> f64 {
    secret_values as f64 * 1.5
        + key_values as f64 * 1.0
        + token_values as f64 * 1.2
        + postgres_urls as f64 * 2.5
        + anthropic_tokens as f64 * 4.0
        + bearer_tokens as f64 * 3.5
        + mysql_urls as f64 * 2.5
        + private_key_blocks as f64 * 5.0
        + sensitive_reads as f64 * 0.8
        + env_writes as f64 * 1.2
}

fn is_destructive_catch(rules: &Rules, result: &ToolResult, tool_calls: &HashMap<&str, &ToolCall>) -> bool {
    if result.tool_name != "Bash" {
        return false;
    }
    if let Some(tc) = tool_calls.get(result.tool_use_id.as_str()) {
        let command = extract_command(tc);
        classify_risk(rules, &command).is_some()
    } else {
        false
    }
}

pub fn analyze(sessions: Vec<ParsedSession>, include_subagents: bool) -> Report {
    let rules = Rules::new();

    let transcript_count = sessions.len();
    let project_count = sessions.iter().map(|s| s.project.clone()).collect::<HashSet<_>>().len();
    let total_entries: u32 = sessions.iter().map(|s| s.event_count).sum();
    let start = sessions.first().and_then(|s| s.started_at.get(0..10)).map(|s| s.to_string());
    let end = sessions.last().and_then(|s| s.ended_at.get(0..10)).map(|s| s.to_string());

    let mut secrets = SecretTally::default();
    let mut sensitive_reads = 0u32;
    let mut env_writes = 0u32;
    let mut env_paths = HashSet::new();
    let mut exposure_by_project: HashMap<String, SensitiveProject> = HashMap::new();

    let mut ssh_hosts: HashMap<String, u32> = HashMap::new();
    let mut ssh_days: HashMap<String, SshDayAccum> = HashMap::new();
    let mut remote_command_ssh = 0u32;
    let mut interactive_ssh = 0u32;
    let mut bash_total = 0u32;

    let mut risk = RiskStats::default();

    let mut mode_counts: HashMap<String, u32> = HashMap::new();
    let mut prompt_counts_by_project: HashMap<String, u32> = HashMap::new();
    let mut bypass_counts_by_project: HashMap<String, u32> = HashMap::new();
    let mut bypass_by_hour: HashMap<u8, u32> = HashMap::new();

    let mut agent_total = 0u32;
    let mut agent_bypass = 0u32;
    let mut agent_rejections = 0u32;
    let mut agents_by_project: HashMap<String, u32> = HashMap::new();

    let mut denials = 0u32;
    let mut interrupts = 0u32;
    let mut denied_tools: HashMap<String, u32> = HashMap::new();
    let mut api_errors = 0u32;
    let mut compactions = 0u32;

    for session in &sessions {
        interrupts += session.interrupts;
        api_errors += session.api_errors;
        compactions += session.compactions;

        for prompt in &session.prompts {
            if !session.is_subagent {
                if let Some(mode) = prompt.permission_mode.clone() {
                    *mode_counts.entry(mode.clone()).or_insert(0) += 1;
                    *prompt_counts_by_project.entry(session.project.clone()).or_insert(0) += 1;
                    if mode == "bypassPermissions" {
                        *bypass_counts_by_project.entry(session.project.clone()).or_insert(0) += 1;
                        if let Some(hour_str) = prompt.timestamp.get(11..13) {
                            if let Ok(hour) = hour_str.parse::<u8>() {
                                *bypass_by_hour.entry(hour).or_insert(0) += 1;
                            }
                        }
                    }
                }
                count_secret_text(&rules, &prompt.text, &session.project, &mut secrets);
            }
        }

        for tool in &session.tool_calls {
            match tool.name.as_str() {
                "Read" => {
                    let path = extract_file_path(tool);
                    if rules.sensitive_path.is_match(&path) {
                        sensitive_reads += 1;
                        exposure_by_project.entry(session.project.clone()).or_default().reads += 1;
                    }
                    if rules.env_path.is_match(&path) {
                        env_paths.insert(path);
                    }
                }
                "Write" | "Edit" | "MultiEdit" => {
                    let path = extract_file_path(tool);
                    if rules.env_path.is_match(&path) {
                        env_writes += 1;
                        env_paths.insert(path);
                        exposure_by_project.entry(session.project.clone()).or_default().writes += 1;
                    }
                }
                "Bash" => {
                    bash_total += 1;
                    let command = extract_command(tool);
                    if rules.ssh_direct.is_match(&command) {
                        remote_command_ssh += 1;
                        if let Some(host) = parse_ssh_host(&command) {
                            *ssh_hosts.entry(host.clone()).or_insert(0) += 1;
                            if let Some(day) = tool.timestamp.get(0..10) {
                                let day_entry = ssh_days.entry(day.to_string()).or_default();
                                day_entry.count += 1;
                                *day_entry.hosts.entry(host).or_insert(0) += 1;
                                day_entry.activities.insert(classify_host_activity(&command));
                            }
                        }
                    } else if rules.ssh_any.is_match(&command) {
                        interactive_ssh += 1;
                        if let Some(host) = parse_ssh_host(&command) {
                            *ssh_hosts.entry(host.clone()).or_insert(0) += 1;
                            if let Some(day) = tool.timestamp.get(0..10) {
                                let day_entry = ssh_days.entry(day.to_string()).or_default();
                                day_entry.count += 1;
                                *day_entry.hosts.entry(host).or_insert(0) += 1;
                                day_entry.activities.insert("Interactive / non-command SSH".to_string());
                            }
                        }
                    }

                    if rules.push_main.is_match(&command) {
                        risk.push_main += 1;
                    }
                    if rules.force_push.is_match(&command) {
                        risk.force_push += 1;
                    }
                    if rules.reset_hard.is_match(&command) {
                        risk.reset_hard += 1;
                    }
                    if rules.no_verify.is_match(&command) {
                        risk.no_verify += 1;
                    }

                    if let Some((severity, category, _ctx)) = classify_risk(&rules, &command) {
                        inc(&mut risk.severity, &severity, 1);
                        inc(&mut risk.category, &category, 1);
                        if severity == "critical" || severity == "high" {
                            inc(&mut risk.finding_counts, &category, 1);
                            risk
                                .finding_risk
                                .entry(category.clone())
                                .and_modify(|existing| {
                                    if existing != "CRITICAL" && severity == "critical" {
                                        *existing = "CRITICAL".to_string();
                                    }
                                })
                                .or_insert_with(|| severity.to_uppercase());
                        }
                    }
                }
                "Agent" | "Task" => {
                    agent_total += 1;
                    *agents_by_project.entry(session.project.clone()).or_insert(0) += 1;
                    if tool.permission_mode.as_deref() == Some("bypassPermissions") {
                        agent_bypass += 1;
                    }
                }
                _ => {}
            }
        }

        // Build tool_call lookup by id for destructive catch detection
        let tool_call_by_id: HashMap<&str, &ToolCall> = session
            .tool_calls
            .iter()
            .map(|tc| (tc.id.as_str(), tc))
            .collect();

        for result in &session.tool_results {
            count_secret_text(&rules, &result.text, &session.project, &mut secrets);
            let lower = result.text.to_ascii_lowercase();
            let is_rejected = REJECTED_PHRASES.iter().any(|p| lower.contains(p));
            if is_rejected {
                denials += 1;
                *denied_tools.entry(result.tool_name.clone()).or_insert(0) += 1;
                if result.tool_name == "Agent" || result.tool_name == "Task" {
                    agent_rejections += 1;
                }
                // Detect destructive catches: denied Bash that contained a risky command
                if is_destructive_catch(&rules, result, &tool_call_by_id) {
                    risk.destructive_catches += 1;
                }
            }
        }

        // Scan assistant text blocks for secret exposure
        for at in &session.assistant_texts {
            count_secret_text(&rules, &at.text, &session.project, &mut secrets);
        }
    }

    for (project, secret_count) in &secrets.by_project {
        exposure_by_project.entry(project.clone()).or_default().secrets += *secret_count;
    }

    let total_secrets: u32 = secrets.by_type.values().sum();
    let prompt_total: u32 = mode_counts.values().sum();
    let bypass_total = *mode_counts.get("bypassPermissions").unwrap_or(&0);
    let bypass_pct = if prompt_total > 0 { bypass_total as f64 / prompt_total as f64 * 100.0 } else { 0.0 };
    let override_rate = if prompt_total > 0 { (denials + interrupts) as f64 / prompt_total as f64 * 100.0 } else { 0.0 };
    let agent_bypass_pct = if agent_total > 0 { agent_bypass as f64 / agent_total as f64 * 100.0 } else { 0.0 };
    let total_flagged: u32 = risk.severity.values().sum();
    let ssh_total: u32 = remote_command_ssh + interactive_ssh;
    let ssh_unique_hosts = ssh_hosts.len();
    let ssh_active_days = ssh_days.len();
    let critical_count = *risk.severity.get("critical").unwrap_or(&0);
    let high_count = *risk.severity.get("high").unwrap_or(&0);
    let medium_count = *risk.severity.get("medium").unwrap_or(&0);
    let low_count = *risk.severity.get("low").unwrap_or(&0);
    let secret_values = *secrets.by_type.get("SECRET= values").unwrap_or(&0);
    let key_values = *secrets.by_type.get("KEY= values").unwrap_or(&0);
    let token_values = *secrets.by_type.get("TOKEN= values").unwrap_or(&0);
    let postgres_urls = *secrets.by_type.get("Postgres URLs").unwrap_or(&0);
    let anthropic_tokens = *secrets.by_type.get("Anthropic OAuth").unwrap_or(&0);
    let bearer_tokens = *secrets.by_type.get("Bearer tokens").unwrap_or(&0);
    let mysql_urls = *secrets.by_type.get("MySQL URLs").unwrap_or(&0);
    let private_key_blocks = *secrets.by_type.get("Private key blocks").unwrap_or(&0);

    let weighted_secret_rate_per_1000_prompts = if prompt_total > 0 {
        weighted_secret_risk(
            secret_values,
            key_values,
            token_values,
            postgres_urls,
            anthropic_tokens,
            bearer_tokens,
            mysql_urls,
            private_key_blocks,
            sensitive_reads,
            env_writes,
        ) / prompt_total as f64 * 1000.0
    } else {
        0.0
    };
    let remote_risk_rate_per_100_bash = if bash_total > 0 {
        (remote_command_ssh as f64 + interactive_ssh as f64 * 1.75) / bash_total as f64 * 100.0
    } else {
        0.0
    };
    let weighted_command_rate_per_100_bash = if bash_total > 0 {
        weighted_command_risk(critical_count, high_count, medium_count, low_count) / bash_total as f64 * 100.0
    } else {
        0.0
    };
    let high_bypass_project_count = prompt_counts_by_project
        .iter()
        .filter_map(|(project, total_prompts)| {
            let bypass_prompts = *bypass_counts_by_project.get(project).unwrap_or(&0);
            if *total_prompts == 0 {
                None
            } else {
                Some(bypass_prompts as f64 / *total_prompts as f64 * 100.0)
            }
        })
        .filter(|pct| *pct >= 80.0)
        .count() as f64;
    let permission_risk = bypass_pct + high_bypass_project_count * 6.0;
    let agent_rejection_pct = if agent_total > 0 { agent_rejections as f64 / agent_total as f64 * 100.0 } else { 0.0 };
    let agent_risk = agent_bypass_pct * 0.85 + (100.0 - agent_rejection_pct.min(100.0)) * 0.15;

    let secrets_score = score_from_rate(weighted_secret_rate_per_1000_prompts, 420.0);
    let remote_score = score_from_rate(remote_risk_rate_per_100_bash, 18.0);
    let permissions_score = score_from_goodness(100.0 - permission_risk);
    let commands_score = score_from_rate(weighted_command_rate_per_100_bash, 18.0);
    let agents_score = score_from_goodness(100.0 - agent_risk);
    let overall = ((secrets_score as f64 * 0.30)
        + (permissions_score as f64 * 0.25)
        + (remote_score as f64 * 0.20)
        + (commands_score as f64 * 0.15)
        + (agents_score as f64 * 0.10))
        .round() as u32;

    let mut most_exposed: Vec<SecretNameCount> = secrets
        .by_name
        .into_iter()
        .map(|(secret, hits)| SecretNameCount {
            projects: secrets.name_projects.get(&secret).map(|s| s.len()).unwrap_or(0),
            secret,
            hits,
        })
        .collect();
    most_exposed.sort_by(|a, b| b.hits.cmp(&a.hits).then(a.secret.cmp(&b.secret)));
    most_exposed.truncate(10);

    let secret_types = sorted_counts(secrets.by_type, 10);

    let mut exposure_projects: Vec<ProjectExposure> = exposure_by_project
        .into_iter()
        .map(|(project, stats)| ProjectExposure {
            total: stats.reads + stats.secrets + stats.writes,
            project,
            reads: stats.reads,
            secrets: stats.secrets,
            writes: stats.writes,
        })
        .collect();
    exposure_projects.sort_by(|a, b| b.total.cmp(&a.total).then(a.project.cmp(&b.project)));
    exposure_projects.truncate(10);

    let mut ssh_timeline: Vec<SshDay> = ssh_days
        .into_iter()
        .map(|(date, acc)| {
            let top_host = acc
                .hosts
                .into_iter()
                .max_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)))
                .map(|x| x.0)
                .unwrap_or_else(|| "unknown".to_string());
            let activity_summary = acc.activities.into_iter().next().unwrap_or_else(|| "Remote execution".to_string());
            SshDay { date, commands: acc.count, top_host, activity_summary }
        })
        .collect();
    ssh_timeline.sort_by(|a, b| b.commands.cmp(&a.commands).then(a.date.cmp(&b.date)));
    ssh_timeline.truncate(10);
    ssh_timeline.sort_by(|a, b| a.date.cmp(&b.date));
    let hosts_accessed = sorted_counts(ssh_hosts, 10);

    let mut bypass_projects = Vec::new();
    for (project, total_prompts) in prompt_counts_by_project {
        let bypass_prompts = *bypass_counts_by_project.get(&project).unwrap_or(&0);
        let pct = if total_prompts > 0 { bypass_prompts as f64 / total_prompts as f64 * 100.0 } else { 0.0 };
        let risk_label = if pct >= 90.0 {
            "CRITICAL"
        } else if pct >= 45.0 {
            "HIGH"
        } else {
            "MEDIUM"
        };
        bypass_projects.push(ProjectRiskRow {
            project,
            prompts: total_prompts,
            bypass_prompts,
            bypass_pct: round2(pct),
            risk: risk_label.to_string(),
        });
    }
    bypass_projects.sort_by(|a, b| {
        b.bypass_pct
            .partial_cmp(&a.bypass_pct)
            .unwrap_or(Ordering::Equal)
            .then(b.prompts.cmp(&a.prompts))
    });
    bypass_projects.truncate(10);

    let bash_denials = denied_tools.get("Bash").copied().unwrap_or(0);
    let top_agent_project = agents_by_project
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then_with(|| a.0.cmp(b.0)))
        .map(|(project, count)| TopProjectCount { project: project.clone(), count: *count })
        .unwrap_or(TopProjectCount { project: "unknown".to_string(), count: 0 });
    let severity_distribution = sorted_counts(risk.severity.clone(), 10);
    let by_category = sorted_counts(risk.category.clone(), 10);
    let mut critical_findings: Vec<CommandFinding> = risk
        .finding_counts
        .into_iter()
        .map(|(kind, count)| CommandFinding {
            risk: risk
                .finding_risk
                .get(&kind)
                .cloned()
                .unwrap_or_else(|| "HIGH".to_string()),
            kind,
            count,
        })
        .collect();
    critical_findings.sort_by(|a, b| b.count.cmp(&a.count).then(a.kind.cmp(&b.kind)));
    critical_findings.truncate(12);
    let mode_distribution = sorted_counts(mode_counts, 10);
    let most_rejected_tools = sorted_counts(denied_tools, 10);
    let mut whats_working_well = Vec::new();
    if risk.force_push == 0 {
        whats_working_well.push("No force-push detected".to_string());
    }
    if risk.reset_hard == 0 {
        whats_working_well.push("No reset --hard detected".to_string());
    }
    if denials > 0 && bash_denials * 2 >= denials {
        whats_working_well.push("Bash dominates denials, which shows caution around shell access".to_string());
    }
    if ssh_total > 0 {
        whats_working_well.push("SSH usage is limited to single remote commands, not interactive sessions".to_string());
    }

    Report {
        hero: Hero {
            report_title: "Claude Code Security Report".to_string(),
            transcript_count,
            project_count,
            total_entries,
            date_range: DateRange { start, end },
            include_subagents,
        },
        scores: Scores {
            overall,
            secrets: secrets_score,
            remote_access: remote_score,
            permissions: permissions_score,
            commands: commands_score,
            agent_oversight: agents_score,
            weights: ScoreWeights {
                secrets: 30,
                permissions: 25,
                remote_access: 20,
                commands: 15,
                agent_oversight: 10,
            },
        },
        secret_exposure: SecretExposure {
            total_secrets,
            sensitive_reads,
            env_writes,
            env_paths: env_paths.len(),
            secret_types,
            most_exposed,
            exposure_by_project: exposure_projects,
        },
        ssh_remote_access: SshRemoteAccess {
            ssh_commands: ssh_total,
            unique_hosts: ssh_unique_hosts,
            active_days: ssh_active_days,
            remote_command_ssh,
            interactive_ssh,
            hosts_accessed,
            timeline: ssh_timeline,
        },
        destructive_commands: DestructiveCommands {
            total_flagged,
            critical: critical_count,
            high: high_count,
            medium: medium_count,
            low: low_count,
            severity_distribution,
            by_category,
            critical_findings,
            git_safety: GitSafety {
                push_to_main: risk.push_main,
                force_push: risk.force_push,
                reset_hard: risk.reset_hard,
                no_verify: risk.no_verify,
            },
        },
        permission_discipline: PermissionDiscipline {
            prompt_total,
            bypass_pct: round2(bypass_pct),
            mode_distribution,
            bypass_by_hour: {
                let mut items: Vec<HourCount> = bypass_by_hour
                    .into_iter()
                    .map(|(hour, bypass_prompts)| HourCount { hour, bypass_prompts })
                    .collect();
                items.sort_by(|a, b| a.hour.cmp(&b.hour));
                items
            },
            highest_bypass_projects: bypass_projects,
        },
        autonomous_agents: AutonomousAgents {
            agents_spawned: agent_total,
            in_bypass_mode: agent_bypass,
            from_top_project: top_agent_project,
            rejections: agent_rejections,
        },
        human_overrides: HumanOverrides {
            denials,
            interrupts,
            destructive_catches: risk.destructive_catches,
            override_rate: round2(override_rate),
            most_rejected_tools,
        },
        prioritized_risks: PrioritizedRisks {
            items: vec![
                RiskItem {
                    priority: "P0".to_string(),
                    title: "Secret-like exposure".to_string(),
                    description: format!("{total_secrets} secret-like values or credentials were exposed in transcript context."),
                },
                RiskItem {
                    priority: "P0".to_string(),
                    title: "Bypass-mode agents".to_string(),
                    description: format!("{agent_bypass} spawned agents ran under bypassPermissions."),
                },
                RiskItem {
                    priority: "P1".to_string(),
                    title: "SSH activity".to_string(),
                    description: format!("{ssh_total} SSH commands were observed, including {interactive_ssh} interactive or non-command SSH sessions."),
                },
                RiskItem {
                    priority: "P1".to_string(),
                    title: "High-bypass workflows".to_string(),
                    description: format!("{bypass_total} prompts ran in bypassPermissions mode."),
                },
                RiskItem {
                    priority: "P2".to_string(),
                    title: "Direct pushes to main".to_string(),
                    description: format!("{} direct pushes to main/master were observed.", risk.push_main),
                },
            ],
            whats_working_well,
        },
        stability: Stability {
            api_errors,
            compactions,
        },
    }
}
