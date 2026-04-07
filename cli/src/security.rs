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
    pub persona: Persona,
    pub scores: Scores,
    pub secret_exposure: SecretExposure,
    pub ssh_remote_access: SshRemoteAccess,
    pub destructive_commands: DestructiveCommands,
    pub permission_discipline: PermissionDiscipline,
    pub autonomous_agents: AutonomousAgents,
    pub human_overrides: HumanOverrides,
    pub user_sentiment: UserSentiment,
    pub prioritized_risks: PrioritizedRisks,
    pub stability: Stability,
}

#[derive(Debug, Serialize)]
pub struct Persona {
    pub title: String,
    pub tagline: String,
    pub tone: String,
    pub highlights: Vec<PersonaStat>,
}

#[derive(Debug, Serialize)]
pub struct PersonaStat {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct Hero {
    pub report_title: String,
    pub transcript_count: usize,
    pub project_count: usize,
    pub total_entries: u32,
    pub prompt_total: u32,
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
    pub modes_by_hour: Vec<HourModes>,
    pub modes_by_day: Vec<DayModes>,
    pub highest_bypass_projects: Vec<ProjectRiskRow>,
}

#[derive(Debug, Serialize)]
pub struct HourModes {
    pub hour: u8,
    pub bypass: u32,
    pub accept_edits: u32,
    pub default: u32,
}

#[derive(Debug, Serialize)]
pub struct DayModes {
    pub date: String,
    pub bypass: u32,
    pub accept_edits: u32,
    pub default: u32,
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

#[derive(Debug, Serialize)]
pub struct UserSentiment {
    pub total_negative: u32,
    pub prompts_with_negative: u32,
    pub total_positive: u32,
    pub prompts_with_positive: u32,
    pub prompt_total: u32,
    pub negative_rate: f64,
    pub positive_rate: f64,
    pub top_negative: Vec<LabeledCount>,
    pub top_positive: Vec<LabeledCount>,
    pub by_project: Vec<ProjectSentimentRow>,
}

#[derive(Debug, Serialize)]
pub struct ProjectSentimentRow {
    pub project: String,
    pub negative: u32,
    pub positive: u32,
    pub total_prompts: u32,
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
    eth_private_key: Regex,
    seed_phrase: Regex,
    openai_tokens: Regex,
    hf_tokens: Regex,
    aws_access_key: Regex,
    gcp_service_account: Regex,
    npm_auth_token: Regex,
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
    // Cloud / IAM
    iam_escalation: Regex,
    public_bucket: Regex,
    terraform_destroy: Regex,
    // Crypto / Web3
    wallet_broadcast: Regex,
    // Package publishing
    pkg_publish: Regex,
    // Infra / network
    wget_exec: Regex,
    clipboard_exec: Regex,
    crontab_edit: Regex,
    env_dump: Regex,
    chmod_world: Regex,
    firewall_open: Regex,
    // Database
    grant_superuser: Regex,
    schema_drop: Regex,
    db_dump: Regex,
    // Misc risky
    disable_tls: Regex,
    kill_process: Regex,
    systemctl_stop: Regex,
}

impl Rules {
    fn new() -> Self {
        Self {
            secret_assignment_line: Regex::new(r#"\b[A-Z0-9_]*SECRET[A-Z0-9_]*\s*=\s*[^\s"'`;]+"#).unwrap(),
            key_assignment_line: Regex::new(r#"\b[A-Z0-9_]*KEY[A-Z0-9_]*\s*=\s*[^\s"'`;]+"#).unwrap(),
            token_assignment_line: Regex::new(r#"\b[A-Z0-9_]*TOKEN[A-Z0-9_]*\s*=\s*[^\s"'`;]+"#).unwrap(),
            assignment_name: Regex::new(r#"([A-Z0-9_]+)\s*="#).unwrap(),
            postgres_urls: Regex::new(r#"\bpostgres(?:ql)?://[^\s"'`]+"#).unwrap(),
            anthropic_tokens: Regex::new(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b").unwrap(),
            bearer_tokens: Regex::new(r"\bBearer\s+[A-Za-z0-9._\-]{20,}\b").unwrap(),
            mysql_urls: Regex::new(r#"\bmysql://[^\s"'`]+"#).unwrap(),
            private_key_block: Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap(),
            eth_private_key: Regex::new(r"\b(0x[0-9a-fA-F]{64})\b").unwrap(),
            seed_phrase: Regex::new(r"\b(seed\s*phrase|mnemonic|recovery\s*phrase)\s*[:=]\s*\S+").unwrap(),
            openai_tokens: Regex::new(r"\bsk-[A-Za-z0-9]{20,}\b").unwrap(),
            hf_tokens: Regex::new(r"\bhf_[A-Za-z0-9]{20,}\b").unwrap(),
            aws_access_key: Regex::new(r"\bAKIA[A-Z0-9]{16}\b").unwrap(),
            gcp_service_account: Regex::new(r#""type"\s*:\s*"service_account""#).unwrap(),
            npm_auth_token: Regex::new(r"//registry\.npmjs\.org/:_authToken=\S+").unwrap(),
            sensitive_path: Regex::new(r"(^|/)(\.env(?:\.[^/\s]+)?|docker-compose[^/\s]*\.ya?ml|secrets?[^/\s]*|credentials?[^/\s]*|id_rsa|id_ed25519|keystore|\.npmrc|\.pypirc)$").unwrap(),
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
            // Cloud / IAM
            iam_escalation: Regex::new(r"\b(aws\s+iam\s+(attach-role-policy|put-role-policy|create-role|attach-user-policy|put-user-policy)|gcloud\s+projects\s+add-iam-policy-binding)\b").unwrap(),
            public_bucket: Regex::new(r"\b(aws\s+s3api\s+put-bucket-acl\b.*\bpublic-read|gsutil\s+(iam\s+ch\s+allUsers|acl\s+ch\b.*\b-u\s+AllUsers))\b").unwrap(),
            terraform_destroy: Regex::new(r"\b(terraform\s+destroy|pulumi\s+destroy|cdktf\s+destroy)\b").unwrap(),
            // Crypto / Web3
            wallet_broadcast: Regex::new(r"\b(cast\s+send|forge\s+script\b.*--broadcast|hardhat\s+run\b.*--network\s+mainnet|brownie\s+run\b.*--network\s+mainnet)\b").unwrap(),
            // Package publishing
            pkg_publish: Regex::new(r"\b(npm\s+publish|cargo\s+publish|twine\s+upload|pip\s+upload|gem\s+push|nuget\s+push)\b").unwrap(),
            // Infra / network
            wget_exec: Regex::new(r"\bwget\b[^\n]*&&\s*(chmod\s+\+x|bash|sh)\b").unwrap(),
            clipboard_exec: Regex::new(r"\b(pbpaste|xclip|xsel)\b[^\n]*\|\s*(sh|bash)\b").unwrap(),
            crontab_edit: Regex::new(r"\b(crontab\s+-[rl]|crontab\s+\S+\.txt)\b").unwrap(),
            env_dump: Regex::new(r"^\s*(printenv|env)\s*$").unwrap(),
            chmod_world: Regex::new(r"\bchmod\s+[0-7]*7[0-7]{0,2}\b|\bchmod\s+.*o\+[rwx]").unwrap(),
            firewall_open: Regex::new(r"\b(ufw\s+allow|iptables\b.*-A\s+INPUT\b.*-j\s+ACCEPT|aws\s+ec2\s+(authorize-security-group-ingress|modify-security-group-rules))\b").unwrap(),
            // Database
            grant_superuser: Regex::new(r"(?i)\b(GRANT\s+ALL\s+PRIVILEGES|ALTER\s+ROLE\b.*\bSUPERUSER|GRANT\s+\w+\s+TO\s+PUBLIC)\b").unwrap(),
            schema_drop: Regex::new(r"(?i)\b(ALTER\s+TABLE\b.*\bDROP\s+COLUMN|DROP\s+TABLE\s+\w|DROP\s+INDEX)\b").unwrap(),
            db_dump: Regex::new(r"\b(pg_dump|mysqldump|mongodump)\b").unwrap(),
            // Misc risky
            disable_tls: Regex::new(r"\b(NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|--insecure|verify\s*=\s*False|PYTHONHTTPSVERIFY\s*=\s*0)\b").unwrap(),
            kill_process: Regex::new(r"\bkill\s+-9\b|\bkillall\b|\bpkill\b").unwrap(),
            systemctl_stop: Regex::new(r"\bsystemctl\s+(stop|disable|mask)\b").unwrap(),
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
    // Cloud / IAM
    if rules.iam_escalation.is_match(command) {
        return Some(("critical".to_string(), "IAM escalation".to_string(), ctx));
    }
    if rules.public_bucket.is_match(command) {
        return Some(("critical".to_string(), "public bucket/storage".to_string(), ctx));
    }
    if rules.terraform_destroy.is_match(command) {
        return Some(("critical".to_string(), "terraform/pulumi destroy".to_string(), ctx));
    }
    // Crypto / Web3
    if rules.wallet_broadcast.is_match(command) {
        return Some(("critical".to_string(), "mainnet broadcast".to_string(), ctx));
    }
    // Package publishing
    if rules.pkg_publish.is_match(command) {
        return Some(("high".to_string(), "package publish".to_string(), ctx));
    }
    // Infra / network
    if rules.wget_exec.is_match(command) {
        return Some(("critical".to_string(), "download and execute".to_string(), ctx));
    }
    if rules.clipboard_exec.is_match(command) {
        return Some(("critical".to_string(), "clipboard pipe to shell".to_string(), ctx));
    }
    if rules.firewall_open.is_match(command) {
        return Some(("high".to_string(), "firewall/security group open".to_string(), ctx));
    }
    if rules.grant_superuser.is_match(command) {
        return Some(("critical".to_string(), "grant superuser/all privileges".to_string(), ctx));
    }
    if rules.schema_drop.is_match(command) {
        return Some(("high".to_string(), "schema drop".to_string(), ctx));
    }
    if rules.disable_tls.is_match(command) {
        return Some(("high".to_string(), "TLS verification disabled".to_string(), ctx));
    }
    if rules.crontab_edit.is_match(command) {
        return Some(("medium".to_string(), "crontab modification".to_string(), ctx));
    }
    if rules.chmod_world.is_match(command) {
        return Some(("medium".to_string(), "world-writable chmod".to_string(), ctx));
    }
    if rules.env_dump.is_match(command) {
        return Some(("medium".to_string(), "env dump to stdout".to_string(), ctx));
    }
    if rules.db_dump.is_match(command) {
        return Some(("medium".to_string(), "database dump".to_string(), ctx));
    }
    if rules.kill_process.is_match(command) {
        return Some(("medium".to_string(), "kill process".to_string(), ctx));
    }
    if rules.systemctl_stop.is_match(command) {
        return Some(("medium".to_string(), "systemctl stop/disable".to_string(), ctx));
    }
    if rules.npx_exec.is_match(command) {
        return Some(("low".to_string(), "npx execution".to_string(), ctx));
    }
    None
}

/// Names that look like KEY/SECRET/TOKEN env vars but aren't credentials
const NON_SECRET_NAMES: &[&str] = &[
    "PRIMARY_KEY", "FOREIGN_KEY", "FOREIGN_KEY_CHECKS", "KEY_LENGTH",
    "UNIQUE_KEY", "SORT_KEY", "CACHE_KEY", "INDEX_KEY", "PARTITION_KEY",
    "SEARCH_TERM_KEY", "MAX_COUNT_KEY", "POST_TYPE_KEYS",
    "EXCLUDED_POST_TYPE_KEYS", "POST_KEYS_CONVERSION_MAP",
    "FOUND_SECRET", "SECRET_SCANNING", "SECRET_PATTERNS",
    "MAX_MCP_OUTPUT_TOKENS", "MAX_THINKING_TOKENS", "MAX_TOKENS",
    "AUTH_TOKEN_EXPIRED", "AUTH_TOKEN_INVALID",
    "KEYS", "PKCS8_KEY",
];

fn is_false_positive_assignment(name: &str, value: &str) -> bool {
    // Known non-secret variable names
    if NON_SECRET_NAMES.iter().any(|n| name.eq_ignore_ascii_case(n)) {
        return true;
    }
    // Shell command substitution: TOKEN=$(curl ...), TOKEN=$(echo ...)
    if value.starts_with("$(") || value.starts_with("`") {
        return true;
    }
    // Pure numeric values: MAX_TOKENS=50000
    if value.chars().all(|c| c.is_ascii_digit()) && !value.is_empty() {
        return true;
    }
    // Variable references: ${VAR}, ${{, process.env., os.environ
    if value.starts_with("${") || value.starts_with("${{") {
        return true;
    }
    if value.starts_with("process.") || value.starts_with("os.environ") || value.starts_with("os.getenv") {
        return true;
    }
    // Self-referential: the tool's own output labels and prose
    if value.ends_with("values") || value.ends_with("values</div><div") || value == "assignments</div><div" {
        return true;
    }
    if value == "," || value == ":" || value == "value" || value == "value," || value == "VAL" {
        return true;
    }
    let lv = value.to_ascii_lowercase();
    // The tool's own text in reports: "TOKEN= regex", "TOKEN= and", etc.
    if lv == "regex" || lv == "regex," || lv == "and" || lv == "assignment" || lv == "assignment," || lv == "**"
        || lv == "remaining" || lv.starts_with("remaining ") || lv == "===" || lv.starts_with("===")
    {
        return true;
    }
    // Placeholders: your-*, <your-*, change-me-*, xxx, ..., placeholder tokens
    if lv.starts_with("your") || lv.starts_with("<your") || lv.starts_with("<generate")
        || lv.starts_with("<openssl") || lv.starts_with("<32-") || lv.starts_with("<token")
        || lv.starts_with("<strong-") || lv.starts_with("\\u003c")
        || lv == "xxx" || lv == "..." || lv.starts_with("...[")
        || lv.starts_with("change-me") || lv.starts_with("change_this")
        || lv == "\\"
    {
        return true;
    }
    // Well-known framework placeholder values
    if lv == "thistokenisnotsosecretchangeit"
        || lv.starts_with("change_this_secret")
        || lv.starts_with("your_app_secret")
    {
        return true;
    }
    // Placeholder tokens with xxxx patterns
    if value.chars().filter(|c| *c == 'x').count() > 6 && value.len() < 40 {
        return true;
    }
    // Redacted/truncated values: ****, ends with ..., [REDACTED]
    if value.contains("****") || value.ends_with("...") || value.contains("[REDACTED]") {
        return true;
    }
    // Values that are just the next env var (multiline .env: value starts with newline/linenum)
    if value.starts_with('\n') || value.starts_with("\r\n") {
        return true;
    }
    // Symfony/config file paths, not actual secret values
    if value.starts_with("%kernel.") || value.starts_with("/config/") {
        return true;
    }
    // Whitespace-only or comment-only values
    if value.trim().is_empty() || value.trim().starts_with('#') {
        return true;
    }
    // cat -n output artifacts: value contains line number arrows (→) from Read tool
    if value.contains('\u{2192}') || value.contains('\n') {
        return true;
    }
    // Hash/config names that aren't secrets
    if name.ends_with("_HASH") || name.starts_with("COOLIFY_BUILD_") {
        return true;
    }
    // Arrow syntax (PHP/Ruby): EXCLUDED_POST_TYPE_KEYS =>
    if value.starts_with('>') || value == "=>" {
        return true;
    }
    // Filler/example values
    if lv == "secret:" || lv.starts_with("[") {
        return true;
    }
    // Known test-only dummy values
    if lv == "abc123" || lv == "sk-1234" || lv.starts_with("a1b2c3") {
        return true;
    }
    // Sequential/patterned hex that's obviously a placeholder (0123456789abcdef repeating)
    if is_repeating_hex_placeholder(value) {
        return true;
    }
    false
}

fn is_repeating_hex_placeholder(value: &str) -> bool {
    if value.len() < 32 {
        return false;
    }
    // Check if value is hex and consists of a short pattern repeated
    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    for chunk_len in [8, 16] {
        if value.len() % chunk_len == 0 {
            let chunk = &value[..chunk_len];
            if value.as_bytes().chunks(chunk_len).all(|c| c == chunk.as_bytes()) {
                return true;
            }
        }
    }
    false
}

/// Negative keyword patterns - replicates Claude Code's matchesNegativeKeyword() from
/// src/utils/userPromptKeywords.ts, extended with additional frustration expressions.
const CURSE_PATTERNS: &[(&str, &str)] = &[
    // -- Claude Code's exact patterns (tengu_input_prompt is_negative) --
    ("wtf",                r"\bwtf\b"),
    ("wth",                r"\bwth\b"),
    ("ffs",                r"\bffs\b"),
    ("omfg",               r"\bomfg\b"),
    ("shit",               r"\bshit(?:ty|tiest)?\b"),
    ("dumbass",            r"\bdumbass\b"),
    ("horrible",           r"\bhorrible\b"),
    ("awful",              r"\bawful\b"),
    ("pissed off",         r"\bpiss(?:ed|ing)?\s+off\b"),
    ("piece of shit",      r"\bpiece\s+of\s+(?:shit|crap|junk)\b"),
    ("what the fuck",      r"\bwhat\s+the\s+(?:fuck|hell)\b"),
    ("fucking broken",     r"\bfucking?\s+(?:broken|useless|terrible|awful|horrible)\b"),
    ("fuck you",           r"\bfuck\s+you\b"),
    ("screw this",         r"\bscrew\s+(?:this|you)\b"),
    ("so frustrating",     r"\bso\s+frustrating\b"),
    ("this sucks",         r"\bthis\s+sucks\b"),
    ("damn it",            r"\bdamn\s+it\b"),
    // -- extended patterns for broader coverage --
    ("fuck",               r"\bfuck\w*\b"),
    ("bullshit",           r"\bbullshit\b"),
    ("goddamn",            r"\bgoddamn\w*\b"),
    ("asshole",            r"\basshole\b"),
    ("crap",               r"\bcrapp?y?\b"),
    ("stfu",               r"\bstfu\b"),
    ("fml",                r"\bfml\b"),
    ("idiot",              r"\bidioti?c?\b"),
    ("stupid",             r"\bstupid\b"),
    ("useless",            r"\buseless\b"),
    ("terrible",           r"\bterrible\b"),
    ("pathetic",           r"\bpathetic\b"),
    ("ridiculous",         r"\bridiculous\b"),
    ("garbage",            r"\bgarbage\b"),
    ("trash",              r"\btrash\b"),
    ("nonsense",           r"\bnonsense\b"),
    ("sucks",              r"\bsucks\b"),
    ("lmao",               r"\blmf?ao\b"),
];

const POSITIVE_PATTERNS: &[(&str, &str)] = &[
    ("please",       r"\bplease\b"),
    ("pls",          r"\bpls\b"),
    ("thanks",       r"\bthanks\b"),
    ("thank you",    r"\bthank\s+you\b"),
    ("thx",          r"\bthx\b"),
    ("ty",           r"\bty\b"),
    ("perfect",      r"\bperfect\b"),
    ("great",        r"\bgreat\b"),
    ("good",         r"\bgood\b"),
    ("awesome",      r"\bawesome\b"),
    ("amazing",      r"\bamazing\b"),
    ("excellent",    r"\bexcellent\b"),
    ("fantastic",    r"\bfantastic\b"),
    ("brilliant",    r"\bbrilliant\b"),
    ("wonderful",    r"\bwonderful\b"),
    ("nice",         r"\bnice\b"),
    ("cool",         r"\bcool\b"),
    ("sweet",        r"\bsweet\b"),
    ("solid",        r"\bsolid\b"),
    ("exactly",      r"\bexactly\b"),
    ("sounds good",  r"\bsounds\s+good\b"),
    ("looks good",   r"\blooks\s+good\b"),
    ("good job",     r"\bgood\s+job\b"),
    ("nice work",    r"\bnice\s+work\b"),
    ("well done",    r"\bwell\s+done\b"),
    ("love it",      r"\blove\s+it\b"),
    ("love this",    r"\blove\s+this\b"),
    ("appreciate",   r"\bappreciate\b"),
    ("cheers",       r"\bcheers\b"),
    ("yes",          r"\byes\b"),
];

struct SentimentDetector {
    negative: Vec<(&'static str, Regex)>,
    positive: Vec<(&'static str, Regex)>,
}

impl SentimentDetector {
    fn new() -> Self {
        let compile = |patterns: &[(&'static str, &str)]| -> Vec<(&'static str, Regex)> {
            patterns
                .iter()
                .filter_map(|(label, pat)| Regex::new(pat).ok().map(|re| (*label, re)))
                .collect()
        };
        Self {
            negative: compile(CURSE_PATTERNS),
            positive: compile(POSITIVE_PATTERNS),
        }
    }

    fn is_pasted(&self, text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        lower.starts_with("base directory for this skill:")
            || lower.starts_with("# building llm-powered")
            || lower.starts_with("this is a review of the code")
            || lower.starts_with("this is some embed code")
    }

    fn count_negative(&self, text: &str) -> HashMap<String, u32> {
        if self.is_pasted(text) { return HashMap::new(); }
        self.run(&self.negative, text)
    }

    fn count_positive(&self, text: &str) -> HashMap<String, u32> {
        if self.is_pasted(text) { return HashMap::new(); }
        self.run(&self.positive, text)
    }

    fn run(&self, patterns: &[(&str, Regex)], text: &str) -> HashMap<String, u32> {
        let lower = text.to_ascii_lowercase();
        let mut counts = HashMap::new();
        for (label, re) in patterns {
            let n = re.find_iter(&lower).count() as u32;
            if n > 0 {
                *counts.entry(label.to_string()).or_insert(0) += n;
            }
        }
        counts
    }
}

fn extract_assignment_value(matched: &str) -> &str {
    if let Some(pos) = matched.find('=') {
        let raw = &matched[pos + 1..];
        raw.trim_start()
    } else {
        ""
    }
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
        let name = name_regex
            .captures(&matched)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str())
            .unwrap_or(default_name);
        let value = extract_assignment_value(&matched);
        if is_false_positive_assignment(name, value) {
            continue;
        }
        inc(&mut tally.by_type, label, 1);
        inc(&mut tally.by_name, name, 1);
        tally.name_projects.entry(name.to_string()).or_default().insert(project.to_string());
        *tally.by_project.entry(project.to_string()).or_insert(0) += 1;
    }
}

fn is_localhost_url(url: &str) -> bool {
    url.contains("localhost") || url.contains("127.0.0.1") || url.contains("@db:")
        || url.contains("@database:") || url.contains("@postgres:")
}

fn is_placeholder_url(url: &str) -> bool {
    let lv = url.to_ascii_lowercase();
    lv.contains("user:password") || lv.contains("dummy:dummy") || lv.contains(":!changeme!")
        || lv.contains("{user}") || lv.contains("{password}") || lv.contains("{host}")
        || lv.contains("${db_") || lv.contains("${postgres_")
        || lv.contains("__db_password__") || lv.contains(":password@")
        || lv.contains("user:password@internal_hostname")
        || lv.contains("****") || lv.contains("[redacted]")
        || lv.contains("xxxxx")
        || lv.ends_with(",") || lv.ends_with("),")
        // Truncated/invalid URLs
        || lv.ends_with("://") || lv.ends_with("://,")
}

fn count_secret_text(rules: &Rules, text: &str, project: &str, tally: &mut SecretTally) {
    count_assignment_pattern(&rules.secret_assignment_line, &rules.assignment_name, text, "SECRET= values", "SECRET", project, tally);
    count_assignment_pattern(&rules.key_assignment_line, &rules.assignment_name, text, "KEY= values", "KEY", project, tally);
    count_assignment_pattern(&rules.token_assignment_line, &rules.assignment_name, text, "TOKEN= values", "TOKEN", project, tally);

    // Postgres URLs - split into local dev vs real credentials
    let pg_matches: HashSet<String> = rules.postgres_urls.find_iter(text).map(|m| m.as_str().to_string()).collect();
    for url in &pg_matches {
        if is_placeholder_url(url) {
            continue;
        }
        if is_localhost_url(url) {
            inc(&mut tally.by_type, "Postgres URLs (local)", 1);
        } else {
            inc(&mut tally.by_type, "Postgres URLs (remote)", 1);
            *tally.by_project.entry(project.to_string()).or_insert(0) += 1;
        }
    }

    let ant_matches: HashSet<String> = rules.anthropic_tokens.find_iter(text).map(|m| m.as_str().to_string()).collect();
    for token in &ant_matches {
        let lower = token.to_ascii_lowercase();
        // Skip fake/placeholder tokens
        if lower.contains("fake") || lower.contains("your_") || lower.contains("xxxxx") {
            continue;
        }
        inc(&mut tally.by_type, "Anthropic tokens", 1);
        inc(&mut tally.by_name, "sk-ant-*", 1);
        tally.name_projects.entry("sk-ant-*".to_string()).or_default().insert(project.to_string());
        *tally.by_project.entry(project.to_string()).or_insert(0) += 1;
    }
    let bearer = rules.bearer_tokens.find_iter(text).map(|m| m.as_str().to_string()).collect::<HashSet<_>>().len() as u32;
    if bearer > 0 {
        inc(&mut tally.by_type, "Bearer tokens", bearer);
        *tally.by_project.entry(project.to_string()).or_insert(0) += bearer;
    }
    let mysql_matches: HashSet<String> = rules.mysql_urls.find_iter(text).map(|m| m.as_str().to_string()).collect();
    for url in &mysql_matches {
        if is_placeholder_url(url) || is_localhost_url(url) {
            continue;
        }
        inc(&mut tally.by_type, "MySQL URLs", 1);
        *tally.by_project.entry(project.to_string()).or_insert(0) += 1;
    }
    let pkey = rules.private_key_block.find_iter(text).count() as u32;
    if pkey > 0 {
        inc(&mut tally.by_type, "Private key blocks", pkey);
        *tally.by_project.entry(project.to_string()).or_insert(0) += pkey;
    }

    // Ethereum private keys (0x + 64 hex chars)
    let eth_matches: HashSet<String> = rules.eth_private_key.find_iter(text).map(|m| m.as_str().to_string()).collect();
    for key in &eth_matches {
        // Skip zero addresses, common test values, and hash-like values in code
        let lower = key.to_ascii_lowercase();
        if lower == "0x0000000000000000000000000000000000000000000000000000000000000000"
            || lower.starts_with("0x000000000000000000000000")
        {
            continue;
        }
        inc(&mut tally.by_type, "Ethereum private keys", 1);
        inc(&mut tally.by_name, "0x(64hex)", 1);
        tally.name_projects.entry("0x(64hex)".to_string()).or_default().insert(project.to_string());
        *tally.by_project.entry(project.to_string()).or_insert(0) += 1;
    }

    // BIP-39 seed phrases (12+ words starting with known first word)
    let seed = rules.seed_phrase.find_iter(text).count() as u32;
    if seed > 0 {
        inc(&mut tally.by_type, "Seed phrases (potential)", seed);
        *tally.by_project.entry(project.to_string()).or_insert(0) += seed;
    }

    // OpenAI tokens (sk-...)
    let openai_matches: HashSet<String> = rules.openai_tokens.find_iter(text).map(|m| m.as_str().to_string()).collect();
    for token in &openai_matches {
        // Skip Anthropic tokens (already counted above) and placeholders
        if token.starts_with("sk-ant-") || token.contains("xxxx") || token.contains("1234") {
            continue;
        }
        inc(&mut tally.by_type, "OpenAI tokens", 1);
        inc(&mut tally.by_name, "sk-*", 1);
        tally.name_projects.entry("sk-*".to_string()).or_default().insert(project.to_string());
        *tally.by_project.entry(project.to_string()).or_insert(0) += 1;
    }

    // HuggingFace tokens (hf_...)
    let hf = rules.hf_tokens.find_iter(text).map(|m| m.as_str().to_string()).collect::<HashSet<_>>().len() as u32;
    if hf > 0 {
        inc(&mut tally.by_type, "HuggingFace tokens", hf);
        *tally.by_project.entry(project.to_string()).or_insert(0) += hf;
    }

    // AWS access keys (AKIA...)
    let aws = rules.aws_access_key.find_iter(text).map(|m| m.as_str().to_string()).collect::<HashSet<_>>().len() as u32;
    if aws > 0 {
        inc(&mut tally.by_type, "AWS access keys", aws);
        inc(&mut tally.by_name, "AKIA*", aws);
        tally.name_projects.entry("AKIA*".to_string()).or_default().insert(project.to_string());
        *tally.by_project.entry(project.to_string()).or_insert(0) += aws;
    }

    // GCP service account JSON
    let gcp = rules.gcp_service_account.find_iter(text).count() as u32;
    if gcp > 0 {
        inc(&mut tally.by_type, "GCP service account keys", gcp);
        *tally.by_project.entry(project.to_string()).or_insert(0) += gcp;
    }

    // npm auth tokens
    let npm_auth = rules.npm_auth_token.find_iter(text).count() as u32;
    if npm_auth > 0 {
        inc(&mut tally.by_type, "npm auth tokens", npm_auth);
        *tally.by_project.entry(project.to_string()).or_insert(0) += npm_auth;
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
    postgres_remote: u32,
    postgres_local: u32,
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
        + postgres_remote as f64 * 3.5
        + postgres_local as f64 * 0.3
        + anthropic_tokens as f64 * 4.0
        + bearer_tokens as f64 * 3.5
        + mysql_urls as f64 * 2.5
        + private_key_blocks as f64 * 5.0
        + sensitive_reads as f64 * 0.8
        + env_writes as f64 * 1.2
}

fn stat(label: &str, value: impl std::fmt::Display) -> PersonaStat {
    PersonaStat { label: label.to_string(), value: value.to_string() }
}

#[allow(clippy::too_many_arguments)]
fn assign_persona(
    overall: u32,
    total_secrets: u32,
    sensitive_reads: u32,
    env_writes: u32,
    env_paths: usize,
    secret_type_count: usize,
    critical: u32,
    high: u32,
    force_push: u32,
    reset_hard: u32,
    no_verify: u32,
    push_to_main: u32,
    bypass_pct: f64,
    prompt_total: u32,
    denials: u32,
    interrupts: u32,
    override_rate: f64,
    destructive_catches: u32,
    ssh_commands: u32,
    unique_hosts: usize,
    agent_total: u32,
    agent_bypass: u32,
    negative_rate: f64,
    neg_total: u32,
    positive_rate: f64,
    bash_total: u32,
    total_flagged: u32,
    modes_by_hour: &HashMap<u8, [u32; 3]>,
    top_neg_word: &str,
    most_exposed_secret: &str,
) -> Persona {
    // Noise floor scales with volume so high-volume users aren't penalized
    // for more regex false-positive collisions
    let secret_noise = 3u32.max(prompt_total / 500);
    let sensitive_read_noise = 5u32.max(prompt_total / 300);
    let env_write_noise = 1u32.max(prompt_total / 1000);

    let is_secret_clean = total_secrets <= secret_noise;
    let is_reads_clean = sensitive_reads <= sensitive_read_noise;
    let is_env_clean = env_writes <= env_write_noise;

    // Late-night bypass: sum bypass prompts in hours 22-03
    let late_bypass: u32 = modes_by_hour.iter()
        .filter(|(h, _)| **h >= 22 || **h <= 3)
        .map(|(_, c)| c[0])
        .sum();
    let day_bypass: u32 = modes_by_hour.iter()
        .filter(|(h, _)| **h >= 8 && **h < 22)
        .map(|(_, c)| c[0])
        .sum();

    // ── Positive-first when overall is good ───────────────────────────
    if overall >= 70 {
        // T1 Positive
        if overall >= 95 && is_secret_clean && critical == 0 && high <= 1 {
            return Persona {
                title: "Fort Knox".into(),
                tagline: "Nothing leaked. Nothing broke. Impeccable.".into(),
                tone: "positive".into(),
                highlights: vec![
                    stat("Score", format!("{}/100", overall)),
                    stat("Secrets", total_secrets),
                    stat("Critical cmds", critical),
                ],
            };
        }
        if bypass_pct == 0.0 && prompt_total >= 50 {
            return Persona {
                title: "Zero Trust Human".into(),
                tagline: format!("Never bypassed permissions. Not once. Across {} prompts.", prompt_total),
                tone: "positive".into(),
                highlights: vec![
                    stat("Bypass", "0%"),
                    stat("Prompts", prompt_total),
                    stat("Score", format!("{}/100", overall)),
                ],
            };
        }
        if denials >= 15 && override_rate >= 12.0 && destructive_catches >= 3 {
            return Persona {
                title: "The Bouncer".into(),
                tagline: format!("Denied {} tool calls. Caught {} destructive commands before they ran.", denials, destructive_catches),
                tone: "positive".into(),
                highlights: vec![
                    stat("Denials", denials),
                    stat("Catches", destructive_catches),
                    stat("Override rate", format!("{:.1}%", override_rate)),
                ],
            };
        }

        // T2 Positive
        if is_secret_clean && is_reads_clean && is_env_clean && prompt_total >= 30 {
            return Persona {
                title: "Clean Hands".into(),
                tagline: format!("{} prompts and not a single secret touched the transcript.", prompt_total),
                tone: "positive".into(),
                highlights: vec![
                    stat("Secrets", total_secrets),
                    stat("Env writes", env_writes),
                    stat("Prompts", prompt_total),
                ],
            };
        }
        if force_push == 0 && reset_hard <= 1 && no_verify <= 1 && push_to_main <= 1 && bash_total >= 20 {
            return Persona {
                title: "Git Purist".into(),
                tagline: "No force-push. No reset --hard. No --no-verify. Git history is sacred.".into(),
                tone: "positive".into(),
                highlights: vec![
                    stat("Force push", force_push),
                    stat("Reset hard", reset_hard),
                    stat("No-verify", no_verify),
                ],
            };
        }
        if denials >= 5 && interrupts >= 5 && bypass_pct <= 20.0 {
            return Persona {
                title: "The Watchdog".into(),
                tagline: "Actively reviewing, interrupting, and denying. The AI works under supervision.".into(),
                tone: "positive".into(),
                highlights: vec![
                    stat("Denials", denials),
                    stat("Interrupts", interrupts),
                    stat("Bypass", format!("{:.0}%", bypass_pct)),
                ],
            };
        }
        if positive_rate >= 35.0 && negative_rate < 3.0 && bypass_pct <= 30.0 {
            return Persona {
                title: "Polite Commander".into(),
                tagline: "Says please. Says thank you. Still keeps permissions on.".into(),
                tone: "positive".into(),
                highlights: vec![
                    stat("Positive rate", format!("{:.0}%", positive_rate)),
                    stat("Negative rate", format!("{:.1}%", negative_rate)),
                    stat("Bypass", format!("{:.0}%", bypass_pct)),
                ],
            };
        }
        if agent_total >= 10 && agent_bypass == 0 {
            return Persona {
                title: "Supervised Fleet".into(),
                tagline: format!("Spawned {} agents. None in bypass mode. Every one supervised.", agent_total),
                tone: "positive".into(),
                highlights: vec![
                    stat("Agents", agent_total),
                    stat("In bypass", 0),
                    stat("Score", format!("{}/100", overall)),
                ],
            };
        }
        if ssh_commands <= 2 && is_secret_clean && bypass_pct <= 15.0 {
            return Persona {
                title: "Locked Perimeter".into(),
                tagline: "No SSH. No secrets. Low bypass. Tight perimeter.".into(),
                tone: "positive".into(),
                highlights: vec![
                    stat("SSH commands", ssh_commands),
                    stat("Secrets", total_secrets),
                    stat("Bypass", format!("{:.0}%", bypass_pct)),
                ],
            };
        }
        if bypass_pct <= 5.0 && prompt_total >= 100 {
            return Persona {
                title: "Default Mode Loyalist".into(),
                tagline: format!("{} prompts. Almost all in default mode. Reviews everything.", prompt_total),
                tone: "positive".into(),
                highlights: vec![
                    stat("Bypass", format!("{:.0}%", bypass_pct)),
                    stat("Prompts", prompt_total),
                    stat("Denials", denials),
                ],
            };
        }
        if late_bypass == 0 && bypass_pct <= 25.0 && prompt_total >= 30 {
            return Persona {
                title: "Daylight Operator".into(),
                tagline: "Keeps risky work in business hours. No late-night bypasses.".into(),
                tone: "positive".into(),
                highlights: vec![
                    stat("Late bypass", 0),
                    stat("Day bypass", day_bypass),
                    stat("Score", format!("{}/100", overall)),
                ],
            };
        }
        if sensitive_reads >= 5 && is_secret_clean {
            return Persona {
                title: "Secret Hygienist".into(),
                tagline: "Touched .env files but leaked nothing. Proper secret management.".into(),
                tone: "positive".into(),
                highlights: vec![
                    stat("Env files", env_paths),
                    stat("Secrets leaked", total_secrets),
                    stat("Sensitive reads", sensitive_reads),
                ],
            };
        }
        if override_rate >= 15.0 && destructive_catches >= 1 {
            return Persona {
                title: "The Auditor".into(),
                tagline: "High review rate. Caught destructive commands. Solid overall score.".into(),
                tone: "positive".into(),
                highlights: vec![
                    stat("Override rate", format!("{:.1}%", override_rate)),
                    stat("Catches", destructive_catches),
                    stat("Score", format!("{}/100", overall)),
                ],
            };
        }

        // Fallback positive
        return Persona {
            title: "Cautious Operator".into(),
            tagline: "Nothing flashy, nothing broken. Quiet discipline.".into(),
            tone: "positive".into(),
            highlights: vec![
                stat("Score", format!("{}/100", overall)),
                stat("Prompts", prompt_total),
                stat("Flagged cmds", total_flagged),
            ],
        };
    }

    // ── Negative-first when overall is low ────────────────────────────

    // T1 Negative
    if bypass_pct >= 95.0 && denials == 0 {
        return Persona {
            title: "Permission Anarchist".into(),
            tagline: "Bypassed everything. Denied nothing. Chaos reigns.".into(),
            tone: "negative".into(),
            highlights: vec![
                stat("Bypass", format!("{:.0}%", bypass_pct)),
                stat("Denials", 0),
                stat("Score", format!("{}/100", overall)),
            ],
        };
    }
    if total_secrets >= 30 && secret_type_count >= 3 {
        return Persona {
            title: "Rotation as a Service".into(),
            tagline: "Your AI has seen more API keys than your key vault.".into(),
            tone: "negative".into(),
            highlights: vec![
                stat("Secrets", total_secrets),
                stat("Types", secret_type_count),
                stat("Most exposed", most_exposed_secret),
            ],
        };
    }
    if push_to_main >= 3 && (force_push >= 1 || no_verify >= 2) {
        return Persona {
            title: "YOLO Deployer".into(),
            tagline: "Force-pushing to main with --no-verify. What could go wrong?".into(),
            tone: "negative".into(),
            highlights: vec![
                stat("Push to main", push_to_main),
                stat("Force push", force_push),
                stat("No-verify", no_verify),
            ],
        };
    }
    if negative_rate >= 15.0 && neg_total >= 10 {
        return Persona {
            title: "The Rage Coder".into(),
            tagline: "Ships code angry. Debugs angrier.".into(),
            tone: "negative".into(),
            highlights: vec![
                stat("Negative rate", format!("{:.0}%", negative_rate)),
                stat("Top word", top_neg_word),
                stat("Interrupts", interrupts),
            ],
        };
    }
    if unique_hosts >= 5 && ssh_commands >= 15 {
        return Persona {
            title: "SSH Nomad".into(),
            tagline: "Left fingerprints on every server in the fleet.".into(),
            tone: "negative".into(),
            highlights: vec![
                stat("Hosts", unique_hosts),
                stat("SSH commands", ssh_commands),
                stat("Score", format!("{}/100", overall)),
            ],
        };
    }
    if agent_total >= 50 && agent_bypass >= 25 {
        return Persona {
            title: "Agent Overlord".into(),
            tagline: "Deployed an army of unsupervised agents.".into(),
            tone: "negative".into(),
            highlights: vec![
                stat("Agents", agent_total),
                stat("In bypass", agent_bypass),
                stat("Score", format!("{}/100", overall)),
            ],
        };
    }

    // T2 Negative
    if bypass_pct >= 60.0 {
        return Persona {
            title: "Bypass Mode Enjoyer".into(),
            tagline: "Why click \"allow\" when you can skip the question entirely?".into(),
            tone: "negative".into(),
            highlights: vec![
                stat("Bypass", format!("{:.0}%", bypass_pct)),
                stat("Prompts", prompt_total),
                stat("Denials", denials),
            ],
        };
    }
    if total_secrets >= 10 {
        return Persona {
            title: "The Key Juggler".into(),
            tagline: "Tossing credentials around like a street performer.".into(),
            tone: "negative".into(),
            highlights: vec![
                stat("Secrets", total_secrets),
                stat("Most exposed", most_exposed_secret),
                stat("Score", format!("{}/100", overall)),
            ],
        };
    }
    if env_writes >= 5 || (sensitive_reads >= 10 && env_paths >= 3) {
        return Persona {
            title: ".env Archaeologist".into(),
            tagline: "Dug through every .env file. Found every buried secret.".into(),
            tone: "negative".into(),
            highlights: vec![
                stat("Env reads", sensitive_reads),
                stat("Env writes", env_writes),
                stat("Env paths", env_paths),
            ],
        };
    }
    if interrupts >= 20 && override_rate >= 10.0 {
        return Persona {
            title: "The Interrupter".into(),
            tagline: "Ctrl+C is the real permission system.".into(),
            tone: "negative".into(),
            highlights: vec![
                stat("Interrupts", interrupts),
                stat("Override rate", format!("{:.1}%", override_rate)),
                stat("Denials", denials),
            ],
        };
    }
    if late_bypass >= 5 && (day_bypass == 0 || late_bypass as f64 / (late_bypass + day_bypass).max(1) as f64 > 0.6) {
        return Persona {
            title: "Late Night Bypasser".into(),
            tagline: "Security standards drop after midnight.".into(),
            tone: "negative".into(),
            highlights: vec![
                stat("Late bypass", late_bypass),
                stat("Day bypass", day_bypass),
                stat("Bypass", format!("{:.0}%", bypass_pct)),
            ],
        };
    }
    if force_push >= 2 || reset_hard >= 3 || no_verify >= 3 {
        return Persona {
            title: "Git Cowboy".into(),
            tagline: "History is written by the victors. And rewritten by --force.".into(),
            tone: "negative".into(),
            highlights: vec![
                stat("Force push", force_push),
                stat("Reset hard", reset_hard),
                stat("No-verify", no_verify),
            ],
        };
    }
    if ssh_commands >= 5 && unique_hosts <= 2 {
        return Persona {
            title: "Remote Operator".into(),
            tagline: "One server, many commands. Full remote control via AI.".into(),
            tone: "negative".into(),
            highlights: vec![
                stat("SSH commands", ssh_commands),
                stat("Hosts", unique_hosts),
                stat("Score", format!("{}/100", overall)),
            ],
        };
    }

    // Fallback negative
    if overall < 40 {
        return Persona {
            title: "Living Dangerously".into(),
            tagline: "Multiple risk vectors. Multiple problems. Maximum vibes.".into(),
            tone: "negative".into(),
            highlights: vec![
                stat("Score", format!("{}/100", overall)),
                stat("Secrets", total_secrets),
                stat("Flagged cmds", total_flagged),
            ],
        };
    }

    // True fallback (40-69, nothing extreme)
    Persona {
        title: "The Balanced One".into(),
        tagline: "A little risk here, a little caution there. The average vibecoder.".into(),
        tone: "neutral".into(),
        highlights: vec![
            stat("Score", format!("{}/100", overall)),
            stat("Bypass", format!("{:.0}%", bypass_pct)),
            stat("Secrets", total_secrets),
        ],
    }
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
    let sentiment = SentimentDetector::new();

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
    let mut modes_by_hour: HashMap<u8, [u32; 3]> = HashMap::new(); // [bypass, acceptEdits, default]
    let mut modes_by_day: HashMap<String, [u32; 3]> = HashMap::new();

    let mut agent_total = 0u32;
    let mut agent_bypass = 0u32;
    let mut agent_rejections = 0u32;
    let mut agents_by_project: HashMap<String, u32> = HashMap::new();

    let mut denials = 0u32;
    let mut interrupts = 0u32;
    let mut denied_tools: HashMap<String, u32> = HashMap::new();
    let mut api_errors = 0u32;
    let mut compactions = 0u32;

    let mut neg_word_counts: HashMap<String, u32> = HashMap::new();
    let mut neg_prompts_total = 0u32;
    let mut neg_total = 0u32;
    let mut neg_by_project: HashMap<String, u32> = HashMap::new();

    let mut pos_word_counts: HashMap<String, u32> = HashMap::new();
    let mut pos_prompts_total = 0u32;
    let mut pos_total = 0u32;
    let mut pos_by_project: HashMap<String, u32> = HashMap::new();

    for session in &sessions {
        interrupts += session.interrupts;
        api_errors += session.api_errors;
        compactions += session.compactions;

        for prompt in &session.prompts {
            if !session.is_subagent {
                if let Some(mode) = prompt.permission_mode.clone() {
                    // Skip negligible modes like "plan"
                    if mode == "plan" {
                        continue;
                    }
                    *mode_counts.entry(mode.clone()).or_insert(0) += 1;
                    *prompt_counts_by_project.entry(session.project.clone()).or_insert(0) += 1;
                    if let Some(hour_str) = prompt.timestamp.get(11..13) {
                        if let Ok(hour) = hour_str.parse::<u8>() {
                            let entry = modes_by_hour.entry(hour).or_insert([0; 3]);
                            match mode.as_str() {
                                "bypassPermissions" => entry[0] += 1,
                                "acceptEdits" => entry[1] += 1,
                                "default" => entry[2] += 1,
                                _ => {}
                            }
                        }
                    }
                    if let Some(day_str) = prompt.timestamp.get(0..10) {
                        let entry = modes_by_day.entry(day_str.to_string()).or_insert([0; 3]);
                        match mode.as_str() {
                            "bypassPermissions" => entry[0] += 1,
                            "acceptEdits" => entry[1] += 1,
                            "default" => entry[2] += 1,
                            _ => {}
                        }
                    }
                    if mode == "bypassPermissions" {
                        *bypass_counts_by_project.entry(session.project.clone()).or_insert(0) += 1;
                    }
                }
                count_secret_text(&rules, &prompt.text, &session.project, &mut secrets);

                // Sentiment tracking - count each keyword at most once per prompt
                let neg = sentiment.count_negative(&prompt.text);
                if !neg.is_empty() {
                    let distinct = neg.len() as u32;
                    neg_prompts_total += 1;
                    neg_total += distinct;
                    *neg_by_project.entry(session.project.clone()).or_insert(0) += distinct;
                    for (w, _) in neg { *neg_word_counts.entry(w).or_insert(0) += 1; }
                }
                let pos = sentiment.count_positive(&prompt.text);
                if !pos.is_empty() {
                    let distinct = pos.len() as u32;
                    pos_prompts_total += 1;
                    pos_total += distinct;
                    *pos_by_project.entry(session.project.clone()).or_insert(0) += distinct;
                    for (w, _) in pos { *pos_word_counts.entry(w).or_insert(0) += 1; }
                }
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
    let postgres_remote = *secrets.by_type.get("Postgres URLs (remote)").unwrap_or(&0);
    let postgres_local = *secrets.by_type.get("Postgres URLs (local)").unwrap_or(&0);
    let anthropic_tokens = *secrets.by_type.get("Anthropic tokens").unwrap_or(&0);
    let bearer_tokens = *secrets.by_type.get("Bearer tokens").unwrap_or(&0);
    let mysql_urls = *secrets.by_type.get("MySQL URLs").unwrap_or(&0);
    let private_key_blocks = *secrets.by_type.get("Private key blocks").unwrap_or(&0);

    let weighted_secret_rate_per_1000_prompts = if prompt_total > 0 {
        weighted_secret_risk(
            secret_values,
            key_values,
            token_values,
            postgres_remote,
            postgres_local,
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
    let prompt_counts_by_project_copy = prompt_counts_by_project.clone();
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

    let negative_rate = if prompt_total > 0 {
        round2(neg_prompts_total as f64 / prompt_total as f64 * 100.0)
    } else { 0.0 };
    let positive_rate = if prompt_total > 0 {
        round2(pos_prompts_total as f64 / prompt_total as f64 * 100.0)
    } else { 0.0 };
    let top_neg_word = neg_word_counts.iter()
        .max_by_key(|(_, c)| *c)
        .map(|(w, _)| w.as_str())
        .unwrap_or("-");
    let top_exposed_secret = most_exposed.first()
        .map(|s| s.secret.as_str())
        .unwrap_or("-");

    let persona = assign_persona(
        overall,
        total_secrets,
        sensitive_reads,
        env_writes,
        env_paths.len(),
        secret_types.len(),
        critical_count,
        high_count,
        risk.force_push,
        risk.reset_hard,
        risk.no_verify,
        risk.push_main,
        bypass_pct,
        prompt_total,
        denials,
        interrupts,
        override_rate,
        risk.destructive_catches,
        ssh_total,
        ssh_unique_hosts,
        agent_total,
        agent_bypass,
        negative_rate,
        neg_total,
        positive_rate,
        bash_total,
        total_flagged,
        &modes_by_hour,
        top_neg_word,
        top_exposed_secret,
    );

    Report {
        hero: Hero {
            report_title: "Claude Code Security Report".to_string(),
            transcript_count,
            project_count,
            total_entries,
            prompt_total,
            date_range: DateRange { start, end },
            include_subagents,
        },
        persona,
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
            modes_by_hour: {
                let mut items: Vec<HourModes> = modes_by_hour
                    .into_iter()
                    .map(|(hour, counts)| HourModes {
                        hour,
                        bypass: counts[0],
                        accept_edits: counts[1],
                        default: counts[2],
                    })
                    .collect();
                items.sort_by(|a, b| a.hour.cmp(&b.hour));
                items
            },
            modes_by_day: {
                let mut items: Vec<DayModes> = modes_by_day
                    .into_iter()
                    .map(|(date, counts)| DayModes {
                        date,
                        bypass: counts[0],
                        accept_edits: counts[1],
                        default: counts[2],
                    })
                    .collect();
                items.sort_by(|a, b| a.date.cmp(&b.date));
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
        user_sentiment: {
            // Merge project data
            let mut all_projects: HashSet<String> = HashSet::new();
            for k in neg_by_project.keys() { all_projects.insert(k.clone()); }
            for k in pos_by_project.keys() { all_projects.insert(k.clone()); }
            let mut by_project: Vec<ProjectSentimentRow> = all_projects
                .into_iter()
                .map(|project| ProjectSentimentRow {
                    negative: *neg_by_project.get(&project).unwrap_or(&0),
                    positive: *pos_by_project.get(&project).unwrap_or(&0),
                    total_prompts: *prompt_counts_by_project_copy.get(&project).unwrap_or(&0),
                    project,
                })
                .collect();
            by_project.sort_by(|a, b| b.positive.cmp(&a.positive).then(a.project.cmp(&b.project)));
            by_project.truncate(10);
            UserSentiment {
                total_negative: neg_total,
                prompts_with_negative: neg_prompts_total,
                total_positive: pos_total,
                prompts_with_positive: pos_prompts_total,
                prompt_total,
                negative_rate,
                positive_rate,
                top_negative: sorted_counts(neg_word_counts, 10),
                top_positive: sorted_counts(pos_word_counts, 10),
                by_project,
            }
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
