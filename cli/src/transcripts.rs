use anyhow::{Context, Result};
use regex::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SessionFile {
    pub project: String,
    pub path: PathBuf,
    pub is_subagent: bool,
}

#[derive(Debug, Clone)]
pub struct ToolCall {
    pub id: String,
    pub timestamp: String,
    pub name: String,
    pub input: Value,
    pub permission_mode: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ToolResult {
    pub tool_use_id: String,
    pub tool_name: String,
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct UserPrompt {
    pub timestamp: String,
    pub text: String,
    pub permission_mode: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AssistantText {
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct ParsedSession {
    pub project: String,
    pub is_subagent: bool,
    pub started_at: String,
    pub ended_at: String,
    pub event_count: u32,
    pub prompts: Vec<UserPrompt>,
    pub tool_calls: Vec<ToolCall>,
    pub tool_results: Vec<ToolResult>,
    pub assistant_texts: Vec<AssistantText>,
    pub interrupts: u32,
    pub api_errors: u32,
    pub compactions: u32,
}

fn collect_jsonl_recursive(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("read_dir {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_jsonl_recursive(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
            out.push(path);
        }
    }
    Ok(())
}

fn project_name_from_cwd(cwd: &str) -> String {
    let parts: Vec<&str> = cwd
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let skip = &["Users", "Documents"];
    let home_user = std::env::var("USER").unwrap_or_default();
    let meaningful: Vec<&str> = parts
        .iter()
        .filter(|s| !skip.contains(s) && **s != home_user)
        .copied()
        .collect();
    if meaningful.is_empty() {
        cwd.to_string()
    } else {
        meaningful[meaningful.len().saturating_sub(2)..].join("/")
    }
}

fn dir_name_fallback(dir_name: &str) -> String {
    dir_name.to_string()
}

fn read_cwd_from_jsonl(path: &Path) -> Option<String> {
    let reader = BufReader::new(fs::File::open(path).ok()?);
    for line in reader.lines() {
        let line = line.ok()?;
        if line.trim().is_empty() { continue; }
        let evt: Value = serde_json::from_str(&line).ok()?;
        if let Some(cwd) = evt.get("cwd").and_then(|v| v.as_str()) {
            if !cwd.is_empty() {
                return Some(cwd.to_string());
            }
        }
    }
    None
}

pub fn discover_sessions(projects_dir: &str, include_subagents: bool) -> Result<Vec<SessionFile>> {
    let root = Path::new(projects_dir);
    let mut out = Vec::new();

    for entry in fs::read_dir(root).with_context(|| format!("read_dir {}", root.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let dir_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("unknown");
        let mut files = Vec::new();
        collect_jsonl_recursive(&path, &mut files)?;

        // Read cwd from the first main session file to derive the project name
        let cwd = files
            .iter()
            .find(|f| !f.to_string_lossy().contains("/subagents/agent-"))
            .and_then(|f| read_cwd_from_jsonl(f));
        let project = match &cwd {
            Some(c) => project_name_from_cwd(c),
            None => dir_name_fallback(dir_name),
        };

        for file in files {
            let file_str = file.to_string_lossy();
            let is_subagent = file_str.contains("/subagents/agent-");
            if !include_subagents && is_subagent {
                continue;
            }
            out.push(SessionFile { project: project.clone(), path: file, is_subagent });
        }
    }

    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

fn is_real_user_prompt(text: &str) -> bool {
    let trimmed = text.trim();
    let lower = trimmed.to_ascii_lowercase();

    !trimmed.is_empty()
        && !trimmed.starts_with("<local-command")
        && !trimmed.starts_with("<bash-")
        && !trimmed.starts_with("/plugin")
        && !trimmed.starts_with("<command-name>")
        && !trimmed.starts_with("<command-message>")
        && !trimmed.starts_with("<task-notification")
        && !trimmed.starts_with("<system-reminder>")
        && trimmed != "Warmup"
        && !lower.starts_with("[suggestion mode:")
        && !lower.starts_with("this session is being continued from a previous conversation")
        && !lower.starts_with("critical: respond with text only. do not call any tools.")
        && !lower.starts_with("your task is to create a detailed summary of the conversation so far")
        && !lower.starts_with("your task is to compact the conversation")
        && !lower.starts_with("you are resuming a previously interrupted conversation summary")
        && !lower.starts_with("unknown skill:")
}

fn text_from_content(content: &Value) -> String {
    match content {
        Value::String(s) => s.clone(),
        Value::Array(items) => items.iter().map(text_from_content).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" "),
        Value::Object(map) => {
            if map.get("type").and_then(|v| v.as_str()) == Some("text") {
                map.get("text").and_then(|v| v.as_str()).unwrap_or("").to_string()
            } else {
                map.values().map(text_from_content).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ")
            }
        }
        _ => String::new(),
    }
}

fn parse_session(file: &SessionFile) -> Result<Option<ParsedSession>> {
    let reader = BufReader::new(fs::File::open(&file.path).with_context(|| format!("open {}", file.path.display()))?);

    let interrupt_re = Regex::new(r"\[Request interrupted by user").unwrap();

    let mut session_id = String::new();
    let mut started_at = String::new();
    let mut ended_at = String::new();
    let mut prompts = Vec::new();
    let mut tool_calls = Vec::new();
    let mut tool_results = Vec::new();
    let mut assistant_texts = Vec::new();
    let mut event_count = 0u32;
    let mut seen_user_messages = HashSet::new();
    let mut seen_tool_ids = HashSet::new();
    let mut current_permission_mode: Option<String> = None;
    let mut tool_name_by_id: HashMap<String, String> = HashMap::new();
    let mut interrupts = 0u32;
    let mut api_errors = 0u32;
    let mut compactions = 0u32;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let evt: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        event_count += 1;

        let ts = evt.get("timestamp").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if !ts.is_empty() {
            if started_at.is_empty() || ts < started_at {
                started_at = ts.clone();
            }
            if ended_at.is_empty() || ts > ended_at {
                ended_at = ts.clone();
            }
        }

        if session_id.is_empty() {
            session_id = evt.get("sessionId").and_then(|v| v.as_str()).unwrap_or("").to_string();
        }

        match evt.get("type").and_then(|v| v.as_str()).unwrap_or("") {
            "system" => {
                match evt.get("subtype").and_then(|v| v.as_str()).unwrap_or("") {
                    "api_error" => api_errors += 1,
                    "compact_boundary" => compactions += 1,
                    _ => {}
                }
            }
            "assistant" => {
                if evt.pointer("/message/model").and_then(|v| v.as_str()) == Some("<synthetic>") {
                    continue;
                }
                if let Some(content) = evt.pointer("/message/content").and_then(|v| v.as_array()) {
                    for block in content {
                        match block.get("type").and_then(|v| v.as_str()) {
                            Some("tool_use") => {
                                let tool_id = block.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                if !tool_id.is_empty() && !seen_tool_ids.insert(tool_id.clone()) {
                                    continue;
                                }
                                let tool_name = block.get("name").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                                tool_name_by_id.insert(tool_id.clone(), tool_name.clone());
                                tool_calls.push(ToolCall {
                                    id: tool_id,
                                    timestamp: ts.clone(),
                                    name: tool_name,
                                    input: block.get("input").cloned().unwrap_or(Value::Null),
                                    permission_mode: current_permission_mode.clone(),
                                });
                            }
                            Some("text") => {
                                let text = block.get("text").and_then(|v| v.as_str()).unwrap_or("");
                                if !text.is_empty() {
                                    assistant_texts.push(AssistantText { text: text.to_string() });
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            "user" => {
                let uuid = evt.get("uuid").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if !uuid.is_empty() && !seen_user_messages.insert(uuid) {
                    continue;
                }

                if let Some(pm) = evt.get("permissionMode").and_then(|v| v.as_str()) {
                    current_permission_mode = Some(pm.to_string());
                }

                match evt.pointer("/message/content") {
                    Some(Value::String(text)) => {
                        if interrupt_re.is_match(text) {
                            interrupts += 1;
                        }
                        if is_real_user_prompt(text) {
                            prompts.push(UserPrompt {
                                timestamp: ts.clone(),
                                text: text.clone(),
                                permission_mode: current_permission_mode.clone(),
                            });
                        }
                    }
                    Some(Value::Array(items)) => {
                        let mut has_tool_result = false;
                        for block in items {
                            if block.get("type").and_then(|v| v.as_str()) == Some("tool_result") {
                                has_tool_result = true;
                                let tool_use_id = block.get("tool_use_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                let text = text_from_content(block.get("content").unwrap_or(&Value::Null));
                                tool_results.push(ToolResult {
                                    tool_use_id: tool_use_id.clone(),
                                    tool_name: tool_name_by_id.get(&tool_use_id).cloned().unwrap_or_else(|| "unknown".to_string()),
                                    text,
                                });
                            }
                        }
                        // Handle text blocks in array-format user messages (interrupts + real prompts)
                        if !has_tool_result {
                            let combined: String = items
                                .iter()
                                .filter(|b| b.get("type").and_then(|v| v.as_str()) == Some("text"))
                                .filter_map(|b| b.get("text").and_then(|v| v.as_str()))
                                .collect::<Vec<_>>()
                                .join(" ");
                            if !combined.is_empty() {
                                if interrupt_re.is_match(&combined) {
                                    interrupts += 1;
                                }
                                if is_real_user_prompt(&combined) {
                                    prompts.push(UserPrompt {
                                        timestamp: ts.clone(),
                                        text: combined,
                                        permission_mode: current_permission_mode.clone(),
                                    });
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    if session_id.is_empty() {
        return Ok(None);
    }

    Ok(Some(ParsedSession {
        project: file.project.clone(),
        is_subagent: file.is_subagent,
        started_at,
        ended_at,
        event_count,
        prompts,
        tool_calls,
        tool_results,
        assistant_texts,
        interrupts,
        api_errors,
        compactions,
    }))
}

pub fn parse_sessions(files: Vec<SessionFile>) -> Result<Vec<ParsedSession>> {
    let mut out = Vec::new();
    for file in files {
        if let Some(session) = parse_session(&file)? {
            out.push(session);
        }
    }
    out.sort_by(|a, b| a.started_at.cmp(&b.started_at));
    Ok(out)
}
