mod security;
mod transcripts;

use anyhow::Result;
use clap::Parser;
use std::fs;
use std::path::PathBuf;

fn default_json_out() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ui/report.json")
}

#[derive(Parser, Debug)]
#[command(
    name = "vibenalytics-security",
    about = "One-shot security analysis for Claude Code transcripts",
    version
)]
struct Cli {
    /// Path to ~/.claude/projects
    #[arg(long, default_value = "~/.claude/projects")]
    projects_dir: String,

    /// Write JSON report to this path
    #[arg(long)]
    json_out: Option<PathBuf>,

    /// Print JSON report to stdout
    #[arg(long, default_value_t = false)]
    json: bool,

    /// Suppress progress status lines
    #[arg(long, default_value_t = false)]
    quiet: bool,
}

fn expand_home(input: &str) -> String {
    if let Some(rest) = input.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest).to_string_lossy().to_string();
        }
    }
    input.to_string()
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let projects_dir = expand_home(&cli.projects_dir);
    let include_subagents = true;

    if !cli.quiet {
        eprintln!("[1/4] discovering transcript files in {}", projects_dir);
    }
    let sessions = transcripts::discover_sessions(&projects_dir, include_subagents)?;
    if !cli.quiet {
        eprintln!(
            "[2/4] parsing {} transcript files{}",
            sessions.len(),
            " (including subagents)"
        );
    }

    let parsed = transcripts::parse_sessions(sessions)?;
    if !cli.quiet {
        eprintln!("[3/4] analyzing {} parsed sessions", parsed.len());
    }
    let analysis = security::analyze(parsed, include_subagents);

    let json = serde_json::to_string_pretty(&analysis)?;
    let json_out = cli.json_out.clone().unwrap_or_else(default_json_out);

    if let Some(parent) = json_out.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&json_out, &json)?;
    if !cli.quiet {
        eprintln!("[4/4] wrote JSON report to {}", json_out.display());
    }

    if cli.json {
        if !cli.quiet {
            eprintln!("[4/4] printing JSON report to stdout");
        }
        println!("{json}");
    }

    Ok(())
}
