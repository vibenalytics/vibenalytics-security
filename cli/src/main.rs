mod security;
mod transcripts;

use anyhow::Result;
use clap::Parser;
use std::fs;
use std::path::PathBuf;

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
    let out_dir = if let Some(ref json_out) = cli.json_out {
        json_out.parent().unwrap_or(std::path::Path::new(".")).to_path_buf()
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join("Documents").join("vibenalytics-security")
    } else {
        PathBuf::from(".")
    };
    fs::create_dir_all(&out_dir)?;

    // Write report.json
    let json_out = out_dir.join("report.json");
    fs::write(&json_out, &json)?;
    if !cli.quiet {
        eprintln!("[4/4] wrote report to {}", json_out.display());
    }

    // Write self-contained report.html with data embedded
    let html_template = include_str!("../../ui/security-metrics-dev-brand-sections.html");
    let html = html_template.replace(
        "fetch(dataUrl)\n      .then(r => { if (!r.ok) throw new Error(`Failed to load ${dataUrl}: ${r.status}`); return r.json(); })\n      .then(render)",
        &format!("Promise.resolve({}).then(render)", json),
    );
    let html_out = out_dir.join("report.html");
    fs::write(&html_out, &html)?;
    if !cli.quiet {
        eprintln!("      wrote report.html to {}", html_out.display());
    }

    if cli.json {
        println!("{json}");
    }

    // Open the report in the browser
    #[cfg(target_os = "macos")]
    { let _ = std::process::Command::new("open").arg(&html_out).spawn(); }
    #[cfg(target_os = "linux")]
    { let _ = std::process::Command::new("xdg-open").arg(&html_out).spawn(); }
    #[cfg(target_os = "windows")]
    { let _ = std::process::Command::new("explorer").arg(&html_out).spawn(); }

    Ok(())
}
