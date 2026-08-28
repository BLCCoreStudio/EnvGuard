use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

use envguard::{scan_bytes, Finding};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    match parse_args(env::args().skip(1)) {
        Ok(ParseOutcome::Help) => print_help(),
        Ok(ParseOutcome::Version) => println!("envguard {VERSION}"),
        Ok(ParseOutcome::Run(config)) => match run(config) {
            Ok(code) => process::exit(code),
            Err(error) => {
                eprintln!("envguard: {error}");
                process::exit(2);
            }
        },
        Err(error) => {
            eprintln!("envguard: {error}");
            eprintln!("Try `envguard --help` for usage.");
            process::exit(2);
        }
    }
}

#[derive(Debug)]
struct Config {
    staged: bool,
    path: PathBuf,
}

enum ParseOutcome {
    Run(Config),
    Help,
    Version,
}

fn parse_args<I, S>(args: I) -> Result<ParseOutcome, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut staged = false;
    let mut path = None;

    for argument in args.into_iter().map(Into::into) {
        match argument.as_str() {
            "-h" | "--help" => return Ok(ParseOutcome::Help),
            "-V" | "--version" => return Ok(ParseOutcome::Version),
            "--staged" => staged = true,
            _ if argument.starts_with('-') => return Err(format!("unknown option: {argument}")),
            _ => {
                if path.is_some() {
                    return Err("only one scan path may be provided".into());
                }
                path = Some(PathBuf::from(argument));
            }
        }
    }

    if staged && path.is_some() {
        return Err("--staged scans the current Git repository and does not accept a path".into());
    }

    Ok(ParseOutcome::Run(Config {
        staged,
        path: path.unwrap_or_else(|| PathBuf::from(".")),
    }))
}

fn run(config: Config) -> Result<i32, String> {
    let mut findings = if config.staged {
        scan_staged_files()?
    } else {
        let mut findings = Vec::new();
        scan_path(&config.path, &mut findings).map_err(|error| {
            format!(
                "could not scan `{}`: {error}",
                config.path.to_string_lossy()
            )
        })?;
        findings
    };

    findings.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.line.cmp(&right.line))
            .then(left.rule.cmp(right.rule))
    });

    if findings.is_empty() {
        println!("EnvGuard: no potential secrets found.");
        return Ok(0);
    }

    eprintln!("EnvGuard found {} potential issue(s):", findings.len());
    for finding in &findings {
        print_finding(finding);
    }
    eprintln!("\nReview the findings before committing or publishing these files.");

    Ok(1)
}

fn scan_path(path: &Path, findings: &mut Vec<Finding>) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }

    if metadata.is_file() {
        let bytes = fs::read(path)?;
        findings.extend(scan_bytes(path, &bytes));
        return Ok(());
    }

    if !metadata.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let child = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() && should_skip_directory(&child) {
            continue;
        }

        scan_path(&child, findings)?;
    }

    Ok(())
}

fn should_skip_directory(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };

    matches!(
        name,
        ".git" | "target" | "node_modules" | ".venv" | "venv" | "dist" | "build"
    )
}

fn scan_staged_files() -> Result<Vec<Finding>, String> {
    let output = Command::new("git")
        .args([
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACMR",
            "-z",
        ])
        .output()
        .map_err(|error| format!("could not run git: {error}"))?;

    if !output.status.success() {
        return Err("git could not list staged files; run EnvGuard inside a Git repository".into());
    }

    let mut findings = Vec::new();
    for raw_path in output.stdout.split(|byte| *byte == 0) {
        if raw_path.is_empty() {
            continue;
        }

        let path = std::str::from_utf8(raw_path)
            .map_err(|_| "a staged path is not valid UTF-8 and cannot be scanned".to_string())?;
        let blob = Command::new("git")
            .args(["show", &format!(":{path}")])
            .output()
            .map_err(|error| format!("could not read staged file `{path}`: {error}"))?;

        if !blob.status.success() {
            return Err(format!("could not read staged file `{path}` from the Git index"));
        }

        findings.extend(scan_bytes(Path::new(path), &blob.stdout));
    }

    Ok(findings)
}

fn print_finding(finding: &Finding) {
    if finding.line == 0 {
        eprintln!("  {} [{}] {}", finding.path, finding.rule, finding.message);
    } else {
        eprintln!(
            "  {}:{} [{}] {}",
            finding.path, finding.line, finding.rule, finding.message
        );
    }
}

fn print_help() {
    println!(
        "EnvGuard {VERSION}\n\
Catch secrets and sensitive files before they reach Git.\n\
\n\
USAGE:\n\
    envguard [PATH]\n\
    envguard --staged\n\
\n\
OPTIONS:\n\
    --staged       Scan the exact file contents currently staged in Git\n\
    -h, --help     Print help\n\
    -V, --version  Print version\n\
\n\
EXIT CODES:\n\
    0  No findings\n\
    1  Potential secret or sensitive file found\n\
    2  Usage or scan error\n\
\n\
EXAMPLES:\n\
    envguard .\n\
    envguard ./config\n\
    envguard --staged"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_current_directory() {
        let ParseOutcome::Run(config) = parse_args(Vec::<String>::new()).unwrap() else {
            panic!("expected run configuration");
        };
        assert_eq!(config.path, PathBuf::from("."));
        assert!(!config.staged);
    }

    #[test]
    fn parses_staged_mode() {
        let ParseOutcome::Run(config) = parse_args(["--staged"]).unwrap() else {
            panic!("expected run configuration");
        };
        assert!(config.staged);
    }

    #[test]
    fn rejects_staged_mode_with_path() {
        let error = parse_args(["--staged", "config"]).err().unwrap();
        assert!(error.contains("does not accept a path"));
    }

    #[test]
    fn ignores_common_generated_directories() {
        assert!(should_skip_directory(Path::new("project/.git")));
        assert!(should_skip_directory(Path::new("project/node_modules")));
        assert!(!should_skip_directory(Path::new("project/src")));
    }
}
