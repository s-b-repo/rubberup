use daemonize::Daemonize;
use regex::Regex;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::path::Path;

const LOG_FILES: &[&str] = &[
    "/var/log/syslog",
    "/var/log/kern.log",
    "/var/log/messages",
    "/var/log/auth.log",
    "/var/log/dmesg",
    "/var/log/debug",
];

const ERROR_KEYWORDS: &[&str] = &["error", "failed", "warning", "fail", "denied", "critical"];
const OUTPUT_LOG: &str = "/var/log/tuxsupport_errors.log";

fn monitor_logs() -> std::io::Result<()> {
    // Check which log files exist.
    let valid_logs: Vec<&str> = LOG_FILES
        .iter()
        .copied()
        .filter(|path| Path::new(path).is_file())
        .collect();
    if valid_logs.is_empty() {
        eprintln!("No valid log files to monitor.");
        return Ok(());
    }

    // Build a regex that matches any of the error keywords (case-insensitive).
    let pattern = format!(r"\b({})\b", ERROR_KEYWORDS.join("|"));
    let re = Regex::new(&pattern).expect("Invalid regex pattern");

    // Build the tail command: tail -Fq -n 0 <valid_log_files...>
    let mut cmd = Command::new("tail");
    cmd.args(&["-Fq", "-n", "0"]).args(&valid_logs);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("Failed to spawn tail process");

    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let reader = BufReader::new(stdout);

    // Open (or create) the output error log file for appending.
    let mut out_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(OUTPUT_LOG)?;

    // Read lines from the tail process and write those matching the pattern.
    for line_result in reader.lines() {
        let line = line_result.unwrap_or_default();
        if re.is_match(&line) {
            writeln!(out_file, "{}", line)?;
            out_file.flush()?;
        }
    }

    // If we ever exit the loop, kill the tail process.
    let _ = child.kill();
    Ok(())
}

fn main() {
    // Set up daemonization. The stdout/stderr of the daemon are redirected to files.
    let stdout = File::create("/tmp/log_monitor_daemon.out").unwrap();
    let stderr = File::create("/tmp/log_monitor_daemon.err").unwrap();

    let daemonize = Daemonize::new()
        .stdout(stdout)
        .stderr(stderr)
        .pid_file("/tmp/log_monitor_daemon.pid");

    match daemonize.start() {
        Ok(_) => {
            // Once daemonized, start monitoring.
            if let Err(e) = monitor_logs() {
                eprintln!("Error in monitor_logs: {}", e);
            }
        }
        Err(e) => eprintln!("Error, {}", e),
    }
}
