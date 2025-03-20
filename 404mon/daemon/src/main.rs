use daemonize::Daemonize;
use regex::Regex;
use std::fs::{OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

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
    // Filter valid log files.
    let valid_logs: Vec<&str> = LOG_FILES
        .iter()
        .copied()
        .filter(|path| Path::new(path).is_file())
        .collect();

    if valid_logs.is_empty() {
        eprintln!("No valid log files to monitor.");
        return Ok(());
    }

    // Build a regex to match any error keyword (case-insensitive).
    let pattern = format!(r"\b({})\b", ERROR_KEYWORDS.join("|"));
    let re = Regex::new(&pattern).expect("Failed to compile regex");

    // Spawn a tail process that follows all valid log files.
    // The "-F" option tells tail to follow by name (handling log rotation) and "-n 0" avoids old lines.
    let mut cmd = Command::new("tail");
    cmd.args(&["-Fq", "-n", "0"]).args(&valid_logs);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("Failed to spawn tail process");

    // Wrap the stdout in a BufReader for line-by-line reading.
    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let reader = BufReader::new(stdout);

    // Open or create the output log file for appending.
    let mut out_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(OUTPUT_LOG)?;

    // Process each new line.
    for line_result in reader.lines() {
        let line = line_result.unwrap_or_default();
        if re.is_match(&line) {
            writeln!(out_file, "{}", line)?;
            out_file.flush()?;
        }
    }

    // In case the loop ever ends, kill the tail process.
    let _ = child.kill();
    Ok(())
}

fn main() {
    // Prepare output files for logging daemon stdout/stderr.
    let stdout = std::fs::File::create("/tmp/daemon.out").unwrap();
    let stderr = std::fs::File::create("/tmp/daemon.err").unwrap();

    // Daemonize the process.
    let daemonize = Daemonize::new()
        .stdout(stdout)
        .stderr(stderr)
        .pid_file("/tmp/daemon.pid");

    match daemonize.start() {
        Ok(_) => {
            if let Err(e) = monitor_logs() {
                eprintln!("Error in monitor_logs: {}", e);
            }
        }
        Err(e) => eprintln!("Error, {}", e),
    }
}
