use clap::Parser;
use chrono::Local;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;
use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use rayon::prelude::*;

/// Enterprise-level system integrity checker for packages and critical system files.
/// This tool scans every installed package (including libraries and dependencies)
/// using pacman’s built-in file integrity check. If any package fails its integrity
/// check, the tool automatically reinstalls it (unless dry-run mode is enabled).
/// In parallel, it computes SHA256 hashes for every file in critical directories
/// (default: /etc, /usr/bin, /usr/lib, /lib) and compares them against a provided baseline,
/// logging every computed hash or mismatch.
#[derive(Parser, Debug)]
#[command(
    name = "intacheck",
    author,
    version,
    about,
    long_about = None
)]
struct Args {
    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
    /// Dry run: show changes but do not reinstall packages or update baselines
    #[arg(long)]
    dry_run: bool,
    /// Log file path (default: /var/log/intacheck.log)
    #[arg(short, long, value_parser)]
    log: Option<PathBuf>,
    /// Baseline JSON file for system file integrity (maps file paths to expected SHA256 hash)
    #[arg(short, long, value_parser)]
    baseline: Option<PathBuf>,
    /// Comma-separated list of directories to scan for system file integrity.
    /// If not provided, defaults to: /etc,/usr/bin,/usr/lib,/lib
    #[arg(short, long, value_parser)]
    dirs: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Baseline {
    files: HashMap<String, String>, // file path -> expected hash
}

fn main() {
    let args = Args::parse();
    let log_path = args.log.unwrap_or_else(|| PathBuf::from("/var/log/intacheck.log"));

    // Log start of operation.
    log_message(&log_path, "=== Starting complete system integrity check ===", args.verbose);

    // 1. Package Integrity Check
    // Retrieve the full list of installed packages (this includes libraries, dependencies, etc.).
    let packages = get_installed_packages(args.verbose);
    let mut packages_to_fix = Vec::new();

    for pkg in &packages {
        if args.verbose {
            println!("Performing integrity check on package '{}'", pkg);
        }
        log_message(&log_path, &format!("Checking package '{}'", pkg), args.verbose);
        if package_has_mismatches(pkg, args.verbose) {
            log_message(&log_path, &format!("Integrity check FAILED for package '{}'", pkg), args.verbose);
            packages_to_fix.push(pkg.clone());
        }
    }

    if packages_to_fix.is_empty() {
        println!("All packages passed integrity check.");
        log_message(&log_path, "All packages passed integrity check.", args.verbose);
    } else {
        println!("Automatically reinstalling packages with integrity mismatches...");
        log_message(&log_path, &format!("Reinstalling packages: {:?}", packages_to_fix), args.verbose);
        for pkg in packages_to_fix {
            if args.dry_run {
                println!("Dry-run mode: {} would be reinstalled.", pkg);
                log_message(&log_path, &format!("Dry-run: {} would be reinstalled.", pkg), args.verbose);
            } else {
                reinstall_package(&pkg, &log_path, args.verbose);
            }
        }
    }

    // 2. System File Integrity Check
    // Load the baseline if provided; otherwise, operate in full reporting mode.
    let baseline = if let Some(baseline_path) = args.baseline {
        match load_baseline(&baseline_path, args.verbose) {
            Ok(b) => Some(b),
            Err(e) => {
                eprintln!("Error loading baseline file: {}", e);
                log_message(&log_path, &format!("Error loading baseline file: {}", e), args.verbose);
                None
            }
        }
    } else {
        None
    };

    // Determine directories to scan; use defaults if not provided.
    let directories: Vec<&str> = if let Some(dirs_str) = args.dirs {
        dirs_str.split(',').map(|s| s.trim()).collect()
    } else {
        vec!["/etc", "/usr/bin", "/usr/lib", "/lib"]
    };

    let system_mismatches = check_system_files_integrity(&directories, baseline.as_ref(), args.verbose, &log_path);
    if system_mismatches.is_empty() {
        println!("All system files passed integrity check.");
        log_message(&log_path, "All system files passed integrity check.", args.verbose);
    } else {
        println!("The following system files have integrity mismatches:");
        for file in system_mismatches {
            println!("  - {}", file);
        }
        log_message(&log_path, "System file mismatches detected.", args.verbose);
    }

    println!("Operation completed.");
    log_message(&log_path, "=== Operation completed ===", args.verbose);
}

/// Retrieves installed package names using `pacman -Qq`.
fn get_installed_packages(verbose: bool) -> Vec<String> {
    let output = Command::new("pacman")
        .arg("-Qq")
        .output()
        .unwrap_or_else(|err| {
            panic!("Failed to execute pacman -Qq: {}", err);
        });
    if !output.status.success() && verbose {
        eprintln!("Error reading package list from pacman.");
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.lines().map(|l| l.to_string()).collect()
}

/// Checks package integrity using `pacman -Qkk <package>`.
/// Returns true if any file in the package fails its integrity check.
fn package_has_mismatches(package: &str, verbose: bool) -> bool {
    let output = Command::new("pacman")
        .args(&["-Qkk", package])
        .output()
        .unwrap_or_else(|err| {
            panic!("Failed to execute pacman -Qkk for {}: {}", package, err);
        });
    let stdout = String::from_utf8_lossy(&output.stdout);
    if verbose {
        println!("Integrity check output for '{}':\n{}", package, stdout);
    }
    stdout.lines().any(|line| line.contains("FAILED"))
}

/// Reinstalls a package using `pacman -S <package> --noconfirm` in a non-interactive manner.
fn reinstall_package(package: &str, log_path: &PathBuf, verbose: bool) {
    println!("Reinstalling package '{}'...", package);
    log_message(log_path, &format!("Reinstalling package '{}'", package), verbose);
    let status = Command::new("pacman")
        .args(&["-S", package, "--noconfirm"])
        .status()
        .unwrap_or_else(|err| {
            panic!("Failed to execute pacman -S for {}: {}", package, err);
        });
    if !status.success() {
        eprintln!("Error: failed to reinstall package '{}'.", package);
        log_message(log_path, &format!("Error: failed to reinstall package '{}'", package), verbose);
    }
}

/// Writes a log message to the given file with a timestamp.
fn log_message(log_path: &PathBuf, message: &str, verbose: bool) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
    let log_entry = format!("[{}] {}\n", timestamp, message);
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
        let _ = file.write_all(log_entry.as_bytes());
    }
    if verbose {
        println!("LOG: {}", log_entry.trim());
    }
}

/// Loads the baseline JSON file mapping file paths to expected hashes.
fn load_baseline(baseline_path: &PathBuf, verbose: bool) -> Result<Baseline, Box<dyn std::error::Error>> {
    let file = File::open(baseline_path)?;
    let reader = BufReader::new(file);
    let baseline: Baseline = serde_json::from_reader(reader)?;
    if verbose {
        println!("Loaded baseline with {} entries.", baseline.files.len());
    }
    Ok(baseline)
}

/// Computes the SHA256 hash of a file.
fn compute_file_hash<P: AsRef<Path>>(path: P) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = File::open(&path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 4096];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Checks system files integrity by comparing computed hashes with the provided baseline (if any).
/// In reporting mode (no baseline), the computed hash for each file is logged.
/// Uses Rayon to parallelize file hash computation for maximum efficiency.
/// Returns a list of file paths that do not match the expected hash.
fn check_system_files_integrity(
    directories: &[&str],
    baseline: Option<&Baseline>,
    verbose: bool,
    log_path: &PathBuf,
) -> Vec<String> {
    // Collect all file paths from the provided directories.
    let files: Vec<_> = directories.iter()
        .flat_map(|dir| {
            WalkDir::new(dir)
                .into_iter()
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.path().is_file())
                .map(|entry| entry.path().to_owned())
                .collect::<Vec<PathBuf>>()
        })
        .collect();

    // Process all files in parallel.
    let mismatches: Vec<String> = files.par_iter()
        .filter_map(|path| {
            match compute_file_hash(path) {
                Ok(computed_hash) => {
                    let path_str = path.to_string_lossy().to_string();
                    if let Some(baseline) = baseline {
                        if let Some(expected_hash) = baseline.files.get(&path_str) {
                            if &computed_hash != expected_hash {
                                let log_msg = format!(
                                    "Mismatch for {}: expected {}, got {}",
                                    path_str, expected_hash, computed_hash
                                );
                                log_message(log_path, &log_msg, verbose);
                                return Some(path_str);
                            }
                        } else if verbose {
                            println!("File {} not present in baseline.", path_str);
                        }
                    } else {
                        // Reporting mode: log every computed hash.
                        log_message(log_path, &format!("{}: {}", path_str, computed_hash), verbose);
                    }
                    None
                },
                Err(e) => {
                    let error_msg = format!("Error computing hash for {:?}: {}", path, e);
                    eprintln!("{}", error_msg);
                    log_message(log_path, &error_msg, verbose);
                    None
                }
            }
        })
        .collect();

    mismatches
}
