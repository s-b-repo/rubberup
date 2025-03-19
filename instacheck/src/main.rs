use clap::Parser;
use chrono::Local;
use std::fs::OpenOptions;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::Command;

/// Pacman package integrity checker and reinstaller
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
    /// Dry run: show changes but do not reinstall packages
    #[arg(long)]
    dry_run: bool,
    /// Log file path (default: pacman_check.log in current directory)
    #[arg(short, long, value_parser)]
    log: Option<PathBuf>,
}

fn main() {
    let args = Args::parse();
    let log_path = args.log.unwrap_or_else(|| PathBuf::from("pacman_check.log"));
    log_message(&log_path, "=== Starting pacman integrity check ===", args.verbose);

    let packages = get_installed_packages(args.verbose);
    let mut packages_to_fix = Vec::new();

    for pkg in packages {
        if args.verbose {
            println!("Checking package '{}'", pkg);
        }
        log_message(&log_path, &format!("Checking package '{}'", pkg), args.verbose);
        if package_has_mismatches(&pkg, args.verbose) {
            println!("-> Package '{}' has mismatched hashes.", pkg);
            log_message(&log_path, &format!("Package '{}' FAILED integrity check.", pkg), args.verbose);
            packages_to_fix.push(pkg);
        } else if args.verbose {
            println!("Package '{}' passed integrity check.", pkg);
        }
    }

    if packages_to_fix.is_empty() {
        println!("All packages passed integrity check.");
        log_message(&log_path, "All packages passed integrity check.", args.verbose);
        return;
    } else {
        println!("\nThe following packages have mismatches and will be reinstalled:");
        for pkg in &packages_to_fix {
            println!("  - {}", pkg);
        }
        log_message(&log_path, &format!("Packages to reinstall: {:?}", packages_to_fix), args.verbose);
    }

    // Ask for confirmation before proceeding
    println!("\nDo you want to proceed with reinstalling these packages? (y/N): ");
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read input");
    if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
        println!("Aborting operation.");
        log_message(&log_path, "User aborted the operation.", args.verbose);
        return;
    }

    if args.dry_run {
        println!("Dry-run mode enabled. No packages will be reinstalled.");
        log_message(&log_path, "Dry-run mode: no packages reinstalled.", args.verbose);
        return;
    }

    println!("\nReinstalling affected packages...");
    log_message(&log_path, "Starting package reinstallation...", args.verbose);
    for pkg in packages_to_fix {
        reinstall_package(&pkg, &log_path, args.verbose);
    }
    println!("Operation completed.");
    log_message(&log_path, "=== Operation completed ===", args.verbose);
}

/// Retrieves installed package names via `pacman -Qq`
fn get_installed_packages(verbose: bool) -> Vec<String> {
    let output = Command::new("pacman")
        .arg("-Qq")
        .output()
        .expect("Failed to execute pacman -Qq");
    if !output.status.success() && verbose {
        eprintln!("Error reading package list.");
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.lines().map(|l| l.to_string()).collect()
}

/// Checks package integrity with `pacman -Qk <package>`.
/// Returns true if any line indicates a FAILED hash for a file in /usr/lib/ or /lib/.
fn package_has_mismatches(package: &str, verbose: bool) -> bool {
    let output = Command::new("pacman")
        .args(&["-Qk", package])
        .output()
        .expect("Failed to execute pacman -Qk");
    let stdout = String::from_utf8_lossy(&output.stdout);
    if verbose {
        println!("Output for '{}':\n{}", package, stdout);
    }
    // Look for lines containing "FAILED" and a library path.
    stdout.lines().any(|line| {
        line.contains("FAILED") && (line.contains("/usr/lib/") || line.contains("/lib/"))
    })
}

/// Reinstalls a package using `pacman -S <package> --noconfirm`
fn reinstall_package(package: &str, log_path: &PathBuf, verbose: bool) {
    println!("Reinstalling package '{}'...", package);
    log_message(log_path, &format!("Reinstalling package '{}'", package), verbose);
    let status = Command::new("pacman")
        .args(&["-S", package, "--noconfirm"])
        .status()
        .expect("Failed to execute pacman -S");
    if !status.success() {
        eprintln!("Error: failed to reinstall package '{}'.", package);
        log_message(log_path, &format!("Error: failed to reinstall '{}'", package), verbose);
    }
}

/// Writes a log message to the given file with a timestamp.
/// If verbose is enabled, it also prints the message to stdout.
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
