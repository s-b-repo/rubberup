// main.rs
// Enterprise Rootkit Scanner
// Note: This scanner is designed for real-world use and includes additional security validations,
// robust error handling, and increased concurrency. Replace the placeholder signature URLs with
// actual public signature databases when deploying in production.

use regex::Regex;
use reqwest;
use serde::{Deserialize, Serialize};
use tokio;
use tokio::fs;
use walkdir::WalkDir;
use tracing::{info, warn, error};
use tracing_subscriber;
use anyhow::{Result, Context};
use futures::stream::{self, StreamExt};
use std::sync::Arc;
use std::path::Path;
use std::fs as stdfs;

/// --- Configuration Module ---
/// Instead of using clap, we now define a Config struct with default values.
mod config {
    use super::*;
    #[derive(Debug)]
    pub struct Config {
        /// URL to download Linux rootkit signatures (JSON array)
        pub linux_signatures_url: String,
        /// URL to download Windows rootkit signatures (JSON array)
        pub windows_signatures_url: String,
        /// Target directory to scan (do not set this to critical system directories)
        pub target_directory: String,
        /// Local file path to store merged signatures
        pub local_signatures_path: String,
        /// Override scanning of dangerous directories
        pub force_scan: bool,
    }
    
    impl Default for Config {
        fn default() -> Self {
            Self {
                linux_signatures_url: "https://raw.githubusercontent.com/enterprise/rootkit-signatures/main/linux.json".to_string(),
                windows_signatures_url: "https://raw.githubusercontent.com/enterprise/rootkit-signatures/main/windows.json".to_string(),
                target_directory: "/var/log".to_string(),
                local_signatures_path: "local_signatures.json".to_string(),
                force_scan: false,
            }
        }
    }
    
    impl Config {
        /// Validate configuration for production hardening.
        pub fn validate(&self) -> Result<(), String> {
            // Check if the target directory is one of the dangerous ones.
            let dangerous_dirs = ["/", "/boot", "/sys", "/proc"];
            let canonical = stdfs::canonicalize(&self.target_directory)
                .map_err(|e| format!("Failed to canonicalize target directory: {}", e))?;
            let target_str = canonical.to_str().unwrap_or_default();
            if dangerous_dirs.iter().any(|&dir| target_str == dir) && !self.force_scan {
                return Err(format!("Target directory '{}' is dangerous. Enable force_scan to override.", target_str));
            }
            Ok(())
        }
    }
}

/// --- Signature Management Module ---
mod signature {
    use super::*;
    
    #[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
    pub struct Signature {
        pub name: String,
        pub pattern: String,
    }
    
    /// Download rootkit signatures from a given URL.
    pub async fn download_signatures_from_url(url: &str) -> Result<Vec<Signature>> {
        info!("Downloading signatures from {}", url);
        let resp = reqwest::get(url)
            .await
            .context(format!("Failed to download signatures from {}", url))?
            .json::<Vec<Signature>>()
            .await
            .context(format!("Failed to parse JSON from {}", url))?;
        Ok(resp)
    }
    
    /// Download signatures from multiple URLs.
    pub async fn download_all_signatures(urls: &[&str]) -> Result<Vec<Signature>> {
        let mut all_signatures = Vec::new();
        for url in urls {
            match download_signatures_from_url(url).await {
                Ok(mut sigs) => {
                    info!("Downloaded {} signatures from {}", sigs.len(), url);
                    all_signatures.append(&mut sigs);
                },
                Err(e) => {
                    warn!("Error downloading from {}: {}", url, e);
                }
            }
        }
        Ok(all_signatures)
    }
    
    /// Load local signatures from a JSON file, if it exists.
    pub fn load_local_signatures<P: AsRef<Path>>(path: P) -> Result<Vec<Signature>> {
        if path.as_ref().exists() {
            let data = stdfs::read_to_string(&path)
                .context("Failed to read local signatures file")?;
            let sigs = serde_json::from_str::<Vec<Signature>>(&data)
                .context("Failed to parse local signatures JSON")?;
            Ok(sigs)
        } else {
            Ok(Vec::new())
        }
    }
    
    /// Save the provided signatures to a local JSON file atomically.
    pub fn save_local_signatures<P: AsRef<Path>>(path: P, signatures: &[Signature]) -> Result<()> {
        let data = serde_json::to_string_pretty(signatures)
            .context("Failed to serialize signatures")?;
        // Write to a temporary file first for atomic update.
        let temp_path = path.as_ref().with_extension("tmp");
        stdfs::write(&temp_path, data)
            .context("Failed to write signatures to temporary file")?;
        stdfs::rename(temp_path, path)
            .context("Failed to rename temporary signatures file")?;
        Ok(())
    }
    
    /// Merge new signatures with the local signature store, avoiding duplicates by name.
    pub fn update_local_signatures<P: AsRef<Path>>(local_path: P, new_sigs: Vec<Signature>) -> Result<Vec<Signature>> {
        let mut local_sigs = load_local_signatures(&local_path)?;
        let initial_count = local_sigs.len();
        for new_sig in new_sigs.into_iter() {
            if !local_sigs.iter().any(|s| s.name == new_sig.name) {
                info!("Adding new signature: {}", new_sig.name);
                local_sigs.push(new_sig);
            }
        }
        if local_sigs.len() > initial_count {
            save_local_signatures(&local_path, &local_sigs)?;
            info!("Local signatures updated. Total signatures: {}", local_sigs.len());
        } else {
            info!("No new signatures found. Local signature store remains unchanged.");
        }
        Ok(local_sigs)
    }
}

/// --- Scanner Module ---
mod scanner {
    use super::*;
    use futures::stream::{self, StreamExt};
    use std::path::PathBuf;
    
    /// Asynchronously scan the given directory for files matching any provided signature regex.
    pub async fn scan_directory(dir: &str, signatures: &[(signature::Signature, Regex)]) -> Result<Vec<String>> {
        let mut alerts = Vec::new();
        
        // Recursively collect file paths using WalkDir.
        let file_paths: Vec<PathBuf> = WalkDir::new(dir)
            .max_depth(10)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| {
                match e {
                    Ok(entry) if entry.depth() <= 10 && entry.metadata().map(|m| m.is_file()).unwrap_or(false) => {
                        Some(entry.path().to_path_buf())
                    },
                    Err(e) => {
                        warn!("Failed to access a directory entry: {}", e);
                        None
                    }
                    _ => None,
                }
            })
            .collect();
        
        info!("Found {} files in '{}'", file_paths.len(), dir);
        
        // Share the compiled signatures with tasks.
        let sigs = Arc::new(signatures.to_vec());
        let concurrency_limit = 20; // Increased for enterprise scanning
        
        let results = stream::iter(file_paths)
            .map(|path| {
                let sigs = sigs.clone();
                async move {
                    let path_display = path.display().to_string();
                    match fs::read_to_string(&path).await {
                        Ok(content) => {
                            let mut file_alerts = Vec::new();
                            for (sig, re) in sigs.iter() {
                                if re.is_match(&content) {
                                    file_alerts.push(format!(
                                        "ALERT: File '{}' matches signature '{}' (pattern: {})",
                                        path_display, sig.name, sig.pattern
                                    ));
                                }
                            }
                            Ok(file_alerts)
                        },
                        Err(e) => {
                            warn!("Failed to read file {}: {}", path_display, e);
                            Ok(vec![])
                        }
                    }
                }
            })
            .buffer_unordered(concurrency_limit)
            .collect::<Vec<Result<Vec<String>>>>()
            .await;
        
        for res in results {
            match res {
                Ok(mut alerts_for_file) => alerts.append(&mut alerts_for_file),
                Err(e) => warn!("Error during file scanning: {}", e),
            }
        }
        Ok(alerts)
    }
}

/// --- Main Application Entry Point ---
/// This version uses the default configuration rather than parsing command-line flags.
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize structured logging.
    tracing_subscriber::fmt::init();
    
    // Use default configuration.
    let config = config::Config::default();
    if let Err(e) = config.validate() {
        error!("Invalid configuration: {}", e);
        return Err(anyhow::anyhow!(e));
    }
    
    info!("Starting Enterprise Rootkit Scanner...");
    
    // Define the signature database URLs.
    let signature_urls = [
        &config.linux_signatures_url as &str,
        &config.windows_signatures_url as &str,
    ];
    
    // Download remote signatures concurrently.
    let remote_signatures = signature::download_all_signatures(&signature_urls).await?;
    
    // Update the local signature store with new entries.
    let updated_signatures = signature::update_local_signatures(&config.local_signatures_path, remote_signatures)?;
    
    // Compile regex patterns and log any invalid entries.
    let mut compiled_signatures = Vec::new();
    for sig in updated_signatures.iter() {
        match Regex::new(&sig.pattern) {
            Ok(re) => compiled_signatures.push((sig.clone(), re)),
            Err(e) => warn!("Invalid regex for signature '{}': {}. Skipping this signature.", sig.name, e),
        }
    }
    
    // Ensure at least one valid signature is available.
    if compiled_signatures.is_empty() {
        error!("No valid signatures available. Aborting scan for security reasons.");
        return Err(anyhow::anyhow!("No valid signatures to scan with."));
    }
    
    // Scan the target directory.
    info!("Scanning directory '{}' for rootkit signatures...", config.target_directory);
    let alerts = scanner::scan_directory(&config.target_directory, &compiled_signatures).await?;
    
    // Report scan results.
    if alerts.is_empty() {
        info!("No rootkit signatures detected.");
    } else {
        info!("Detected {} potential rootkit signatures:", alerts.len());
        for alert in alerts {
            println!("{}", alert);
        }
    }
    
    Ok(())
}
