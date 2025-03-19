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
use std::collections::HashMap;
use sha2::{Digest, Sha256};
use hex;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MalwareHash {
    pub name: String,
    pub sha256: String,
}

/// --- Configuration Module ---
mod config {
    use super::*;
    #[derive(Debug)]
    pub struct Config {
        /// URL to download the malware hash database (JSON array)
        pub malware_hashes_url: String,
        /// Target directory to scan (do not set this to critical system directories)
        pub target_directory: String,
        /// Local file path to store the downloaded malware hashes
        pub local_hashes_path: String,
        /// Override scanning of dangerous directories
        pub force_scan: bool,
    }
    
    impl Default for Config {
        fn default() -> Self {
            Self {
                // Replace the URL below with the actual endpoint of the biggest public malware hash DB.
                malware_hashes_url: "https://example.com/malware_hashes.json".to_string(),
                target_directory: "/var/log".to_string(),
                local_hashes_path: "local_hashes.json".to_string(),
                force_scan: false,
            }
        }
    }
    
    impl Config {
        /// Validate configuration for production hardening.
        pub fn validate(&self) -> Result<(), String> {
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

/// --- Malware Hash Management Module ---
mod hashdb {
    use super::*;
    
    /// Download malware hashes from a given URL.
    pub async fn download_hashes_from_url(url: &str) -> Result<Vec<MalwareHash>> {
        info!("Downloading malware hashes from {}", url);
        let resp = reqwest::get(url)
            .await
            .context(format!("Failed to download hashes from {}", url))?
            .json::<Vec<MalwareHash>>()
            .await
            .context(format!("Failed to parse JSON from {}", url))?;
        Ok(resp)
    }
    
    /// Download malware hashes from the provided URL.
    pub async fn get_malware_hashes(url: &str) -> Result<Vec<MalwareHash>> {
        download_hashes_from_url(url).await
    }
}

/// --- Scanner Module ---
mod scanner {
    use super::*;
    
    /// Asynchronously scan the given directory for malware by computing SHA256 hashes.
    pub async fn scan_directory_for_hashes(
        dir: &str,
        malware_hashes: &HashMap<String, String>,
    ) -> Result<Vec<String>> {
        let mut alerts = Vec::new();
        
        // Recursively collect file paths.
        let file_paths: Vec<_> = WalkDir::new(dir)
            .max_depth(10)
            .into_iter()
            .filter_map(|e| {
                if let Ok(entry) = e {
                    if entry.metadata().map(|m| m.is_file()).unwrap_or(false) {
                        Some(entry.path().to_path_buf())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();
        
        info!("Found {} files in '{}'", file_paths.len(), dir);
        
        let concurrency_limit = 20;
        
        let results = stream::iter(file_paths)
            .map(|path| {
                let malware_hashes = malware_hashes.clone();
                async move {
                    let path_display = path.display().to_string();
                    match fs::read(&path).await {
                        Ok(contents) => {
                            let mut hasher = Sha256::new();
                            hasher.update(&contents);
                            let result = hasher.finalize();
                            let hash_str = hex::encode(result);
                            if let Some(malware_name) = malware_hashes.get(&hash_str) {
                                Ok(vec![format!(
                                    "ALERT: File '{}' is detected as malware '{}' (hash: {})",
                                    path_display, malware_name, hash_str
                                )])
                            } else {
                                Ok(vec![])
                            }
                        }
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
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    let config = config::Config::default();
    if let Err(e) = config.validate() {
        error!("Invalid configuration: {}", e);
        return Err(anyhow::anyhow!(e));
    }
    
    info!("Starting Enterprise Malware Scanner...");
    
    // Download the malware hash database.
    let hashes = hashdb::get_malware_hashes(&config.malware_hashes_url).await?;
    
    info!("Downloaded {} malware hash entries.", hashes.len());
    
    // Build a HashMap for quick lookup.
    // The key is the SHA256 hash and the value is the malware name.
    let malware_map: HashMap<String, String> = hashes
        .into_iter()
        .map(|mh| (mh.sha256, mh.name))
        .collect();
    
    // Scan the target directory.
    info!("Scanning directory '{}' for malware signatures...", config.target_directory);
    let alerts = scanner::scan_directory_for_hashes(&config.target_directory, &malware_map).await?;
    
    if alerts.is_empty() {
        info!("No malware detected.");
    } else {
        info!("Detected {} potential malware files:", alerts.len());
        for alert in alerts {
            println!("{}", alert);
        }
    }
    
    Ok(())
}
