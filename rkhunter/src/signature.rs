use serde::{Deserialize, Serialize};
use reqwest;
use anyhow::{Result, Context};
use tracing::{warn, info};
use std::fs;
use std::path::Path;
use futures::future::join_all;
use std::collections::HashSet;
use tempfile::NamedTempFile;
use std::io::Write;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct Signature {
    pub name: String,
    pub pattern: String,
}

impl Signature {
    /// Validates the signature pattern as hexadecimal bytes
    pub fn validate(&self) -> Result<()> {
        let clean_pattern = self.pattern.replace(" ", "");
        hex::decode(&clean_pattern)
            .context(format!("Invalid hex pattern in signature '{}'", self.name))?;
        Ok(())
    }
}

/// Downloads rootkit signatures from the given URL with validation
pub async fn download_signatures_from_url(url: &str) -> Result<Vec<Signature>> {
    let resp = reqwest::get(url)
        .await
        .context(format!("Failed to download from {}", url))?;
    
    let mut sigs = resp.json::<Vec<Signature>>()
        .await
        .context(format!("Failed to parse JSON from {}", url))?;

    // Validate all signatures
    for sig in &sigs {
        sig.validate()
            .context(format!("Invalid signature from {}", url))?;
    }

    info!("Validated {} signatures from {}", sigs.len(), url);
    Ok(sigs)
}

/// Concurrently downloads signatures from multiple URLs
pub async fn download_all_signatures(urls: &[&str]) -> Result<Vec<Signature>> {
    let download_futures = urls.iter().map(|&url| download_signatures_from_url(url));
    let results = join_all(download_futures).await;

    let mut all_signatures = Vec::new();
    for (url, result) in urls.iter().zip(results) {
        match result {
            Ok(mut sigs) => {
                all_signatures.append(&mut sigs);
            },
            Err(e) => {
                warn!("Error downloading from {}: {:#}", url, e);
            }
        }
    }
    
    info!("Total downloaded signatures: {}", all_signatures.len());
    Ok(all_signatures)
}

/// Loads local signatures from a JSON file
pub fn load_local_signatures<P: AsRef<Path>>(path: P) -> Result<Vec<Signature>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(Vec::new());
    }

    let data = fs::read_to_string(path)
        .context("Failed to read local signatures file")?;
    
    let sigs = serde_json::from_str::<Vec<Signature>>(&data)
        .context("Failed to parse local signatures JSON")?;

    Ok(sigs)
}

/// Saves signatures with atomic write operation
pub fn save_local_signatures<P: AsRef<Path>>(path: P, signatures: &[Signature]) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .context("Failed to create signatures directory")?;
    }

    let mut temp_file = NamedTempFile::new_in(path.parent().unwrap())
        .context("Failed to create temporary file")?;
    
    let data = serde_json::to_string_pretty(signatures)
        .context("Failed to serialize signatures")?;
    
    temp_file.write_all(data.as_bytes())
        .context("Failed to write to temporary file")?;
    
    temp_file.persist(path)
        .context("Failed to replace old signatures file")?;
    
    Ok(())
}

/// Merges and updates signatures with deduplication
pub fn update_local_signatures<P: AsRef<Path>>(
    local_path: P,
    new_sigs: Vec<Signature>
) -> Result<Vec<Signature>> {
    let mut local_sigs = load_local_signatures(&local_path)?;
    
    // Create case-insensitive index of existing names
    let existing_names: HashSet<String> = local_sigs.iter()
        .map(|s| s.name.to_lowercase())
        .collect();

    let initial_count = local_sigs.len();
    let mut added = 0;

    for new_sig in new_sigs {
        let lower_name = new_sig.name.to_lowercase();
        if !existing_names.contains(&lower_name) {
            info!("Adding new signature: {}", new_sig.name);
            local_sigs.push(new_sig);
            added += 1;
        }
    }

    if added > 0 {
        save_local_signatures(&local_path, &local_sigs)?;
        info!("Added {} new signatures. Total: {}", added, local_sigs.len());
    } else {
        info!("No new signatures found. Current total: {}", local_sigs.len());
    }

    Ok(local_sigs)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Example signature sources
    let urls = [
        "https://raw.githubusercontent.com/example/rootkit-signatures/main/sigs.json",
        "https://security.example.com/api/v1/signatures",
    ];

    // Download remote signatures concurrently
    let remote_signatures = download_all_signatures(&urls).await?;

    // Update local signature store
    let local_path = "data/signatures.json";
    let updated = update_local_signatures(local_path, remote_signatures)?;

    println!("Successfully updated signature database. Total signatures: {}", updated.len());
    Ok(())
}
