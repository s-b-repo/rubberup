# Intacheck - Integrity Checker for Installed Packages

## Build and Install

### Manual Installation

1. **Build the tool**:
   ```bash
   cargo build --release
   ```

2. **Install system-wide**:
   ```bash
   sudo cp target/release/intacheck /usr/local/bin/
   sudo chmod +x /usr/local/bin/intacheck
   ```

3. **Set up log file**:
   ```bash
   sudo touch /var/log/intacheck.log
   sudo chmod 664 /var/log/intacheck.log
   sudo chown root:adm /var/log/intacheck.log
   ```

### One-Click Install (Alternative)
Run the installation script:
```bash
chmod +x install.sh && ./install.sh
```

## Usage
Run the tool with:
```bash
sudo intacheck --verbose
```

Features:
- Lists installed packages and checks integrity
- Prompts before reinstalling problematic packages
- Logs actions to `/var/log/intacheck.log`
- Add `--dry-run` to test without changes
