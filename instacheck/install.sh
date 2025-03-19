#!/bin/bash

# Build the tool
echo "Building intacheck..."
cargo build --release || {
    echo "Build failed! Ensure Rust is installed."
    exit 1
}

# Install binary
echo "Installing system-wide..."
sudo cp target/release/intacheck /usr/local/bin/ &&
sudo chmod +x /usr/local/bin/intacheck

# Configure log file
echo "Setting up log file..."
sudo touch /var/log/intacheck.log
sudo chmod 664 /var/log/intacheck.log
sudo chown root:adm /var/log/intacheck.log

echo "Done! Run with: sudo intacheck --verbose"
