use std::fs::File;
use std::io::{self, Read};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const OUTPUT_LOG: &str = "/var/log/tuxsupport_errors.log";

fn display_errors() -> io::Result<()> {
    loop {
        // Attempt to open the error log file.
        let mut file = match File::open(OUTPUT_LOG) {
            Ok(f) => f,
            Err(_) => {
                println!("Error log not found. Ensure the daemon is running.");
                return Ok(());
            }
        };
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        println!("{}", contents);
        println!("Type 'stop' and press Enter to exit.");

        // Use a channel to try to capture user input with a 2-second timeout.
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut input = String::new();
            let _ = io::stdin().read_line(&mut input);
            let _ = tx.send(input);
        });

        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(input) if input.trim().eq_ignore_ascii_case("stop") => {
                println!("Exiting.");
                break;
            }
            _ => {} // Timeout or other input, loop again.
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = display_errors() {
        eprintln!("Error: {}", e);
    }
}
