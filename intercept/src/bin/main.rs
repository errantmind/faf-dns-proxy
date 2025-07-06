//! Debug binary for the eBPF DNS monitoring library
//!
//! This binary provides the same functionality as the original standalone application,
//! but uses the library implementation underneath. It's useful for debugging and
//! demonstrating the real-time monitoring capabilities.

use faf_dns_intercept::{DnsMonitor, Error};
use std::io::{self, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create and configure the monitor
    let mut monitor = DnsMonitor::new()?;

    // Enable debug output to get the same behavior as the original
    monitor.enable_debug_output();

    // Set up Ctrl+C handler
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        println!("\nShutting down...");
        r.store(false, std::sync::atomic::Ordering::Relaxed);
    })
    .expect("Error setting Ctrl-C handler");

    // Start monitoring
    match monitor.start_monitoring() {
        Ok(()) => {
            // For debug mode, we need to continuously poll to show real-time output
            // This simulates the old background polling behavior
            while running.load(std::sync::atomic::Ordering::Relaxed) {
                // Poll by doing a dummy lookup - this triggers the ring buffer poll
                // We use a dummy address that won't match anything
                let dummy_addr =
                    std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(255, 255, 255, 255), 65535);
                let _ = monitor.lookup_request_details(dummy_addr);

                // Small delay to avoid excessive CPU usage
                std::thread::sleep(std::time::Duration::from_millis(10));

                // Optionally print cache statistics periodically
                if std::env::var("SHOW_CACHE_STATS").is_ok() {
                    let (cache_len, _) = monitor.cache_stats();
                    if cache_len > 0 {
                        print!("\r[Cache: {} entries] ", cache_len);
                        io::stdout().flush().unwrap();
                    }
                }
            }

            monitor.stop_monitoring();
            println!("\nMonitoring stopped.");
        }
        Err(Error::RuntimeRequirements(msg)) => {
            eprintln!("❌ Runtime requirements not met:\n");
            eprintln!("{}", msg);
            eprintln!("\n How to fix:");
            eprintln!("  For BTF support:");
            eprintln!(
                "    - Use a distribution with BTF-enabled kernel (Ubuntu 20.04+, Fedora 32+)"
            );
            eprintln!("    - Or rebuild kernel with CONFIG_DEBUG_INFO_BTF=y");
            eprintln!("  For root privileges:");
            eprintln!("    sudo cargo run --bin debug");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to start monitoring: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
