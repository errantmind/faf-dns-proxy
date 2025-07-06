//! Simple example showing how to use the eBPF DNS monitoring library
//!
//! This example demonstrates the basic API for monitoring DNS traffic.
//! Note: Requires root privileges to run.

use faf_dns_intercept::{DnsMonitor, Error};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("eBPF DNS Monitor Library Example");
    println!("=================================");

    // Create a new DNS monitor
    let mut monitor = match DnsMonitor::new() {
        Ok(m) => m,
        Err(Error::RuntimeRequirements(msg)) => {
            eprintln!("Cannot start monitoring - runtime requirements not met:");
            eprintln!("{}", msg);
            eprintln!("\nTry running with: sudo cargo run --example simple_usage");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    println!("DNS monitor created successfully");

    // Start monitoring (this will load eBPF programs and start background thread)
    monitor.start_monitoring()?;
    println!("DNS monitoring started");

    // Example of how a DNS client might use this library
    println!("\nSimulating DNS client usage...");
    println!("   (In a real DNS client, you'd have the actual source addresses)");

    // Simulate some lookups for example addresses
    let example_addresses = vec![
        SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345),
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 50), 54321),
        SocketAddrV4::new(Ipv4Addr::new(172, 16, 0, 10), 23456),
    ];

    println!("\nLooking up DNS request details for example addresses:");
    println!("   (These will be empty until actual DNS traffic is captured)");

    for _ in 0..10 {
        for addr in &example_addresses {
            if let Some(info) = monitor.lookup_request_details(*addr) {
                println!("   Found DNS request: {}", info);
            }
        }

        // Show cache statistics
        let (cache_len, is_empty) = monitor.cache_stats();
        if !is_empty {
            println!("   Cache contains {} DNS request entries", cache_len);
        }

        std::thread::sleep(Duration::from_millis(500));
    }

    // Stop monitoring
    monitor.stop_monitoring();
    println!("\nDNS monitoring stopped");

    println!("\nTo see actual DNS traffic, try:");
    println!("   1. Run: sudo cargo run --bin debug");
    println!("   2. In another terminal, make some DNS queries:");
    println!("      nslookup google.com");
    println!("      dig example.com");

    Ok(())
}
