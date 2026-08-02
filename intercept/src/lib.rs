//! eBPF-based DNS traffic monitoring library
//!
//! This library provides real-time monitoring of DNS traffic using eBPF kernel probes.
//! It can track DNS requests with process information, network details, and latency measurements.

mod cache;
mod ebpf;
mod error;
mod monitor;
mod types;

// Re-export main public types
pub use error::{Error, Result};
pub use monitor::DnsMonitor;
pub use types::{DnsRequestInfo, ProcessNode};
