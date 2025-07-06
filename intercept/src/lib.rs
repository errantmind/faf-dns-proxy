//! eBPF-based DNS traffic monitoring library
//!
//! This library provides real-time monitoring of DNS traffic using eBPF kernel probes.
//! It can track DNS requests with process information, network details, and latency measurements.

pub mod cache;
pub mod ebpf;
pub mod error;
pub mod monitor;
pub mod types;

// Re-export main public types
pub use error::{Error, Result};
pub use monitor::DnsMonitor;
pub use types::{DnsRequestInfo, ProcessNode};
