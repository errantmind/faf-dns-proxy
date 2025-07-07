//! Public types for the eBPF DNS monitoring library

use plain::Plain;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};

/// Information about a process in the process tree
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessNode {
    pub pid: u32,
    pub name: String,
}

/// Complete information about a DNS request
#[derive(Debug, Clone)]
pub struct DnsRequestInfo {
    /// Process ID that made the request
    pub pid: u32,
    /// Process name/command
    pub process_name: String,
    /// Source IP address
    pub source_addr: Ipv4Addr,
    /// Source port
    pub source_port: u16,
    /// Destination IP address  
    pub destination_addr: Ipv4Addr,
    /// Destination port (typically 53 for DNS)
    pub destination_port: u16,
    /// Message length in bytes
    pub message_length: u32,
    /// Processing latency in microseconds
    pub latency_us: u64,
    /// Process tree (from child to parent)
    pub process_tree: Vec<ProcessNode>,
    /// Timestamp when the request was captured (nanoseconds)
    pub timestamp_ns: u64,
}

impl DnsRequestInfo {
    /// Get the source socket address
    pub fn source_socket_addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.source_addr, self.source_port)
    }

    /// Get the destination socket address
    pub fn destination_socket_addr(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.destination_addr, self.destination_port)
    }

    /// Get a formatted process tree string
    pub fn process_tree_string(&self) -> String {
        if self.process_tree.is_empty() {
            format!("{}({})", self.process_name, self.pid)
        } else {
            self.process_tree
                .iter()
                .map(|node| format!("{}({})", node.name, node.pid))
                .collect::<Vec<_>>()
                .join(" -> ")
        }
    }
}

impl fmt::Display for DnsRequestInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DNS {} {}:{} -> {}:{} len={} lat={}μs proc={}",
            self.pid,
            self.source_addr,
            self.source_port,
            self.destination_addr,
            self.destination_port,
            self.message_length,
            self.latency_us,
            self.process_tree_string()
        )
    }
}

// Internal types for eBPF interop (kept from original implementation)

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct ProcessNodeRaw {
    pub pid: u32,
    pub comm: [u8; 16],
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct UdpPacketInfo {
    pub pid: u32,
    pub comm: [u8; 16],
    pub saddr: u32,
    pub sport: u16,
    pub daddr: u32,
    pub dport: u16,
    pub timestamp_ns: u64,
    pub processing_start_ns: u64,
    pub processing_end_ns: u64,
    pub msg_len: u32,
    pub flags: u8,
    pub tree_depth: u8,
    pub padding: [u8; 2],
    pub tree: [ProcessNodeRaw; 5], // MAX_PROCESS_TREE_DEPTH
}

unsafe impl Plain for UdpPacketInfo {}

impl UdpPacketInfo {
    /// Convert raw eBPF data to public API type
    pub fn to_dns_request_info(&self) -> DnsRequestInfo {
        let process_name = std::str::from_utf8(&self.comm)
            .unwrap_or("?")
            .trim_end_matches('\0')
            .to_string();

        let source_addr = if self.flags & 1 != 0 && self.saddr != 0 {
            Ipv4Addr::from(u32::from_be(self.saddr))
        } else {
            Ipv4Addr::new(0, 0, 0, 0)
        };

        let source_port = if self.flags & 2 != 0 { self.sport } else { 0 };

        let destination_addr = if self.flags & 4 != 0 && self.daddr != 0 {
            Ipv4Addr::from(u32::from_be(self.daddr))
        } else {
            Ipv4Addr::new(0, 0, 0, 0)
        };

        let destination_port = if self.flags & 8 != 0 { self.dport } else { 0 };

        let latency_us = if self.processing_end_ns > self.processing_start_ns {
            (self.processing_end_ns - self.processing_start_ns) / 1000
        } else {
            0
        };

        let process_tree = if self.flags & 16 != 0 && self.tree_depth > 0 {
            self.tree[..self.tree_depth as usize]
                .iter()
                .map(|node| {
                    let name = std::str::from_utf8(&node.comm)
                        .unwrap_or("?")
                        .trim_end_matches('\0')
                        .to_string();
                    ProcessNode {
                        pid: node.pid,
                        name,
                    }
                })
                .collect()
        } else {
            vec![]
        };

        DnsRequestInfo {
            pid: self.pid,
            process_name,
            source_addr,
            source_port,
            destination_addr,
            destination_port,
            message_length: self.msg_len,
            latency_us,
            process_tree,
            timestamp_ns: self.timestamp_ns,
        }
    }
}
