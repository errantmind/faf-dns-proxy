//! Error types for the eBPF DNS monitoring library

use std::fmt;

/// Library result type
pub type Result<T> = std::result::Result<T, Error>;

/// Error types that can occur when using the DNS monitor
#[derive(Debug)]
pub enum Error {
    /// eBPF program loading or management error
    EbpfError(Box<dyn std::error::Error + Send + Sync>),
    /// Runtime requirements not met (permissions, kernel version, etc.)
    RuntimeRequirements(String),
    /// Monitor is not running when operation requires it
    NotRunning,
    /// Monitor is already running when trying to start
    AlreadyRunning,
    /// Invalid configuration or parameters
    InvalidConfig(String),
    /// I/O error (file operations, etc.)
    IoError(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::EbpfError(e) => write!(f, "eBPF error: {}", e),
            Error::RuntimeRequirements(msg) => write!(f, "Runtime requirements not met: {}", msg),
            Error::NotRunning => write!(f, "DNS monitor is not running"),
            Error::AlreadyRunning => write!(f, "DNS monitor is already running"),
            Error::InvalidConfig(msg) => write!(f, "Invalid configuration: {}", msg),
            Error::IoError(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::EbpfError(e) => Some(&**e),
            Error::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IoError(err)
    }
}

impl From<libbpf_rs::Error> for Error {
    fn from(err: libbpf_rs::Error) -> Self {
        Error::EbpfError(Box::new(err))
    }
}
