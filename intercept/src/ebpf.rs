//! eBPF program management and runtime requirements checking

use crate::error::{Error, Result};
use libbpf_rs::{MapCore, ObjectBuilder, RingBufferBuilder};
use std::path::Path;
use std::process::Command;

static UDP_INTERCEPT_OBJ: &[u8] = include_bytes!("udp_intercept.o");

/// eBPF program manager
pub struct EbpfManager {
    object: Option<libbpf_rs::Object>,
    _udp_link: Option<libbpf_rs::Link>,
    _prctl_link: Option<libbpf_rs::Link>,
}

impl EbpfManager {
    /// Create a new eBPF manager
    pub fn new() -> Self {
        Self {
            object: None,
            _udp_link: None,
            _prctl_link: None,
        }
    }

    /// Check runtime requirements and load eBPF programs
    pub fn load_and_attach(&mut self) -> Result<()> {
        // Perform essential runtime checks
        check_runtime_requirements()?;

        let mut obj_builder = ObjectBuilder::default();
        let open_object = obj_builder.open_memory(UDP_INTERCEPT_OBJ)?;
        let object = open_object.load()?;

        // Attach UDP sendmsg kprobe
        let udp_prog = object
            .progs_mut()
            .find(|p| p.name() == "trace_udp_sendmsg")
            .ok_or_else(|| Error::EbpfError("UDP probe program not found".into()))?;

        let udp_link = udp_prog.attach_kprobe(false, "udp_sendmsg")?;

        // Attach prctl tracepoint
        let prctl_prog = object
            .progs_mut()
            .find(|p| p.name() == "trace_prctl_enter")
            .ok_or_else(|| Error::EbpfError("prctl probe program not found".into()))?;

        let prctl_link = prctl_prog.attach()?;

        self.object = Some(object);
        self._udp_link = Some(udp_link);
        self._prctl_link = Some(prctl_link);

        Ok(())
    }

    /// Create a ring buffer for receiving events
    pub fn create_ringbuffer<F>(&'_ self, callback: F) -> Result<libbpf_rs::RingBuffer<'_>>
    where
        F: Fn(&[u8]) -> i32 + 'static,
    {
        let object = self.object.as_ref().ok_or(Error::NotRunning)?;

        let rb_map = object
            .maps()
            .find(|m| m.name() == "rb")
            .ok_or_else(|| Error::EbpfError("Ring buffer map not found".into()))?;

        let mut builder = RingBufferBuilder::new();
        builder.add(&rb_map, callback)?;
        let ringbuf = builder.build()?;

        Ok(ringbuf)
    }

    /// Check if the eBPF programs are loaded and attached
    pub fn is_loaded(&self) -> bool {
        self.object.is_some()
    }
}

impl Drop for EbpfManager {
    fn drop(&mut self) {
        // Cleanup is handled automatically by the libbpf-rs RAII types
    }
}

/// Check runtime requirements for eBPF operation
pub fn check_runtime_requirements() -> Result<()> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Check BTF support (critical for CO-RE)
    if !Path::new("/sys/kernel/btf/vmlinux").exists() {
        errors
            .push("BTF support not available - /sys/kernel/btf/vmlinux does not exist".to_string());
        errors.push("Your kernel was not compiled with CONFIG_DEBUG_INFO_BTF=y".to_string());
        errors.push("This is required for CO-RE (Compile Once Run Everywhere) support".to_string());
    }

    // Check if running as root (required for eBPF program loading)
    if !is_running_as_root() {
        errors.push("Root privileges required - run with sudo".to_string());
        errors.push("eBPF programs require CAP_SYS_ADMIN capability".to_string());
    }

    // Check kernel version
    match get_kernel_version() {
        Ok((major, minor)) => {
            if major < 5 || (major == 5 && minor < 4) {
                errors.push(format!(
                    "Kernel {}.{} found, but Linux 5.4+ required for CO-RE support",
                    major, minor
                ));
            } else if major < 5 || (major == 5 && minor < 10) {
                warnings.push(format!(
                    "Kernel {}.{} found, Linux 5.10+ recommended for better stability",
                    major, minor
                ));
            }
        }
        Err(msg) => warnings.push(format!("Could not detect kernel version: {}", msg)),
    }

    // Check architecture (informational)
    match get_current_architecture() {
        Ok(arch) if arch != "x86_64" => {
            warnings.push(format!(
                "Architecture '{}' detected - this program is optimized for x86_64",
                arch
            ));
        }
        Err(msg) => warnings.push(format!("Could not detect architecture: {}", msg)),
        _ => {} // x86_64, all good
    }

    // Print warnings if any
    if !warnings.is_empty() {
        eprintln!("⚠️  Runtime warnings:");
        for warning in &warnings {
            eprintln!("  - {}", warning);
        }
        eprintln!();
    }

    // Handle critical errors
    if !errors.is_empty() {
        let error_msg = format!("Runtime requirements not met:\n{}", errors.join("\n"));
        return Err(Error::RuntimeRequirements(error_msg));
    }

    Ok(())
}

fn is_running_as_root() -> bool {
    // Check if effective user ID is 0 (root)
    unsafe { libc::geteuid() == 0 }
}

fn get_kernel_version() -> std::result::Result<(u32, u32), String> {
    let output = Command::new("uname")
        .arg("-r")
        .output()
        .map_err(|_| "Could not run uname command".to_string())?;

    let version_str = String::from_utf8_lossy(&output.stdout);
    let version_str = version_str.trim();

    // Parse version like "6.14.5-arch1-1" -> (6, 14)
    let parts: Vec<&str> = version_str.split('.').collect();
    if parts.len() >= 2 {
        if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
            return Ok((major, minor));
        }
    }

    Err(format!("Could not parse kernel version: {}", version_str))
}

fn get_current_architecture() -> std::result::Result<String, String> {
    let output = Command::new("uname")
        .arg("-m")
        .output()
        .map_err(|_| "Could not run uname command".to_string())?;

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
