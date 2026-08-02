use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        panic!("faf-dns-intercept can only be built for Linux");
    }

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set"));
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is not set"));
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "unknown".to_string());
    let object_path = out_dir.join("udp_intercept.o");
    let precompiled_path = manifest_dir
        .join("precompiled")
        .join(&target_arch)
        .join("udp_intercept.o");

    let force_build = env::var_os("FORCE_BUILD_EBPF").is_some();
    if force_build || !precompiled_path.exists() {
        if force_build {
            println!("cargo:warning=Building eBPF from source (FORCE_BUILD_EBPF set)");
        } else {
            println!(
                "cargo:warning=Building eBPF from source (no precompiled object for {target_arch})"
            );
        }

        check_build_dependencies(&target_arch);
        build_from_source(&manifest_dir, &out_dir, &object_path);
    } else {
        println!("cargo:warning=Using precompiled eBPF object for {target_arch}");
        fs::copy(&precompiled_path, &object_path).unwrap_or_else(|error| {
            panic!(
                "Failed to copy precompiled eBPF object from {} to {}: {error}",
                precompiled_path.display(),
                object_path.display()
            )
        });
    }

    println!("cargo:rerun-if-changed=src/udp_intercept.c");
    println!("cargo:rerun-if-changed=/sys/kernel/btf/vmlinux");
    println!("cargo:rerun-if-changed=precompiled/");
    println!("cargo:rerun-if-env-changed=FORCE_BUILD_EBPF");
}

fn build_from_source(manifest_dir: &Path, out_dir: &Path, object_path: &Path) {
    let vmlinux_h = out_dir.join("vmlinux.h");
    generate_vmlinux_h(&vmlinux_h);

    let c_file = manifest_dir.join("src/udp_intercept.c");
    let output = Command::new("clang")
        .args(["-O2", "-target", "bpf", "-D__TARGET_ARCH_x86", "-g"])
        .arg("-I")
        .arg(out_dir)
        .arg("-c")
        .arg(&c_file)
        .arg("-o")
        .arg(object_path)
        .output()
        .expect("Failed to compile eBPF program");

    if !output.status.success() {
        panic!(
            "Failed to compile eBPF program: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn generate_vmlinux_h(output_path: &Path) {
    println!("cargo:warning=Generating vmlinux.h for current kernel...");

    let output = Command::new("bpftool")
        .args([
            "btf",
            "dump",
            "file",
            "/sys/kernel/btf/vmlinux",
            "format",
            "c",
        ])
        .output()
        .expect("Failed to run bpftool - make sure bpftool is installed");

    if !output.status.success() {
        panic!(
            "Failed to generate vmlinux.h: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fs::write(output_path, &output.stdout)
        .unwrap_or_else(|error| panic!("Failed to write {}: {error}", output_path.display()));

    println!(
        "cargo:warning=Generated vmlinux.h with {} bytes",
        output.stdout.len()
    );
}

fn check_build_dependencies(target_arch: &str) {
    let mut missing_deps = Vec::new();
    let mut warnings = Vec::new();

    match check_clang() {
        Ok(version) => {
            if version < 10 {
                missing_deps.push(format!(
                    "clang version {} found, but version 10+ required (15+ recommended)",
                    version
                ));
            } else if version < 15 {
                warnings.push(format!(
                    "clang version {} found, version 15+ recommended for best compatibility",
                    version
                ));
            }
        }
        Err(message) => missing_deps.push(message),
    }

    if let Err(message) = check_bpftool() {
        missing_deps.push(message);
    }
    if let Err(message) = check_btf_support() {
        missing_deps.push(message);
    }

    match check_kernel_version() {
        Ok((major, minor)) => {
            if major < 5 || (major == 5 && minor < 4) {
                missing_deps.push(format!(
                    "Kernel {}.{} found, but Linux 5.4+ required for CO-RE support",
                    major, minor
                ));
            } else if major == 5 && minor < 10 {
                warnings.push(format!(
                    "Kernel {}.{} found, Linux 5.10+ recommended for better stability",
                    major, minor
                ));
            }
        }
        Err(message) => warnings.push(message),
    }

    if target_arch != "x86_64" {
        missing_deps.push(format!(
            "Architecture '{}' is not supported - only x86_64 is currently supported",
            target_arch
        ));
    }

    if !warnings.is_empty() {
        println!("cargo:warning=Build warnings:");
        for warning in &warnings {
            println!("cargo:warning=  - {warning}");
        }
    }

    if missing_deps.is_empty() {
        return;
    }

    eprintln!("\n❌ BUILD FAILED: Missing critical dependencies\n");
    for dependency in &missing_deps {
        eprintln!("  ❌ {dependency}");
    }

    eprintln!("\n🔧 How to fix:");
    match detect_distribution() {
        Some("ubuntu") | Some("debian") => {
            eprintln!("  On Ubuntu/Debian:");
            eprintln!("    sudo apt update");
            eprintln!("    sudo apt install clang bpftool libbpf-dev linux-headers-$(uname -r)");
        }
        Some("fedora") | Some("rhel") | Some("centos") => {
            eprintln!("  On Fedora/RHEL/CentOS:");
            eprintln!("    sudo dnf install clang bpftool libbpf-devel kernel-devel");
        }
        Some("arch") => {
            eprintln!("  On Arch Linux:");
            eprintln!("    sudo pacman -S clang bpf libbpf linux-headers");
        }
        _ => {
            eprintln!("  Install the following packages for your distribution:");
            eprintln!("    - clang (version 10+)");
            eprintln!("    - bpftool (for BTF processing)");
            eprintln!("    - libbpf development headers");
            eprintln!("    - kernel headers");
        }
    }

    eprintln!("\nAlternatively, provide a precompiled eBPF object for the target architecture.");
    panic!("Build dependencies not satisfied");
}

fn check_clang() -> Result<u32, String> {
    let output = Command::new("clang")
        .arg("--version")
        .output()
        .map_err(|_| "clang not found - install clang compiler (apt install clang / dnf install clang / pacman -S clang)".to_string())?;

    if !output.status.success() {
        return Err("clang command failed".to_string());
    }

    let version = String::from_utf8_lossy(&output.stdout);
    for line in version.lines() {
        if let Some(version_part) = line.split_whitespace().nth(2)
            && line.contains("clang version")
            && let Some(major) = version_part
                .split('.')
                .next()
                .and_then(|value| value.parse().ok())
        {
            return Ok(major);
        }
    }

    Err("Could not parse clang version".to_string())
}

fn check_bpftool() -> Result<(), String> {
    let output = Command::new("bpftool")
        .arg("--version")
        .output()
        .map_err(|_| "bpftool not found - install bpftool package (apt install bpftool / dnf install bpftool / pacman -S bpf)".to_string())?;

    if output.status.success() {
        Ok(())
    } else {
        Err("bpftool command failed".to_string())
    }
}

fn check_btf_support() -> Result<(), String> {
    if Path::new("/sys/kernel/btf/vmlinux").exists() {
        Ok(())
    } else {
        Err(
            "BTF support not available - /sys/kernel/btf/vmlinux does not exist\n    Your kernel was not compiled with CONFIG_DEBUG_INFO_BTF=y\n    This is required for CO-RE (Compile Once Run Everywhere) support".to_string(),
        )
    }
}

fn check_kernel_version() -> Result<(u32, u32), String> {
    let output = Command::new("uname")
        .arg("-r")
        .output()
        .map_err(|_| "Could not detect kernel version".to_string())?;

    let version = String::from_utf8_lossy(&output.stdout);
    let mut parts = version.trim().split('.');
    let major = parts.next().and_then(|value| value.parse().ok());
    let minor = parts.next().and_then(|value| value.parse().ok());

    match (major, minor) {
        (Some(major), Some(minor)) => Ok((major, minor)),
        _ => Err(format!(
            "Could not parse kernel version: {}",
            version.trim()
        )),
    }
}

fn detect_distribution() -> Option<&'static str> {
    let content = std::fs::read_to_string("/etc/os-release")
        .ok()?
        .to_lowercase();
    if content.contains("ubuntu") {
        Some("ubuntu")
    } else if content.contains("debian") {
        Some("debian")
    } else if content.contains("fedora") {
        Some("fedora")
    } else if content.contains("rhel") || content.contains("red hat") {
        Some("rhel")
    } else if content.contains("centos") {
        Some("centos")
    } else if content.contains("arch") {
        Some("arch")
    } else {
        None
    }
}
