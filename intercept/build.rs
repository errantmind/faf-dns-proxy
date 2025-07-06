use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let src_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    // Default to precompiled, only build from source if:
    // 1. FORCE_BUILD_EBPF env var is set, OR
    // 2. No precompiled object exists for current architecture
    let force_build = env::var("FORCE_BUILD_EBPF").is_ok();
    let precompiled_available = check_precompiled_available(&src_dir);

    if force_build || !precompiled_available {
        if force_build {
            println!("cargo:warning=Building eBPF from source (FORCE_BUILD_EBPF set)");
        } else {
            println!("cargo:warning=Building eBPF from source (no precompiled object available)");
        }

        // Check all build dependencies before attempting compilation
        check_build_dependencies();

        let out_dir = env::var("OUT_DIR").unwrap();

        // Generate vmlinux.h for the current system
        let vmlinux_h = PathBuf::from(&src_dir).join("src/vmlinux.h");
        generate_vmlinux_h(&vmlinux_h);

        let c_file = PathBuf::from(&src_dir).join("src/udp_intercept.c");
        let obj_file = PathBuf::from(&out_dir).join("udp_intercept.o");

        let output = Command::new("clang")
            .args(&[
                "-O2",
                "-target",
                "bpf",
                "-D__TARGET_ARCH_x86",
                "-g",
                "-c",
                c_file.to_str().unwrap(),
                "-o",
                obj_file.to_str().unwrap(),
            ])
            .output()
            .expect("Failed to compile eBPF program");

        if !output.status.success() {
            panic!(
                "Failed to compile eBPF program: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Copy the object file to src/ so it can be included at compile time
        let dest_obj = PathBuf::from(&src_dir).join("src/udp_intercept.o");
        fs::copy(&obj_file, &dest_obj).expect("Failed to copy object file");

        println!("cargo:rerun-if-changed=src/udp_intercept.c");
        println!("cargo:rerun-if-changed=/sys/kernel/btf/vmlinux");
    } else {
        println!("cargo:warning=Using precompiled eBPF object for current architecture");
        use_precompiled_object(&src_dir);
    }

    println!("cargo:rerun-if-changed=precompiled/");
    println!("cargo:rerun-if-env-changed=FORCE_BUILD_EBPF");
}

fn generate_vmlinux_h(output_path: &PathBuf) {
    println!("cargo:warning=Generating vmlinux.h for current kernel...");

    let output = Command::new("bpftool")
        .args(&[
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

    fs::write(output_path, &output.stdout).expect("Failed to write vmlinux.h");

    println!(
        "cargo:warning=Generated vmlinux.h with {} bytes",
        output.stdout.len()
    );
}

fn check_precompiled_available(src_dir: &str) -> bool {
    let arch = get_target_architecture();
    let precompiled_path = PathBuf::from(src_dir)
        .join("precompiled")
        .join(&arch)
        .join("udp_intercept.o");

    let available = precompiled_path.exists();
    if available {
        println!("cargo:warning=Found precompiled eBPF object for {}", arch);
    } else {
        println!(
            "cargo:warning=No precompiled eBPF object found for {} at {}",
            arch,
            precompiled_path.display()
        );
    }
    available
}

fn use_precompiled_object(src_dir: &str) {
    let arch = get_target_architecture();
    let precompiled_path = PathBuf::from(src_dir)
        .join("precompiled")
        .join(&arch)
        .join("udp_intercept.o");

    let dest_obj = PathBuf::from(src_dir).join("src/udp_intercept.o");

    if precompiled_path.exists() {
        fs::copy(&precompiled_path, &dest_obj).expect("Failed to copy precompiled eBPF object");
        println!("cargo:warning=Copied precompiled eBPF object for {}", arch);
    } else {
        panic!(
            "Precompiled eBPF object not found for architecture: {}",
            arch
        );
    }
}

fn get_target_architecture() -> String {
    // Get target architecture, defaulting to host architecture
    env::var("CARGO_CFG_TARGET_ARCH")
        .or_else(|_| {
            // Fallback to detecting host architecture
            Command::new("uname")
                .arg("-m")
                .output()
                .map(|output| {
                    let arch = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    // Normalize architecture names
                    match arch.as_str() {
                        "x86_64" => "x86_64".to_string(),
                        "aarch64" | "arm64" => "aarch64".to_string(),
                        "armv7l" => "armv7".to_string(),
                        other => other.to_string(),
                    }
                })
                .map_err(|_| env::VarError::NotPresent)
        })
        .unwrap_or_else(|_| "unknown".to_string())
}

fn check_build_dependencies() {
    let mut missing_deps = Vec::new();
    let mut warnings = Vec::new();

    // Check for clang compiler
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
        Err(msg) => missing_deps.push(msg),
    }

    // Check for bpftool (required for vmlinux.h generation)
    if let Err(msg) = check_bpftool() {
        missing_deps.push(msg);
    }

    // Check for BTF support (critical for CO-RE)
    if let Err(msg) = check_btf_support() {
        missing_deps.push(msg);
    }

    // Check kernel version
    match check_kernel_version() {
        Ok((major, minor)) => {
            if major < 5 || (major == 5 && minor < 4) {
                missing_deps.push(format!(
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
        Err(msg) => warnings.push(msg),
    }

    // Check architecture
    if let Err(msg) = check_architecture() {
        missing_deps.push(msg);
    }

    // Print warnings
    if !warnings.is_empty() {
        println!("cargo:warning=Build warnings:");
        for warning in &warnings {
            println!("cargo:warning=  - {}", warning);
        }
        println!("cargo:warning=");
    }

    // If critical dependencies are missing, provide helpful error message
    if !missing_deps.is_empty() {
        eprintln!("\n❌ BUILD FAILED: Missing critical dependencies\n");

        for dep in &missing_deps {
            eprintln!("  ❌ {}", dep);
        }

        eprintln!("\n🔧 How to fix:");

        // Detect distribution and provide specific instructions
        match detect_distribution() {
            Some("ubuntu") | Some("debian") => {
                eprintln!("  On Ubuntu/Debian:");
                eprintln!("    sudo apt update");
                eprintln!(
                    "    sudo apt install clang bpftool libbpf-dev linux-headers-$(uname -r)"
                );
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

        eprintln!("\nAlternatively, you can try using precompiled eBPF objects:");
        eprintln!("   cargo clean && cargo build --release");

        panic!("Build dependencies not satisfied");
    }
}

fn check_clang() -> Result<u32, String> {
    let output = Command::new("clang")
        .arg("--version")
        .output()
        .map_err(|_| "clang not found - install clang compiler (apt install clang / dnf install clang / pacman -S clang)".to_string())?;

    if !output.status.success() {
        return Err("clang command failed".to_string());
    }

    let version_str = String::from_utf8_lossy(&output.stdout);

    // Parse version from output like "clang version 15.0.0"
    for line in version_str.lines() {
        if line.contains("clang version") {
            if let Some(version_part) = line.split_whitespace().nth(2) {
                if let Some(major_str) = version_part.split('.').next() {
                    if let Ok(major) = major_str.parse::<u32>() {
                        return Ok(major);
                    }
                }
            }
        }
    }

    Err("Could not parse clang version".to_string())
}

fn check_bpftool() -> Result<(), String> {
    let output = Command::new("bpftool")
        .arg("--version")
        .output()
        .map_err(|_| "bpftool not found - install bpftool package (apt install bpftool / dnf install bpftool / pacman -S bpf)".to_string())?;

    if !output.status.success() {
        return Err("bpftool command failed".to_string());
    }

    // Just verify it runs successfully, version parsing is less critical for bpftool
    Ok(())
}

fn check_btf_support() -> Result<(), String> {
    if !std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
        return Err(
            "BTF support not available - /sys/kernel/btf/vmlinux does not exist\n    Your kernel was not compiled with CONFIG_DEBUG_INFO_BTF=y\n    This is required for CO-RE (Compile Once Run Everywhere) support".to_string()
        );
    }
    Ok(())
}

fn check_kernel_version() -> Result<(u32, u32), String> {
    let output = Command::new("uname")
        .arg("-r")
        .output()
        .map_err(|_| "Could not detect kernel version".to_string())?;

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

fn check_architecture() -> Result<(), String> {
    let output = Command::new("uname")
        .arg("-m")
        .output()
        .map_err(|_| "Could not detect architecture".to_string())?;

    let arch = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if arch != "x86_64" {
        return Err(format!(
            "Architecture '{}' not supported - only x86_64 is currently supported\n    To add support for other architectures, modify build.rs to change -D__TARGET_ARCH_x86",
            arch
        ));
    }

    Ok(())
}

fn detect_distribution() -> Option<&'static str> {
    // Try to detect distribution from /etc/os-release
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        let content_lower = content.to_lowercase();
        if content_lower.contains("ubuntu") {
            return Some("ubuntu");
        } else if content_lower.contains("debian") {
            return Some("debian");
        } else if content_lower.contains("fedora") {
            return Some("fedora");
        } else if content_lower.contains("rhel") || content_lower.contains("red hat") {
            return Some("rhel");
        } else if content_lower.contains("centos") {
            return Some("centos");
        } else if content_lower.contains("arch") {
            return Some("arch");
        }
    }
    None
}
