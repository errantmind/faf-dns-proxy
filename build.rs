use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Only build eBPF programs on Linux
    if env::var("CARGO_CFG_TARGET_OS").unwrap() != "linux" {
        return;
    }
    
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let src_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    
    // eBPF source file
    let ebpf_src = src_dir.join("src/bpf/socket_tracker.c");
    let ebpf_obj = out_dir.join("socket_tracker");
    
    // Check if clang is available for eBPF compilation
    if Command::new("clang").arg("--version").output().is_err() {
        println!("cargo:warning=clang not found - eBPF features will be disabled");
        
        // Create empty object file to avoid link errors
        fs::write(&ebpf_obj, &[]).expect("Failed to create empty eBPF object");
        return;
    }
    
    // Check if we have required headers
    let bpf_headers_exist = Command::new("clang")
        .args(&[
            "-E",
            "-I/usr/include",
            "-include", "linux/bpf.h",
            "-x", "c",
            "/dev/null"
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
        
    if !bpf_headers_exist {
        println!("cargo:warning=eBPF headers not found - install linux-headers or kernel-devel package");
        fs::write(&ebpf_obj, &[]).expect("Failed to create empty eBPF object");
        return;
    }
    
    println!("cargo:rerun-if-changed={}", ebpf_src.display());
    
    // Compile eBPF program with BTF generation
    let status = Command::new("clang")
        .args(&[
            "-O2",
            "-target", "bpf",
            "-c",
            ebpf_src.to_str().unwrap(),
            "-o", ebpf_obj.to_str().unwrap(),
            "-I/usr/include",
            "-g",  // Generate debug info for BTF
            "-Wall",
            "-Wextra",
        ])
        .status()
        .expect("Failed to execute clang");
        
    if !status.success() {
        println!("cargo:warning=eBPF compilation failed - eBPF features will be disabled");
        fs::write(&ebpf_obj, &[]).expect("Failed to create empty eBPF object");
    } else {
        println!("cargo:warning=eBPF program compiled successfully");
    }
}