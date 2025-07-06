#!/bin/sh

# Optimized build using .cargo/config.toml for per-crate rustflags
cargo +nightly build --release -p faf-dns-proxy --features ebpf-client-ident --target x86_64-unknown-linux-gnu \
 -Zbuild-std=panic_abort,core,std,alloc,proc_macro,compiler_builtins \
 && strip ./target/x86_64-unknown-linux-gnu/release/faf-dns-proxy
