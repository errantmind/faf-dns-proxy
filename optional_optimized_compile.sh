#!/bin/sh
set -eu

# This is an optional host-specific build. Normal cargo commands deliberately
# use Cargo's standard profiles so checks and tests remain portable.
export RUSTFLAGS="-Zcf-protection=none -Ccontrol-flow-guard=off -Ctarget-cpu=native -Ztune-cpu=native -Clinker=/usr/bin/clang -Clink-arg=-fuse-ld=/usr/bin/ld.lld -Copt-level=3 -Ccodegen-units=1 -Cpanic=abort -Cembed-bitcode=yes -Cforce-frame-pointers=n -Cdebug-assertions=no -Coverflow-checks=no -Clink-dead-code=no"

cargo +nightly build --release -p faf-dns-proxy --features ebpf-client-ident --target x86_64-unknown-linux-gnu \
   -Zbuild-std=panic_abort,core,std,alloc,proc_macro,compiler_builtins
strip ./target/x86_64-unknown-linux-gnu/release/faf-dns-proxy
