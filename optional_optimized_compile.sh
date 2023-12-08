#!/bin/sh

RUSTFLAGS="-Ctarget-cpu=native -Ztune-cpu=native \
-Clink-arg=-flto=thin -Clto=thin -Zdylib-lto -Copt-level=3 -Ccodegen-units=1 \
-Cpanic=abort -Cembed-bitcode=yes -Cforce-frame-pointers=n -Cdebug-assertions=no -Coverflow-checks=no\
 -Ccontrol-flow-guard=no -Clink-dead-code=no" \
 cargo build --release --target x86_64-unknown-linux-gnu -Zbuild-std=panic_abort,core,std,alloc,proc_macro,compiler_builtins \
 && strip ./target/x86_64-unknown-linux-gnu/release/faf-dns-proxy
