#!/bin/sh

RUSTFLAGS="-Zcf-protection=none -Ccontrol-flow-guard=off \
-Ctarget-cpu=native -Ztune-cpu=native -Clinker=/usr/bin/clang -Clink-arg=-fuse-ld=/usr/bin/ld.lld \
-Clink-arg=-flto=thin -Clto=thin -Zdylib-lto -Copt-level=3 -Ccodegen-units=1 \
-Cpanic=abort -Cembed-bitcode=yes -Cforce-frame-pointers=n -Cdebug-assertions=no -Coverflow-checks=no\
 -Ccontrol-flow-guard=no -Clink-dead-code=no" \
 cargo +nightly build --release  --target x86_64-unknown-linux-gnu -Zbuild-std=panic_abort,core,std,alloc,proc_macro,compiler_builtins \
 && strip ./target/x86_64-unknown-linux-gnu/release/faf-dns-proxy
