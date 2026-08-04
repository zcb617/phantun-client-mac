#!/bin/zsh
set -euo pipefail

build_root=$(cd "$(dirname "$0")" && pwd)
cd "$build_root"

for target in x86_64-apple-darwin aarch64-apple-darwin; do
  target_libdir=$(rustc --print target-libdir --target "$target")
  if [[ ! -d "$target_libdir" ]]; then
    print -u2 "缺少 Rust 目标 $target。请使用 rustup 安装两个 macOS 目标后再执行本脚本。"
    exit 1
  fi
done

cargo build --release --bin phantun-client --target x86_64-apple-darwin
cargo build --release --bin phantun-client --target aarch64-apple-darwin

mkdir -p dist
lipo -create \
  target/x86_64-apple-darwin/release/phantun-client \
  target/aarch64-apple-darwin/release/phantun-client \
  -output dist/phantun-client

file dist/phantun-client
