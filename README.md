# myapp

基于ebpf的通信中间件验证demo

之后应该会想一个好名字

## 日志

现在进行了几次测试，发现程序只能在100Hz下工作良好。等效流量为4.8KB。我个人认为远未达到预期。现在考虑以下改进：
* 让程序工作在两个树莓派上，减少wsl可能带来的影响
* 现在ebpf的逻辑是正确的包会丢弃，考虑抓包检查它是否handle了所有目标流量。有漏的就说明性能不达标。
* 完善测试脚本，修改为Rust。

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package myapp --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/myapp` can be
copied to a Linux server or VM and run there.
