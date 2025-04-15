# myapp

基于ebpf的通信中间件验证demo。

之后应该会想一个好名字。

## 已知

观察到树莓派环境（原始linux内核环境）和wsl（转义内核环境）存在较大性能差距。使用4KB，1000Hz作为严格条件，树莓派成功率为90.158%，85.972%。

我强烈建议避免在wsl运行。我不知道我的电脑除了什么问题但85.972%是在开机后一小段时间得到的数据。有时该条件下我能得到60%左右。且在wsl下观察到更多次缓存区溢出。

## TODO

- [ ] 使用yaml而不是命令行参数作为启动参数
- [ ] 使用rust重写python的raw ipv4脚本

## 同步代码

```shell
while inotifywait -r -e modify,create,delete,move ./; do
    rsync -av --delete --exclude-from='.gitignore' --exclude='.git/' ./ labpi:myapp/ # 单次同步直接运行这个也行
done
```

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
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' # 建议添加为别名
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
