# myapp

An eBPF-based communication middleware validation demo.

I should come up with a good name later.

## Known

A significant performance gap has been observed between the Raspberry Pi environment (native Linux kernel environment) and WSL (escaped kernel environment). Using 4KB and 1000Hz as strict conditions, the success rate on the Raspberry Pi was 90.158% and 85.972%.

I strongly recommend avoiding running it on WSL. I don't know what other issues my computer might have, but 85.972% was the data collected shortly after booting. Sometimes, under the same conditions, I get around 60%. Additionally, more buffer overflows were observed under WSL.

## TODO

- [ ] Use YAML instead of command-line arguments as startup parameters
- [ ] Rewrite the Python raw IPv4 script using Rust

## Synchronize Code

```shell
while inotifywait -r -e modify,create,delete,move ./; do
    rsync -av --delete --exclude-from='.gitignore' --exclude='.git/' ./ labpi:myapp/ # For single synchronization, just run this
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
