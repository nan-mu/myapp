# myapp

An eBPF-based communication middleware validation demo. The core process will be supplemented after the code work is completed.

I should come up with a good name later.

## Known

The research goal is now shifting from throughput to a practical scenario, with fixed frequency and data volume, and using ebpf to reduce the overhead on the target machine.

Currently writing the measurement program in the benchmark branch. The following are some related term explanations:

* sensor: The data sender wants to send data to the hardworker for processing.
* hardworker: Receive data from the sensor. Assuming that the device completes important logical decisions, we hope to reduce the resource overhead of the device in communication while obtaining TCP type communication guarantees.
* logger: Receive data packets from the network and convert them into logs and store them in its own database.

### issues

Although TCP communication was successful before, the following problems were found:

1. Sensor lost hardworker's mac address, logger lost sensor's mac address.
  1. `arp -n` shows these mac are `incomplete`.
  1. Communication returned to normal after manually fixing the mac after using `sudo arp -s <ip> <mac>`
1. Windows(use ssh control all of them) shows sensor is Unreachable.
  1. `ping` show that.
  1. After using `route -p add <sensor ip> MASK <mask> <net gate ip> IF 3` communication returned.

I think the above reason is another reason to write a daemon. I expect the daemon to fix these mac addresses in advance and compile a specific ebpf program.

## TODO

- [ ] Rewrite the Python raw IPv4 script using Rust
- [ ] Write a simulated load to measure the system load with the same amount of data and user-mode handler programs
- [ ] Write a benchmark to measure the reduction of system load

## Synchronize Code

Now there is no need for heavy testing, use git pull to synchronize the code

## Prerequisites

> ### TL&DR
> ```bash
> #install Rust and have Cargo env first
> rustup toolchain install stable && \
> rustup toolchain install nightly --component rust-src && \
> cargo install bpf-linker && \
> git clone https://www.github.com/nan-mu/myapp.git && cd myapp && \
> #And go to the folder you want to run
> ```

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
