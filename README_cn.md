# myapp

基于ebpf的通信中间件验证demo。核心流程将在代码工作完成后补充。

之后应该会想一个好名字。

## 已知

研究目标已从吞吐量转向为在实际场景的固定发信频率与大小下，使用ebpf降低目标机器的开销。

当前正在benchmark分支编写测量程序。以下为相关术语说明：

* sensor: 数据发送方，需向hardworker发送处理数据
* hardworker: 接收sensor数据。假设设备需完成重要逻辑决策，希望在获得TCP类型通信保障的同时降低设备在通信中的资源开销
* logger: 从网络接收数据包并转化为日志存储于自身数据库

### 问题记录

虽然此前TCP通信成功，但发现以下问题：

1. Sensor丢失hardworker的mac地址，logger丢失sensor的mac地址
  1. `arp -n`显示这些mac地址状态为`incomplete`
  1. 使用`sudo arp -s  `手动修复mac后通信恢复正常
1. Windows（通过SSH控制所有设备）显示sensor不可达
  1. `ping`命令验证该问题
  1. 使用`route -p add  MASK   IF 3`后通信恢复

认为上述问题是需要编写守护进程的另一原因，预期该守护进程可预先修复这些mac地址并编译特定ebpf程序。

## 待办事项

- [x] 使用Rust重写Python脚本
- [ ] 重写sensor接收ebpf数据的逻辑，测试时看到这里有些问题
- [ ] 编写模拟负载以测量同等数据量下系统负载与用户态处理程序
- [ ] 编写基准测试以测量系统负载降低效果

## 代码同步

当前无需重型测试，使用git pull同步代码即可

## 环境要求

> ### 快速指南
> ```bash
> # 首先安装Rust和Cargo环境
> rustup toolchain install stable && \
> rustup toolchain install nightly --component rust-src && \
> cargo install bpf-linker && \
> git clone https://www.github.com/nan-mu/myapp.git && cd myapp && \
> # 进入需要运行的目录
> ```

1. 稳定版Rust工具链: `rustup toolchain install stable`
1.  nightly版Rust工具链: `rustup toolchain install nightly --component rust-src`
1. (交叉编译时) rustup目标平台: `rustup target add ${ARCH}-unknown-linux-musl`
1. (交叉编译时) LLVM: 例如macOS使用`brew install llvm`
1. (交叉编译时) C工具链: 例如macOS使用[`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross)
1. bpf-linker: `cargo install bpf-linker` (macOS需添加`--no-default-features`参数)

## 构建与运行

常规使用`cargo build`、`cargo check`等命令。运行程序使用：

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

Cargo构建脚本会自动编译eBPF程序并集成到主程序中。

## macOS跨平台编译

支持Intel和Apple Silicon芯片的跨平台编译：

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package myapp --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
编译后的程序`target/${ARCH}-unknown-linux-musl/release/myapp`可复制到Linux服务器或虚拟机运行。

---
使用 Perplexity 翻译，正确内容见英文或email咨询