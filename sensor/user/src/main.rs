use clap::Parser;
use config::TcpConfig;
use log::{debug, warn};
use tcp::TcpHandler;
use tokio::time::{sleep, Duration};

mod tcp;
mod config;
mod ebpf;

use ebpf::EbpfBuilder;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "../config.toml")]
    config: String,
    #[clap(short, long, default_value = "../const.toml")]
    consts: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt: Opt = Opt::parse();
    let Opt { config, consts } = opt;

    let config = TcpConfig::build(config, consts)?;

    let _ebpf = EbpfBuilder::build(config.ifname.clone())
        .cancel_memlock()?
        .build_xdp()?;
    debug!("ebpf构建完成");

    let tcp_client = TcpHandler::from(config);
    let tcp_shutdown_tx = tcp_client.get_signal();
    
    // 启动TCP客户端
    tcp_client.start().await?;
    debug!("TCP客户端启动完成");

    let sig_int = tokio::signal::ctrl_c();
    println!("准备完成，等待Ctrl-C或超时退出...");

    tokio::select! {
        _ = sig_int => {
            println!("\nCtrl+c退出...");
        }
        _ = sleep(Duration::from_secs(1000)) => {
            println!("\n超时退出...");
        }
    }

    // 发送关闭信号给TCP客户端
    if let Err(e) = tcp_shutdown_tx.send(()).await {
        warn!("发送TCP关闭信号失败: {:?}", e);
    }

    println!("程序退出");
    Ok(())
}
