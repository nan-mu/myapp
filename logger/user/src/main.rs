use anyhow::Context;
use clap::Parser;
use log::{debug, info};
use pidfile::PidFile;
use std::future::pending;
use tokio::time::{sleep, Duration};

mod config;
mod ebpf;
mod tcp;

use config::TcpConfig;
use ebpf::EbpfBuilder;
use tcp::TcpHandler;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "../config.toml")]
    config: String,
    #[clap(short, long, default_value = "../const.toml")]
    consts: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    let Opt { config, consts } = opt;

    env_logger::init();

    // 创建pid文件
    let pidfile = PidFile::new("/var/run/logger.pid")?;

    let config = TcpConfig::build(config, consts)?;
    let timeout = config.timeout;

    let ebpf = match &config.target {
        config::Role::Hardworker => {
            info!("本机角色为 logger 根据配置文件目标角色缺省或为 Hardworker。ebpf将被构建");
            let ebpf = EbpfBuilder::build(config.ifname.clone())
                .cancel_memlock()?
                .build_xdp()?;
            debug!("ebpf构建完成");
            Some(ebpf)
        }
        target => {
            info!("本机角色为 logger 根据配置文件目标角色为 {target}。ebpf将不会被构建");
            None
        }
    };

    let tcp_server = TcpHandler::from(config);
    let tcp_shutdown_tx = tcp_server.get_signal();
    tcp_server.start().await?;

    let sig_int = tokio::signal::ctrl_c();

    info!("准备完成，等待Ctrl-C或超时退出...");

    tokio::select! {
        _ = sig_int => {
            info!("\nCtrl+c退出...");
        }
        _ = sleep_or_pending(timeout) => {
            info!("\n超时退出...");
        }
    }

    tcp_shutdown_tx
        .send(())
        .await
        .context("发送TCP关闭信号失败")?;

    drop(ebpf);
    drop(pidfile);

    Ok(())
}

async fn sleep_or_pending(timeout: Option<Duration>) {
    match timeout {
        Some(timeout) => sleep(timeout).await,
        None => pending().await,
    }
}
