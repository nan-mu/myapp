use std::{future::pending, sync::atomic::Ordering, time::Duration};

use anyhow::Context as _;
use clap::Parser;
use config::Config;
use log::{debug, info};
use pidfile::PidFile;

mod ebpf;
mod fd_handle;
mod config;

use ebpf::EbpfBuilder;
use tokio::time::sleep;

// mod fd_handle;
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

    let config = Config::build(config, consts)?;
    let timeout = config.timeout;

    // 创建pid文件
    let pidfile = PidFile::new("/var/run/hardworker.pid")?;

    let mut ebpf = EbpfBuilder::build(config.ifname.clone())
        .cancel_memlock()?
        .build_xdp()?;
    debug!("ebpf构建完成");

    let ringbuf_handler = ebpf.build_ringbuf_fd("TARGET_MAP".into(), config.size)?;
    let (shutdown, success) = ringbuf_handler.start()?;

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

    shutdown
        .send(())
        .await
        .context("发送ring_buf关闭信号失败")?;

    info!("成功次数: {}", success.load(Ordering::SeqCst));

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
