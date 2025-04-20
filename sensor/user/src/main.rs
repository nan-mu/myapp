use clap::Parser;
use config::TcpConfig;
use log::{debug, info, warn};
use pidfile::PidFile;
use tcp::TcpHandler;
use tokio::time::{sleep, Duration};

mod config;
mod ebpf;
mod tcp;

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

    env_logger::init();

    // 创建pid文件
    let pidfile = PidFile::new("/var/run/sensor.pid")?;

    let config = TcpConfig::build(config, consts)?;

    match &config.target {
        config::Role::Hardworker => {
            info!("本机角色为 sensor 根据配置文件目标角色缺省或为 Hardworker。ebpf将被构建");
            let _ebpf = EbpfBuilder::build(config.ifname.clone())
                .cancel_memlock()?
                .build_xdp()?;
            debug!("ebpf构建完成");
        }
        target => {
            info!("本机角色为 sensor 根据配置文件目标角色为 {target}。ebpf将不会被构建");
        }
    }

    let tcp_client = TcpHandler::from(config);
    let tcp_shutdown_tx = tcp_client.get_signal();

    // 启动TCP客户端
    tcp_client.start().await?;
    debug!("TCP客户端启动完成");

    let sig_int = tokio::signal::ctrl_c();
    info!("准备完成，等待Ctrl-C或超时退出...");

    tokio::select! {
        _ = sig_int => {
            info!("\nCtrl+c退出...");
        }
        _ = sleep(Duration::from_secs(1000)) => {
            info!("\n超时退出...");
        }
    }

    // 发送关闭信号给TCP客户端
    if let Err(e) = tcp_shutdown_tx.send(()).await {
        warn!("发送TCP关闭信号失败: {:?}", e);
    }

    drop(pidfile);

    Ok(())
}
