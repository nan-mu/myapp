include!(concat!(env!("OUT_DIR"), "/const_gen.rs"));

use anyhow::Context as _;
use clap::Parser;
use log::{debug, info};
use pidfile::PidFile;

mod ebpf;
mod fd_handle;

use ebpf::EbpfBuilder;

// mod fd_handle;
#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlan0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // let opt = Opt::parse();

    env_logger::init();

    // 创建pid文件
    let pidfile = PidFile::new("/var/run/hardworker.pid")?;

    let mut ebpf = EbpfBuilder::build("wlan0".into())
        .cancel_memlock()?
        .build_xdp()?;
    debug!("ebpf构建完成");

    let ringbuf_handler = ebpf.build_ringbuf_fd("TARGET_MAP".into())?;
    let (shutdown, success) = ringbuf_handler.start()?;

    let sig_int = tokio::signal::ctrl_c();
    // let mut sig_int = signal(SignalKind::interrupt())?;

    info!("准备完成，等待Ctrl-C或超时退出...");

    tokio::select! {
        _ = sig_int => {
            info!("\nCtrl+c退出...");

        }
        // _ = sleep(Duration::from_secs(1000)) => {
        //     info!("\n超时退出...");
        // }
    }

    shutdown
        .send(())
        .await.context("发送关闭信号失败，考虑子线程出错或外部干预，考虑sudo kill主线程")?;

    info!(
        "成功次数: {}",
        success.load(std::sync::atomic::Ordering::SeqCst)
    );

    drop(pidfile);

    Ok(())
}
