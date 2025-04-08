use anyhow::Context as _;
use aya::programs::{Xdp, XdpFlags};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::time::{sleep, Duration};

// mod fd_handle;
#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlan0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/logger"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("初始化ebpf日志器失败: {}", e);
    }
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("logger").unwrap().try_into()?;
    program.load()?;
    program
        .attach(&iface, XdpFlags::default())
        .context("默认flag连接xdp失败，考虑特定flag")?;

    println!("主进程PID: {}", std::process::id());
    println!("主线程TID: {}", unsafe {
        libc::syscall(libc::SYS_gettid)
    });

    let sig_int = tokio::signal::ctrl_c();

    println!("准备完成，等待Ctrl-C或超时退出...");

    tokio::select! {
        _ = sig_int => {
            println!("\nCtrl+c退出...");
            // shutdown
            //     .send(())
            //     .expect("发送关闭信号失败，考虑子线程出错或外部干预，考虑sudo kill主线程");
        }
        _ = sleep(Duration::from_secs(1000)) => {
            println!("\n超时退出...");
            // shutdown
            //     .send(())
            //     .expect("发送关闭信号失败，考虑子线程出错或外部干预，考虑sudo kill主线程");
        }
    }

    Ok(())
}
