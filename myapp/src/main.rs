use anyhow::Context as _;
use aya::{
    maps::RingBuf,
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::{io::unix::AsyncFd, signal};
#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
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
        "/myapp"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("初始化ebpf日志器失败: {}", e);
    }
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("myapp").unwrap().try_into()?;
    program.load()?;
    program
        .attach(&iface, XdpFlags::default())
        .context("默认flag连接xdp失败，考虑特定flag")?;

    let (shutdown, mut rx) = tokio::sync::oneshot::channel();

    tokio::task::spawn(async move {
        let ring_buffer = RingBuf::try_from(
            ebpf.map_mut("TARGET_MAP")
                .expect("找不到Map，考虑ebpf程序未正常加载"),
        )
        .expect("无法使用Map");
        let mut poll = AsyncFd::new(ring_buffer).expect("创建AsyncFd失败");

        let mut data = [0u64; 3];
        let mut success = 0 as u64;
        let mut fail = 0 as u64;

        loop {
            tokio::select! {
                _ = &mut rx => {
                    println!("成功次数: {}, 失败次数: {}", success, fail);
                    break;
                }
                guard = poll.readable_mut() => {
                    let mut guard = guard.unwrap();
                    while let Some(new_data) = guard.get_inner_mut().next() {
                        if new_data.len() == std::mem::size_of::<[u64; 3]>() {
                            let new_data = unsafe {
                                std::ptr::read_unaligned(new_data.as_ptr() as *const [u64; 3])
                            };
                            if data == [0, 0, 0] {
                                data = new_data;
                            } else {
                                if data[0] == new_data[0] {
                                    // 模糊匹配，我简单认为没必要每个字节都一样
                                    success += 1;
                                } else {
                                    fail += 1;
                                }
                                data = [0, 0, 0];
                            }
                        } else {
                            fail += 1;
                        }
                    }
                }
            }
        }
    });

    let ctrl_c = signal::ctrl_c();
    println!("准备完成，等待Ctrl-C退出...");
    ctrl_c.await?;
    println!("退出...");
    shutdown
        .send(())
        .expect("发送关闭信号失败，考虑子线程出错或外部干预");

    Ok(())
}
