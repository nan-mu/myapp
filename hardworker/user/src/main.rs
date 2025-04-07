include!(concat!(env!("OUT_DIR"), "/const_gen.rs"));

use anyhow::Context as _;
use aya::{
    maps::RingBuf,
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::{
    io::unix::AsyncFd,
    time::{sleep, Duration},
};

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
        "/hardworker"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("初始化ebpf日志器失败: {}", e);
    }
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("hardworker").unwrap().try_into()?;
    program.load()?;
    program
        .attach(&iface, XdpFlags::default())
        .context("默认flag连接xdp失败，考虑特定flag")?;

    let (shutdown, rx) = tokio::sync::oneshot::channel();

    let handle = tokio::task::spawn(async move {
        println!("工作线程TID: {}", unsafe {
            libc::syscall(libc::SYS_gettid)
        });

        let ring_buffer = RingBuf::try_from(
            ebpf.map_mut("TARGET_MAP")
                .expect("找不到Map，考虑ebpf程序未正常加载"),
        )
        .expect("无法使用Map");
        let mut poll = AsyncFd::new(ring_buffer).expect("创建AsyncFd失败");

        #[derive(Debug, Default, Clone, Copy)]
        struct FaillType {
            match_fail: u64,
            align_fail: u64,
            guard_fail: u64,
        }

        let (tx_success, rx_success) = tokio::sync::watch::channel(0 as u64);
        let (tx_fail, rx_fail) = tokio::sync::watch::channel(FaillType::default());

        let mut handle = async move || {
            let mut success = 0 as u64;
            let mut fail = FaillType::default();
            let mut data = [0u64; DATA.load_u64_count];
            loop {
                while let Ok(mut guard) = poll.readable_mut().await {
                    if let Some(new_data) = guard.get_inner_mut().next() {
                        if new_data.len() == std::mem::size_of::<[u64; DATA.load_u64_count]>() {
                            let val = unsafe {
                                std::ptr::read_unaligned(
                                    new_data.as_ptr() as *const [u64; DATA.load_u64_count]
                                )
                            };
                            drop(new_data);
                            if data[0] == 0 {
                                data = val;
                                success += 1;
                                tx_success
                                    .send(success)
                                    .expect("发送成功次数失败，考虑外部干预");
                                println!("工作线程第一次成功");
                                // Print the data in hexdump format
                                let bytes: Vec<u8> = data.iter()
                                    .flat_map(|&val| val.to_le_bytes().to_vec())
                                    .collect();

                                for (i, chunk) in bytes.chunks(16).enumerate() {
                                    // Print the offset
                                    print!("{:08x}  ", i * 16);
                                    
                                    // Print hex values
                                    for &byte in chunk {
                                        print!("{:02x} ", byte);
                                    }
                                    
                                    // Add padding if needed
                                    for _ in 0..(16 - chunk.len()) {
                                        print!("   ");
                                    }
                                    
                                    // Print ASCII representation
                                    print!(" |");
                                    for &byte in chunk {
                                        let c = if byte >= 32 && byte <= 126 { byte as char } else { '.' };
                                        print!("{}", c);
                                    }
                                    println!("|");
                                }
                            } else {
                                // Check if all bytes match (full comparison)
                                if data == val {
                                    success += 1;
                                    tx_success
                                        .send(success)
                                        .expect("发送成功次数失败，考虑外部干预");
                                } else {
                                    fail.match_fail += 1;
                                    tx_fail.send(fail).expect("发送失败次数失败，考虑外部干预");
                                }
                                // if data[0] == val[0] {
                                //     // 模糊匹配，我简单认为没必要每个字节都一样
                                //     success += 1;
                                //     tx_success
                                //         .send(success)
                                //         .expect("发送成功次数失败，考虑外部干预");
                                // } else {
                                //     fail.match_fail += 1;
                                //     tx_fail.send(fail).expect("发送失败次数失败，考虑外部干预");
                                // }
                            }
                        } else {
                            fail.align_fail += 1;
                            tx_fail.send(fail).expect("发送失败次数失败，考虑外部干预");
                        }
                    } else {
                        fail.guard_fail += 1;
                        tx_fail.send(fail).expect("发送失败次数失败，考虑外部干预");
                        tokio::task::yield_now().await;
                    }
                }
            }
        };

        tokio::select! {
            _ = rx => {
                let (success, fail) = (*rx_success.borrow(), *rx_fail.borrow());
                println!("成功次数: {}, 失败次数: {:?}", success, fail);
            }
            _ = handle() => {
                println!("工作线程居然退出，考虑外部干预");
            }
        };
    });

    println!("主进程PID: {}", std::process::id());
    println!("主线程TID: {}", unsafe {
        libc::syscall(libc::SYS_gettid)
    });

    let sig_int = tokio::signal::ctrl_c();
    // let mut sig_int = signal(SignalKind::interrupt())?;

    println!("准备完成，等待Ctrl-C或超时退出...");

    tokio::select! {
        _ = sig_int => {
            println!("\nCtrl+c退出...");
            shutdown
                .send(())
                .expect("发送关闭信号失败，考虑子线程出错或外部干预，考虑sudo kill主线程");
        }
        _ = sleep(Duration::from_secs(1000)) => {
            println!("\n超时退出...");
            shutdown
                .send(())
                .expect("发送关闭信号失败，考虑子线程出错或外部干预，考虑sudo kill主线程");
        }
    }

    let _ = handle.await;

    Ok(())
}
