#![no_std]
#![no_main]

use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::RingBuf,
    programs::XdpContext,
};

use aya_log_ebpf::{debug, error, info};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, tcp::TcpHdr};

// mod csum;

#[xdp]
pub fn hardworker(ctx: XdpContext) -> u32 {
    match try_hardworker(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

// 计划传输几个u64大小
const U64_COUNT: usize = 150;
const DATA_SIZE: usize = U64_COUNT * 8;
const _: [(); 1] = [(); (DATA_SIZE <= 1212) as usize]; // 保守负载大小
const DSTIP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 93); // logger ip

#[map(name = "TARGET_MAP")]
static mut TARGET_MAP: RingBuf = RingBuf::with_byte_size((DATA_SIZE) as u32, 0);

fn try_hardworker(ctx: XdpContext) -> Result<u32, ()> {
    const TARGET_TOS: u8 = 0b01101000;

    // 编译时断言
    // 确保TOS字段的最后一位为0符合TOS字段要求
    // 确保前三位不为001和000避免与已定义TOS类型冲突
    // tos字段前三位弃用，所以将标识为0x011xxxxx应该不会和其他包冲突
    const _: [(); 1] = [(); (TARGET_TOS & 0b00000001 == 0b00000000) as usize];
    const _: [(); 1] = [(); (TARGET_TOS & 0b11100000 != 0b00000000) as usize];
    const _: [(); 1] = [(); (TARGET_TOS & 0b11100000 != 0b00100000) as usize];

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    match unsafe { (*ipv4hdr).tos } {
        TARGET_TOS => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // 以下确定是目的数据包
    info!(&ctx, "get");

    // 只处理携带负载的tcp
    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    debug!(
        &ctx,
        "TCP flags: FIN={}, SYN={}, RST={}, PSH={}, ACK={}, URG={}",
        unsafe { (*tcphdr).fin() },
        unsafe { (*tcphdr).syn() },
        unsafe { (*tcphdr).rst() },
        unsafe { (*tcphdr).psh() },
        unsafe { (*tcphdr).ack() },
        unsafe { (*tcphdr).urg() }
    );
    if unsafe { (*tcphdr).psh() } == 1 {
        unsafe {
            #[allow(static_mut_refs)]
            let reserved = TARGET_MAP.reserve::<[u64; U64_COUNT]>(0);
            match reserved {
                Some(mut entry) => {
                    // 拷贝DATA_SIZE字节数据到ring_buf
                    if let Ok(data) = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) {
                        entry.write(*data);
                    };
                    entry.submit(0);
                }
                None => error!(&ctx, "ring_buf full"),
            }
        }
    }

    // 修改数据包发送字段，传输到日志器
    unsafe {
        let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
        let ethhdr_ptr: *const [u8; EthHdr::LEN] = ptr_at(&ctx, 0)?;
        // for i in 0..EthHdr::LEN {
        //     debug!(&ctx, "ethhdr[{}]: 0x{:x}", i, (*ethhdr_ptr)[i]);
        // }
        // [0x54, 0x6c, 0xeb, 0x72, 0xbd, 0x84] for pc 96
        // [0x2c, 0xcf, 0x67, 0x3e, 0x3b, 0x03] for logger test2 79
        // [0x2c, 0xcf, 0x67, 0x3e, 0x3a, 0x02] for test1 93
        (*(ethhdr as *mut EthHdr)).src_addr = [0x2c, 0xcf, 0x67, 0x3e, 0x3b, 0x03];
        (*(ethhdr as *mut EthHdr)).dst_addr = [0x2c, 0xcf, 0x67, 0x3e, 0x3a, 0x02];
        // for i in 0..EthHdr::LEN {
        //     debug!(&ctx, "changed ethhdr[{}]: 0x{:x}", i, (*ethhdr_ptr)[i]);
        // }

        debug!(
            &ctx,
            "changed ethhdr src_addr: 0x{:x}",
            (*ethhdr).src_addr[5]
        );
        debug!(
            &ctx,
            "changed ethhdr dst_addr: 0x{:x}",
            (*ethhdr).dst_addr[5]
        );

        let ip_csum = (*ipv4hdr).check.swap_bytes();
        let tcp_csum = (*tcphdr).check.swap_bytes();
        debug!(&ctx, "old ip csum: 0x{:x}", ip_csum);
        debug!(&ctx, "old tcp csum: 0x{:x}", tcp_csum);

        let old_ip = (*ipv4hdr).dst_addr.swap_bytes() as u16;
        const NEW_IP: u16 = u16::from_be_bytes([DSTIP.octets()[2], DSTIP.octets()[3]]);
        debug!(&ctx, "old ip: 0x{:x}", old_ip);
        debug!(&ctx, "new ip: 0x{:x}", NEW_IP);

        let ip_csum = update_checksum(ip_csum, old_ip, NEW_IP);
        let tcp_csum = update_checksum(tcp_csum, old_ip, NEW_IP);

        debug!(&ctx, "new ip csum: 0x{:x}", ip_csum);
        debug!(&ctx, "new tcp csum: 0x{:x}", tcp_csum);

        (*(ipv4hdr as *mut Ipv4Hdr)).dst_addr = DSTIP.to_bits().swap_bytes();
        (*(ipv4hdr as *mut Ipv4Hdr)).check = ip_csum.swap_bytes();
        (*(tcphdr as *mut TcpHdr)).check = tcp_csum.swap_bytes();

        // 打印ipv4头部所有字段，一行一行打印
        // debug!(
        //     &ctx,
        //     "ipv4hdr version: {}",
        //     unsafe { (*ipv4hdr).version }
        // );
        // debug!(
        //     &ctx,
        //     "ipv4hdr ihl: {}",
        //     unsafe { (*ipv4hdr).ihl }
        // );
        debug!(&ctx, "ipv4hdr tos: 0x{:x}", (*ipv4hdr).tos);
        debug!(&ctx, "ipv4hdr total_len: {}", (*ipv4hdr).tot_len.swap_bytes());
        debug!(&ctx, "ipv4hdr check: 0x{:x}", (*ipv4hdr).check.swap_bytes());
        debug!(&ctx, "ipv4hdr src_addr: 0x{:x}", (*ipv4hdr).src_addr.swap_bytes());
        debug!(&ctx, "ipv4hdr dst_addr: 0x{:x}", (*ipv4hdr).dst_addr.swap_bytes());
    }

    debug!(&ctx, "Returning XDP action: XDP_TX");
    Ok(xdp_action::XDP_TX)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = ::core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

/// 通过差异增量计算新的IP校验和
/// 注意所有字段应当按照小端（be）顺序存储
/// # 参数
/// * `old_csum` - 原始校验和
/// * `old` - 被修改的16位值
/// * `new` - 新的16位值
///
/// # 返回值
/// 更新后的校验和
#[inline(always)]
fn update_checksum(old_csum: u16, old: u16, new: u16) -> u16 {
    // 计算增量: 从旧校验和中减去旧值，加上新值
    let mut csum = !old_csum as u32; // 校验和取反得到和
    csum = csum.wrapping_sub(old as u32).wrapping_add(new as u32); // 更新和

    // 处理进位
    let csum = (csum >> 16) + (csum & 0xFFFF);
    let csum = csum + (csum >> 16);

    (!csum as u16) & 0xFFFF // 再次取反得到新校验和
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
