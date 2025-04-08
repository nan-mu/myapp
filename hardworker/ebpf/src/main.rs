#![no_std]
#![no_main]

include!(concat!(env!("OUT_DIR"), "/const_gen.rs"));

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::RingBuf,
    programs::XdpContext,
};

use aya_log_ebpf::{debug, error};
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
const DATA_SIZE: usize = DATA.load_u64_count * 8;
const _: [(); 1] = [(); ((DATA_SIZE + Ipv4Hdr::LEN + TcpHdr::LEN) <= DATA.mtu) as usize]; // 保守负载大小

#[map(name = "TARGET_MAP")]
static mut TARGET_MAP: RingBuf = RingBuf::with_byte_size((DATA_SIZE) as u32, 0);

fn try_hardworker(ctx: XdpContext) -> Result<u32, ()> {
    const TARGET_TOS: u8 = MARK.tos;

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

    // 我发现光一个tos还是不够，加一个tcp端口号
    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    if unsafe { (*tcphdr).dest } == MARK.port.swap_bytes() {
        return Ok(xdp_action::XDP_PASS);
    }

    debug!(
        &ctx,
        "get TCP {} pack",
        if unsafe { (*tcphdr).fin() } == 1 {
            "FIN"
        } else if unsafe { (*tcphdr).syn() } == 1 {
            "SYN"
        } else if unsafe { (*tcphdr).rst() } == 1 {
            "RST"
        } else if unsafe { (*tcphdr).psh() } == 1 {
            "PSH"
        } else if unsafe { (*tcphdr).ack() } == 1 {
            "ACK"
        } else if unsafe { (*tcphdr).urg() } == 1 {
            "URG"
        } else {
            "ERR"
        }
    );

    if unsafe { (*tcphdr).psh() } == 1 {
        unsafe {
            #[allow(static_mut_refs)]
            let reserved = TARGET_MAP.reserve::<[u64; DATA.load_u64_count]>(0);
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
        (*(ethhdr as *mut EthHdr)).src_addr = MAC.hardworker;
        (*(ethhdr as *mut EthHdr)).dst_addr = MAC.logger;

        let ip_csum = (*ipv4hdr).check.swap_bytes();
        let tcp_csum = (*tcphdr).check.swap_bytes();

        let old_ip = (*ipv4hdr).dst_addr.swap_bytes() as u16;
        const NEW_IP: u16 = u16::from_be_bytes([IP.logger.octets()[2], IP.logger.octets()[3]]);

        let ip_csum = update_checksum(ip_csum, old_ip, NEW_IP);
        let tcp_csum = update_checksum(tcp_csum, old_ip, NEW_IP);

        (*(ipv4hdr as *mut Ipv4Hdr)).dst_addr = IP.logger.to_bits().swap_bytes();
        (*(ipv4hdr as *mut Ipv4Hdr)).check = ip_csum.swap_bytes();
        (*(tcphdr as *mut TcpHdr)).check = tcp_csum.swap_bytes();
    }

    debug!(
        &ctx,
        "pack reach XDP_TX with TCP checksum: 0x{:x}",
        unsafe { (*tcphdr).check.swap_bytes() }
    );
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
