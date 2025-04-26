#![no_std]
#![no_main]

include!(concat!(env!("OUT_DIR"), "/const_gen.rs"));

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::RingBuf,
    programs::XdpContext,
};
use aya_log_ebpf::debug;
use core::ops::Add;
use network_types::{
    eth::EthHdr,
    ip::Ipv4Hdr,
    tcp::TcpHdr,
};

#[xdp]
pub fn hardworker(ctx: XdpContext) -> u32 {
    match try_hardworker(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

// 计划传输几个u64大小
const RING_BUF_SIZE: u32 = 16 * (DATA.mtu) as u32;
const _: [(); 1] = [(); ((DATA.size + Ipv4Hdr::LEN + TcpHdr::LEN) <= DATA.mtu) as usize]; // 保守负载大小
const _: [(); 1] = [(); (RING_BUF_SIZE as usize <= 256 * 1024) as usize]; // 保守ringbuf大小

#[map(name = "TARGET_MAP")]
static mut TARGET_MAP: RingBuf = RingBuf::with_byte_size(RING_BUF_SIZE, 0);

#[repr(C)]
struct LoadData {
    pub data_len: u16,
    pub data: [u8; DATA.mtu],
}

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
        TARGET_TOS => {
            // debug!(&ctx, "hit tos");
        }
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // 我发现光一个tos还是不够，加一个tcp端口号
    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

    if unsafe { (*tcphdr).dest } != MARK.port.swap_bytes() {
        return Ok(xdp_action::XDP_PASS);
    }

    let start = unsafe {
        ctx.data()
            .add(EthHdr::LEN + Ipv4Hdr::LEN + ((*tcphdr).doff() * 4) as usize)
    };
    let end = ctx.data_end();
    let size = end.saturating_sub(start as usize);

    // 判断是否存在负载数据
    if size > 0 && size < 4096 {
        #[allow(static_mut_refs)]
        if let Some(mut event) = unsafe { TARGET_MAP.reserve::<LoadData>(0) } {
            let ptr = event.as_mut_ptr();
            unsafe {
                (*ptr).data_len = size as u16;
                core::ptr::copy_nonoverlapping(start as *const u8, (*ptr).data.as_mut_ptr(), size);
            }
        }
    }

    // 发送数据负载到ringbuf
    // if unsafe { (*tcphdr).psh() } == 1 {
    //     #[allow(static_mut_refs)]
    //     let scratch = unsafe { SCRATCH_BUF.get_ptr_mut(0).ok_or(())? };
    //     let buf = unsafe { &mut *scratch };
    //     let size = get_tcp_payload(&ctx, tcphdr, buf)?;
    //     #[allow(static_mut_refs)]
    //     let result = unsafe { TARGET_MAP.output(&buf[..size], 0) };
    //     match result {
    //         Ok(_) => {
    //             debug!(&ctx, "output data size: {}", size);
    //         }
    //         Err(err) => {
    //             error!(&ctx, "output data failed: {}", err);
    //         }
    //     }
    // }

    // 修改数据包发送字段，传输到日志器
    unsafe {
        let ethhdr: *mut EthHdr = ptr_at_mut(&ctx, 0)?;
        (*ethhdr).src_addr = MAC.hardworker;
        (*ethhdr).dst_addr = MAC.logger;

        let ip_csum = (*ipv4hdr).check.swap_bytes();
        let tcp_csum = (*tcphdr).check.swap_bytes();

        let old_ip = (*ipv4hdr).dst_addr.swap_bytes() as u16;
        const NEW_IP: u16 = u16::from_be_bytes([IP.logger.octets()[2], IP.logger.octets()[3]]);

        let ip_csum = update_checksum(ip_csum, old_ip, NEW_IP);
        let tcp_csum = update_checksum(tcp_csum, old_ip, NEW_IP);

        let ipv4hdr = ipv4hdr as *mut Ipv4Hdr;
        let tcphdr = tcphdr as *mut TcpHdr;

        (*ipv4hdr).dst_addr = IP.logger.to_bits().swap_bytes();
        (*ipv4hdr).check = ip_csum.swap_bytes();
        (*tcphdr).check = tcp_csum.swap_bytes();
    }

    debug!(
        &ctx,
        "pack reach XDP_TX with src: {}, dst: {}, {} pack, csum: 0x{:x}",
        unsafe { (*tcphdr).source.swap_bytes() },
        unsafe { (*tcphdr).dest.swap_bytes() },
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
        },
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

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = ::core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
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
