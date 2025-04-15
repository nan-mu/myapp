#![no_std]
#![no_main]

include!(concat!(env!("OUT_DIR"), "/const_gen.rs"));

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

use aya_log_ebpf::debug;
use network_types::{eth::EthHdr, ip::Ipv4Hdr, tcp::TcpHdr};

#[xdp]
pub fn sensor(ctx: XdpContext) -> u32 {
    match try_sensor(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_sensor(ctx: XdpContext) -> Result<u32, ()> {
    // const TARGET_TOS: u8 = MARK.tos;

    // // 编译时断言
    // // 确保TOS字段的最后一位为0符合TOS字段要求
    // // 确保前三位不为001和000避免与已定义TOS类型冲突
    // // tos字段前三位弃用，所以将标识为0x011xxxxx应该不会和其他包冲突
    // const _: [(); 1] = [(); (TARGET_TOS & 0b00000001 == 0b00000000) as usize];
    // const _: [(); 1] = [(); (TARGET_TOS & 0b11100000 != 0b00000000) as usize];
    // const _: [(); 1] = [(); (TARGET_TOS & 0b11100000 != 0b00100000) as usize];

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    // match unsafe { (*ipv4hdr).tos } {
    //     TARGET_TOS => {}
    //     _ => return Ok(xdp_action::XDP_PASS),
    // }

    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    if unsafe { (*tcphdr).source } != MARK.port.swap_bytes() {
        return Ok(xdp_action::XDP_PASS);
    }

    // 修改数据包发送字段，传输到日志器
    unsafe {
        // 修改mac地址从logger到hardworker
        let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
        (*(ethhdr as *mut EthHdr)).src_addr = MAC.hardworker;

        let ip_csum = (*ipv4hdr).check.swap_bytes();
        let tcp_csum = (*tcphdr).check.swap_bytes();

        let old_ip = (*ipv4hdr).src_addr.swap_bytes() as u16;
        const NEW_IP: u16 =
            u16::from_be_bytes([IP.hardworker.octets()[2], IP.hardworker.octets()[3]]);

        let ip_csum = update_checksum(ip_csum, old_ip, NEW_IP);
        let tcp_csum = update_checksum(tcp_csum, old_ip, NEW_IP);

        // 更新ip从logger到hardworker并更新校验和
        (*(ipv4hdr as *mut Ipv4Hdr)).src_addr = IP.hardworker.to_bits().swap_bytes();
        (*(ipv4hdr as *mut Ipv4Hdr)).check = ip_csum.swap_bytes();
        (*(tcphdr as *mut TcpHdr)).check = tcp_csum.swap_bytes();
    }

    debug!(
        &ctx,
        "pack reach XDP_PASS with TCP checksum: 0x{:x}",
        unsafe { (*tcphdr).check.swap_bytes() }
    );
    Ok(xdp_action::XDP_PASS)
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
