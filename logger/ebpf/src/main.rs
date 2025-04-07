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
pub fn logger(ctx: XdpContext) -> u32 {
    match try_logger(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_logger(ctx: XdpContext) -> Result<u32, ()> {
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
