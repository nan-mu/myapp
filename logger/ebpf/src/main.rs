#![no_std]
#![no_main]

include!(concat!(env!("OUT_DIR"), "/const_gen.rs"));


use aya_ebpf::{
    bindings::xdp_action,
    macros::xdp,
    programs::XdpContext,
};

use aya_log_ebpf::debug;
use network_types::{eth::EthHdr, ip::Ipv4Hdr, tcp::TcpHdr};

#[xdp]
pub fn logger(ctx: XdpContext) -> u32 {
    match try_logger(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_logger(ctx: XdpContext) -> Result<u32, ()> {
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

    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    if unsafe { (*tcphdr).dest } == MARK.port {
        return Ok(xdp_action::XDP_PASS);
    }

    debug!(
        &ctx,
        "get TCP pack with checksum {}",
        unsafe { (*tcphdr).check }
    );

    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    unsafe {
        (*(ethhdr as *mut EthHdr)).src_addr = MAC.sensor;
    }

    debug!(&ctx, "pack reach XDP_PASS with TCP checksum 0x{:x}", unsafe { (*tcphdr).check });
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
