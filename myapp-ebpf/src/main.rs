#![no_std]
#![no_main]

use core::net::Ipv4Addr;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::RingBuf,
    programs::XdpContext,
};

use aya_log_ebpf::error;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    tcp::TcpHdr,
};

#[xdp]
pub fn myapp(ctx: XdpContext) -> u32 {
    match try_myapp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

// 计划传输几个u64大小
const U64_COUNT: usize = 150;
const DATA_SIZE: usize = U64_COUNT * 8;
const _: [(); 1] = [(); (DATA_SIZE <= 1212) as usize]; // 保守负载大小
const DSTIP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 96); // logger ip

// 临时校验和，源字段为
// 00000000  45 68 7f fc 06 c1 00 00 40 fd 00 00 c0 a8 01 5d   |Eh......@......]|
// 00000010  c0 a8 01 5d                                       |...]|
const CHECK: u16 = 0x4D4F;

#[map(name = "TARGET_MAP")]
static mut TARGET_MAP: RingBuf = RingBuf::with_byte_size((DATA_SIZE) as u32, 0);

fn try_myapp(ctx: XdpContext) -> Result<u32, ()> {
    // 理论上，该程序只会关注特定的数据包，所以将优先判断最小概率条件
    // 最小条件下，数据包包含完整ip头部并且ip头部的服务字段为44（CS5关键业务）
    // DATA_SIZE为传感器传输的数据大小，两个u64。
    if ctx.data() + EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN + DATA_SIZE > ctx.data_end() {
        return Ok(xdp_action::XDP_PASS);
    }

    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

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

    // 只处理携带负载的tcp
    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
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
        core::mem::swap(
            &mut (*(ethhdr as *mut EthHdr)).dst_addr,
            &mut (*(ethhdr as *mut EthHdr)).src_addr,
        );
        (*(ipv4hdr as *mut Ipv4Hdr)).set_dst_addr(DSTIP);
        (*(ipv4hdr as *mut Ipv4Hdr)).check = CHECK;
    };

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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
