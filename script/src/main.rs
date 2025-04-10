use std::net::Ipv4Addr;

fn main() {
    let ipv4hdr = [
        0x6845, 0x3c00, 0xbef0, 0x0040, 0x0640,
        0x0000, 0xa8c0, 0x6001, 0xa8c0, 0x5d01,
    ]
    .map(|x| (x as u16).swap_bytes());
    
    println!("  ipv4头部: {:04x?}", ipv4hdr);
    let old_sum = ipv4_checksum(&ipv4hdr);
    let old_ip: u32 = (ipv4hdr[6] as u32) << 16 | (ipv4hdr[7] as u32);

    let mut ipv4hdr = ipv4hdr;
    let new_ip: u32 = Ipv4Addr::new(192, 168, 1, 79).to_bits();
    ipv4hdr[6] = (new_ip >> 16) as u16;
    ipv4hdr[7] = new_ip as u16;
    println!("新ipv4头部: {:04x?}", ipv4hdr);
    println!("IP更新从0x{:08x}到0x{:08x}", old_ip, new_ip);
    println!("旧校验和: {:04x}", old_sum);
    let new_sum = update_checksum(old_sum, old_ip as u16, new_ip as u16);
    println!("新校验和: {:04x}", new_sum);
    println!("理论新校验和: {:04x}", ipv4_checksum(&ipv4hdr));
}

/// 从[u16; 10]计算校验和
fn ipv4_checksum(ipv4hdr: &[u16; 10]) -> u16 {
    let sum: u32= ipv4hdr
        .map(|num| num as u32)
        .iter()
        .sum();
    // s = (s >> 16) + (s & 0xFFFF)
    // s += s >> 16
    let sum = (sum >> 16) + (sum & 0xFFFF);
    let sum = sum + (sum >> 16);
    !((sum & 0xFFFF) as u16)
}

/// 通过差异增量计算新的IP校验和
/// 
/// # 参数
/// * `old_csum` - 原始校验和
/// * `old` - 被修改的16位值
/// * `new` - 新的16位值
/// 
/// # 返回值
/// 更新后的校验和
fn update_checksum(old_csum: u16, old: u16, new: u16) -> u16 {
    // 计算增量: 从旧校验和中减去旧值，加上新值
    let mut csum = !old_csum as u32;  // 校验和取反得到和
    csum = csum.wrapping_sub(old as u32).wrapping_add(new as u32);  // 更新和
    
    // 处理进位
    let csum = (csum >> 16) + (csum & 0xFFFF);
    let csum = csum + (csum >> 16);
    
    (!csum as u16) & 0xFFFF  // 再次取反得到新校验和
}