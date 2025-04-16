use std::sync::Arc;
use anyhow::{Context, Result};
use aya::programs::{Xdp, XdpFlags};
use log::debug;

pub struct EbpfBuilder {
    pub ifname: Arc<str>,
}

pub struct EbpfHandle {
    _ebpf: aya::Ebpf,
    // program: PGT,
}

impl EbpfBuilder {
    pub fn build(target_ifname: Arc<str>) -> Self{
        EbpfBuilder {
            ifname: target_ifname.clone(),
        }
    }
    pub fn cancel_memlock(self) -> Result<Self> {
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
        Ok(self)
    }

    pub fn build_xdp(&mut self) -> Result<EbpfHandle> {
        env_logger::init();
        
        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/sensor"
        )))?;
        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            debug!("初始化ebpf日志器失败: {}", e);
        }
        let program: &mut Xdp = ebpf.program_mut("sensor").unwrap().try_into()?;
        program.load()?;
        program
            .attach(&self.ifname, XdpFlags::default())
            .context("默认flag连接xdp失败，考虑特定flag")?;
        debug!("ebpf 附加到设备 {} 成功", self.ifname);
        Ok(EbpfHandle { _ebpf: ebpf })
    }
}

#[cfg(test)]
mod tests {

    // #[test]
    // fn test_ebpf_builder() {
    //     let builder = EbpfBuilder::build("wlan0".into());
    //     let target_ip = Ipv4Addr::new(192, 168, 1, 1);
    //     assert!(builder.with_target_ip(target_ip).is_ok());
    // }
}