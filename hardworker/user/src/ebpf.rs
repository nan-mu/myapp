use anyhow::{Context, Ok, Result};
use aya::{
    maps::RingBuf,
    programs::{Xdp, XdpFlags},
};
use log::debug;
use std::sync::Arc;

use crate::fd_handle::FdHandleBuilder;

pub struct EbpfBuilder {
    pub ifname: Arc<str>,
}

pub struct EbpfHandle {
    ebpf: aya::Ebpf,
}

impl EbpfBuilder {
    pub fn build(target_ifname: Arc<str>) -> Self {
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
        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/hardworker"
        )))?;
        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            debug!("初始化ebpf日志器失败: {}", e);
        }
        let program: &mut Xdp = ebpf.program_mut("hardworker").unwrap().try_into()?;
        program.load()?;
        program
            .attach(&self.ifname, XdpFlags::default())
            .context("默认flag连接xdp失败，考虑特定flag")?;
        debug!("ebpf 附加到设备 {} 成功", self.ifname);
        Ok(EbpfHandle { ebpf: ebpf })
    }
}

impl EbpfHandle {
    pub fn build_ringbuf_fd(&mut self, name: Arc<str>, size: usize) -> Result<FdHandleBuilder> {
        let map = self
            .ebpf
            .take_map(name.as_ref())
            .context("找不到Map, 考虑ebpf程序未正常加载")?;
        let ringbuf = RingBuf::try_from(map)?;
        FdHandleBuilder::new(ringbuf, size)
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
