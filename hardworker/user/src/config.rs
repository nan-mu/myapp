use anyhow::{anyhow, Context, Result};
use log::debug;
use procfs::Current;
use serde::Deserialize;
use std::{
    cmp::Ordering,
    fmt::Debug,
    fs,
    net::Ipv4Addr,
    path::Path,
    sync::Arc, time::Duration,
};

mod consts {
    //! const.toml 中的常量配置

    use super::*;

    #[derive(Debug, Clone, Deserialize)]
    pub struct ConstConfig {
        // pub mac: MacAddresses,
        pub ip: IpAddresses,
        // pub mark: MarkConfig,
        pub data: DataConfig,
    }

    /// MAC地址配置
    // #[derive(Debug, Clone, Deserialize)]
    // pub struct MacAddresses {
    //     pub logger: String,
    //     pub hardworker: String,
    //     pub sensor: String,
    // }

    /// MAC地址配置解析后使用的结构体
    // #[derive(Debug, Clone, Deserialize)]
    // pub struct Mac {
    //     pub logger: [u8; 6],
    //     pub hardworker: [u8; 6],
    //     pub sensor: [u8; 6],
    // }

    /// IP地址配置
    #[derive(Debug, Clone, Deserialize)]
    pub struct IpAddresses {
        // pub logger: Ipv4Addr,
        pub hardworker: Ipv4Addr,
        // pub sensor: Ipv4Addr,
    }

    // /// 数据包标记配置
    // #[derive(Debug, Clone, Deserialize)]
    // pub struct MarkConfig {
    //     pub tos: u8,
    //     pub port: u16,
    // }

    /// 数据负载配置
    #[derive(Debug, Clone, Deserialize)]
    pub struct DataConfig {
        // pub mtu: usize,
        pub size: usize,
    }
}

/// config.toml 中的用户配置
#[derive(Debug, Clone, Deserialize)]
struct FileConfig {
    pub timeout: Option<u64>,
    pub tcp: Option<FileTcpConfig>,
}

/// TCP通信配置
#[derive(Debug, Clone, Deserialize)]
struct FileTcpConfig {
    /// 网卡名称，可选
    pub ifname: Option<String>,

    /// 目标IP地址，可选，默认使用const.toml中的hardworker值
    pub ip: Option<Ipv4Addr>,

    // /// 目标端口，可选，默认使用const.toml中的port值
    // pub port: Option<u16>,

    // /// TOS值，可选，默认使用const.toml中的tos值
    // pub tos: Option<u8>,

    /// 数据包大小，可选，默认使用const.toml中的mtu值
    pub size: Option<usize>,
    // /// 发送频率(Hz)，必须指定
    // pub freq: f64,
    // /// 发包目标角色
    // pub target: Option<Role>,
}

// /// 系统中的角色类型
// #[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
// #[serde(rename_all = "lowercase")]
// pub enum Role {
//     Logger,
//     Hardworker,
//     Sensor,
// }

// impl Display for Role {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         match self {
//             Role::Logger => write!(f, "logger"),
//             Role::Hardworker => write!(f, "hardworker"),
//             Role::Sensor => write!(f, "sensor"),
//         }
//     }
// }

/// 最终合并的配置
#[derive(Debug, Clone)]
pub struct Config {
    pub ifname: Arc<str>,
    // pub target: Role,
    // pub host_ip: Ipv4Addr,
    // pub port: u16,
    // pub tos: u8,
    pub size: usize,
    pub timeout: Option<Duration>,
    // pub freq: f64,
}

impl TryFrom<(FileConfig, consts::ConstConfig)> for Config {
    type Error = anyhow::Error;
    fn try_from((file_config, const_config): (FileConfig, consts::ConstConfig)) -> Result<Self> {
        let tcp_config = file_config
            .tcp
            .ok_or_else(|| anyhow::anyhow!("配置缺失"))?;
        // let target = tcp_config.target.unwrap_or(Role::Hardworker);
        let host_ip = tcp_config.ip.unwrap_or(const_config.ip.hardworker);
        // let port = tcp_config.port.unwrap_or(const_config.mark.port);
        // let tos = tcp_config.tos.unwrap_or(const_config.mark.tos);
        let size = tcp_config.size.unwrap_or(const_config.data.size);
        let timeout = file_config.timeout.map(Duration::from_secs);
        // let freq = tcp_config.freq;
        let ifname = match tcp_config.ifname {
            Some(ifname) => ifname,
            None => {
                let routers = procfs::net::RouteEntries::current()?;
                let ip = host_ip.to_bits();
                let best_router = routers
                    .0
                    .iter()
                    .filter(|router| {
                        let mask = router.mask.to_bits();
                        let destination = router.destination.to_bits();
                        ip & mask == destination & mask
                    })
                    .max_by(|&a, &b| {
                        // 第一优先级：掩码中1的位数（最长前缀）
                        let mask_cmp = a
                            .mask
                            .to_bits()
                            .count_ones()
                            .cmp(&b.mask.to_bits().count_ones());
                        match mask_cmp {
                            Ordering::Equal => b.metrics.cmp(&a.metrics),
                            _ => mask_cmp,
                        }
                    })
                    .ok_or(anyhow!("找不到对hardworker的路由, 检查目标ip或尝试手动填充config.toml的tcp.ifname字段"))?;
                debug!("对ip: {host_ip} 找到路由: {}", best_router.iface);
                best_router.iface.clone()
            }
        };

        Ok(Config {
            ifname: Arc::from(ifname),
            // host_ip,
            // port,
            // tos,
            size,
            timeout,
            // freq,
        })
    }
}

impl Config {
    /// path -> FileConfig&&ConstConfig -> TcpConfig
    pub fn build<T: AsRef<Path> + Debug>(config_path: T, consts_path: T) -> Result<Self> {
        let config = fs::read_to_string(&config_path)
            .with_context(|| format!("输入config文件路径: {:?}", &config_path))?;
        let config: FileConfig = toml::from_str(&config)?;
        let consts = fs::read_to_string(&consts_path)
            .with_context(|| format!("输入consts文件路径: {:?}", &consts_path))?;
        let consts: consts::ConstConfig = toml::from_str(&consts)?;
        Ok(Self::try_from((config, consts))?)
    }
}
