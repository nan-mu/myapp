use anyhow::{anyhow, Context as _, Result};
use aya_build::cargo_metadata;
use const_gen::{const_declaration, const_definition, CompileConst};
use core::net::Ipv4Addr;
use serde::Deserialize;
use std::{env, fs, path::Path};

fn main() -> Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name == "ebpf")
        .ok_or_else(|| anyhow!("ebpf package not found"))?;
    aya_build::build_ebpf([ebpf_package])?;

    // 填充常量
    let toml = std::fs::read_to_string("../../const.toml").unwrap();
    // println!("{toml}");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("const_gen.rs");

    let consts: Consts = toml::from_str(&toml).unwrap();
    let mac = Mac::from(consts.mac);
    let ip = consts.ip;
    let data = consts.data;
    let mark = consts.mark;

    let const_declarations = vec![
        "#[allow(unused)]".to_string(),
        const_definition!(Mac),
        "#[allow(unused)]".to_string(),
        const_definition!(Ip),
        "#[allow(unused)]".to_string(),
        const_definition!(Data),
        "#[allow(unused)]".to_string(),
        const_definition!(Mark),
        "#[allow(unused)]".to_string(),
        const_declaration!(MAC = mac),
        "#[allow(unused)]".to_string(),
        const_declaration!(IP = ip),
        "#[allow(unused)]".to_string(),
        const_declaration!(DATA = data),
        "#[allow(unused)]".to_string(),
        const_declaration!(MARK = mark),
    ]
    .join("\n");

    fs::write(&dest_path, const_declarations)?;

    Ok(())
}

#[derive(Deserialize)]
struct Consts {
    mac: MacToml,
    ip: Ip,
    data: Data,
    mark: Mark,
}

#[derive(Deserialize)]
struct MacToml {
    logger: String,
    hardworker: String,
    sensor: String,
}

impl From<MacToml> for Mac {
    fn from(mac: MacToml) -> Self {
        let logger = mac
            .logger
            .split(':')
            .map(|s| u8::from_str_radix(s, 16).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let hardworker = mac
            .hardworker
            .split(':')
            .map(|s| u8::from_str_radix(s, 16).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let sensor = mac
            .sensor
            .split(':')
            .map(|s| u8::from_str_radix(s, 16).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        Self {
            logger,
            hardworker,
            sensor,
        }
    }
}

#[derive(CompileConst)]
struct Mac {
    logger: [u8; 6],
    hardworker: [u8; 6],
    sensor: [u8; 6],
}

#[derive(CompileConst, Deserialize)]
struct Ip {
    logger: Ipv4Addr,
    hardworker: Ipv4Addr,
    sensor: Ipv4Addr,
}

#[derive(CompileConst, Deserialize)]
struct Data {
    mtu: usize,
    load_u64_count: usize,
}

#[derive(CompileConst, Deserialize)]
struct Mark {
    tos: u8,
    port: u16,
}
