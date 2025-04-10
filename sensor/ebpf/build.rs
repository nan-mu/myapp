use core::net::Ipv4Addr;
use std::{env, fs, path::Path};
use const_gen::{const_declaration, const_definition, CompileConst};
use serde::Deserialize;
use which::which;

/// Building this crate has an undeclared dependency on the `bpf-linker` binary. This would be
/// better expressed by [artifact-dependencies][bindeps] but issues such as
/// https://github.com/rust-lang/cargo/issues/12385 make their use impractical for the time being.
///
/// This file implements an imperfect solution: it causes cargo to rebuild the crate whenever the
/// mtime of `which bpf-linker` changes. Note that possibility that a new bpf-linker is added to
/// $PATH ahead of the one used as the cache key still exists. Solving this in the general case
/// would require rebuild-if-changed-env=PATH *and* rebuild-if-changed={every-directory-in-PATH}
/// which would likely mean far too much cache invalidation.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies

fn main() {
    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());

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
    ].join("\n");

    fs::write(&dest_path, const_declarations).unwrap();
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
        let logger = mac.logger.split(':').map(|s| u8::from_str_radix(s, 16).unwrap()).collect::<Vec<_>>().try_into().unwrap();
        let hardworker = mac.hardworker.split(':').map(|s| u8::from_str_radix(s, 16).unwrap()).collect::<Vec<_>>().try_into().unwrap();
        let sensor = mac.sensor.split(':').map(|s| u8::from_str_radix(s, 16).unwrap()).collect::<Vec<_>>().try_into().unwrap();
        Self { logger, hardworker, sensor }
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