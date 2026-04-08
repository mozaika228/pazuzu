use std::env;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let mut clang_args = vec![
        "-I../../ebpf".to_string(),
        "-g".to_string(),
        "-O2".to_string(),
        "-target".to_string(),
        "bpf".to_string(),
    ];

    // CI images often place asm headers under multiarch include dirs.
    for dir in [
        "/usr/include/x86_64-linux-gnu",
        "/usr/include/aarch64-linux-gnu",
        "/usr/include/arm-linux-gnueabihf",
    ] {
        if PathBuf::from(dir).exists() {
            clang_args.push(format!("-I{dir}"));
        }
    }

    libbpf_cargo::SkeletonBuilder::new()
        .source("../../ebpf/xdp_pass.bpf.c")
        .clang_args(clang_args)
        .build_and_generate(out.join("xdp_pass.skel.rs"))
        .unwrap();

    println!("cargo:rerun-if-changed=../../ebpf/xdp_pass.bpf.c");
}
