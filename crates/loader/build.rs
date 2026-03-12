use std::env;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());

    libbpf_cargo::SkeletonBuilder::new()
        .source("../../ebpf/xdp_pass.bpf.c")
        .clang_args(["-I../../ebpf", "-g", "-O2", "-target", "bpf"])
        .build_and_generate(out.join("xdp_pass.skel.rs"))
        .unwrap();

    println!("cargo:rerun-if-changed=../../ebpf/xdp_pass.bpf.c");
}
