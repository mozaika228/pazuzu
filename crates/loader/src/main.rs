use anyhow::{bail, Context, Result};
use clap::Parser;
use libbpf_rs::XdpFlags;
use std::path::PathBuf;
use std::sync::{atomic::{AtomicBool, Ordering}, Arc};

#[derive(Parser, Debug)]
#[command(about = "Attach xdp_pass to an interface")]
struct Args {
    /// Interface name, e.g. eth0
    #[arg(short, long)]
    iface: String,

    /// Native or SKB mode
    #[arg(long, default_value = "native")]
    mode: String,
}

include!(concat!(env!("OUT_DIR"), "/xdp_pass.skel.rs"));

fn main() -> Result<()> {
    let args = Args::parse();

    let mut skel_builder = XdpPassSkelBuilder::default();
    let mut open = skel_builder.open().context("open skeleton")?;
    let skel = open.load().context("load skeleton")?;

    let flags = match args.mode.as_str() {
        "native" => XdpFlags::DRV_MODE,
        "skb" => XdpFlags::SKB_MODE,
        _ => bail!("mode must be native or skb"),
    };

    let link = skel
        .progs()
        .xdp_pass()
        .attach_xdp(&args.iface, flags)
        .context("attach xdp")?;

    println!("attached xdp_pass to {} in {} mode", args.iface, args.mode);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    drop(link);
    println!("detached");
    Ok(())
}
