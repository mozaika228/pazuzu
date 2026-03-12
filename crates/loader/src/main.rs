use anyhow::{bail, Context, Result};
use axum::{extract::Path, http::StatusCode, routing::{delete, get, post}, Json, Router};
use clap::Parser;
use libbpf_rs::{MapFlags, XdpFlags};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex};
use tokio::signal;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(about = "Attach xdp_pass to an interface")]
struct Args {
    /// Interface name, e.g. eth0
    #[arg(short, long)]
    iface: String,

    /// Native or SKB mode
    #[arg(long, default_value = "native")]
    mode: String,

    /// Listen address for control API
    #[arg(long, default_value = "127.0.0.1:8080")]
    api: String,

    /// Default rate per second (0 = disabled)
    #[arg(long, default_value_t = 0)]
    rate: u64,

    /// Default burst (0 = use rate)
    #[arg(long, default_value_t = 0)]
    burst: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct RateLimitCfg {
    rate_per_sec: u64,
    burst: u64,
}

#[derive(Serialize)]
struct Stats {
    pass: u64,
    drop_block: u64,
    drop_rate: u64,
    parse_err: u64,
}

#[derive(Deserialize)]
struct RateReq {
    rate_per_sec: u64,
    burst: u64,
}

include!(concat!(env!("OUT_DIR"), "/xdp_pass.skel.rs"));

struct AppState {
    skel: Mutex<XdpPassSkel>,
}

fn ipv4_to_key(ip: &str) -> Result<u32> {
    let addr: Ipv4Addr = ip.parse().context("invalid ipv4")?;
    Ok(u32::from_be_bytes(addr.octets()))
}

fn set_rate_cfg(skel: &mut XdpPassSkel, cfg: RateLimitCfg) -> Result<()> {
    let key: u32 = 0;
    let val = cfg;
    skel.maps()
        .rate_cfg()
        .update(&key.to_ne_bytes(), &val, MapFlags::ANY)
        .context("update rate_cfg")?;
    Ok(())
}

fn read_stats(skel: &mut XdpPassSkel) -> Result<Stats> {
    let mut get_idx = |idx: u32| -> Result<u64> {
        let v = skel
            .maps()
            .stats()
            .lookup(&idx.to_ne_bytes(), MapFlags::ANY)
            .context("lookup stats")?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&v);
        Ok(u64::from_ne_bytes(arr))
    };

    Ok(Stats {
        pass: get_idx(0)?,
        drop_block: get_idx(1)?,
        drop_rate: get_idx(2)?,
        parse_err: get_idx(3)?,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let args = Args::parse();

    let mut skel_builder = XdpPassSkelBuilder::default();
    let mut open = skel_builder.open().context("open skeleton")?;
    let mut skel = open.load().context("load skeleton")?;

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

    set_rate_cfg(
        &mut skel,
        RateLimitCfg {
            rate_per_sec: args.rate,
            burst: args.burst,
        },
    )?;

    info!("attached xdp_pass to {} in {} mode", args.iface, args.mode);

    let state = Arc::new(AppState {
        skel: Mutex::new(skel),
    });

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/block/:ip", post(block_ip).delete(unblock_ip))
        .route("/rate", post(set_rate))
        .route("/stats", get(get_stats))
        .with_state(state.clone());

    let api_addr = args.api.parse().context("invalid api addr")?;
    let server = axum::Server::bind(&api_addr).serve(app.into_make_service());
    info!("api listening on {}", args.api);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    tokio::select! {
        _ = server => {
            warn!("api server exited");
        }
        _ = async {
            while running.load(Ordering::SeqCst) {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        } => {}
        _ = signal::ctrl_c() => {}
    }

    drop(link);
    info!("detached");
    Ok(())
}

async fn block_ip(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let key = ipv4_to_key(&ip).map_err(|_| StatusCode::BAD_REQUEST)?;
    let val: u8 = 1;
    let mut skel = state.skel.lock().unwrap();
    skel.maps()
        .rules_blocklist()
        .update(&key.to_ne_bytes(), &val, MapFlags::ANY)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn unblock_ip(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let key = ipv4_to_key(&ip).map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut skel = state.skel.lock().unwrap();
    skel.maps()
        .rules_blocklist()
        .delete(&key.to_ne_bytes())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn set_rate(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(req): Json<RateReq>,
) -> Result<StatusCode, StatusCode> {
    let mut skel = state.skel.lock().unwrap();
    set_rate_cfg(
        &mut skel,
        RateLimitCfg {
            rate_per_sec: req.rate_per_sec,
            burst: req.burst,
        },
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_stats(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Result<Json<Stats>, StatusCode> {
    let mut skel = state.skel.lock().unwrap();
    let stats = read_stats(&mut skel).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(stats))
}
