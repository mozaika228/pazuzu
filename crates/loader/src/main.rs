use anyhow::{bail, Context, Result};
use axum::{extract::Path, http::StatusCode, routing::{delete, get, post}, Json, Router};
use clap::Parser;
use libbpf_rs::{MapFlags, XdpFlags};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::PathBuf;
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

    /// Pin maps in bpffs (e.g. /sys/fs/bpf/pazuzu)
    #[arg(long)]
    pin_maps: Option<String>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct RateLimitCfg {
    rate_per_sec: u64,
    burst: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct RuleEpoch {
    epoch: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct Ipv4LpmKey {
    prefixlen: u32,
    addr: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct TcpSignatureCfg {
    block_null_scan: u8,
    block_xmas_scan: u8,
    pad: [u8; 6],
}

#[derive(Serialize)]
struct Stats {
    pass: u64,
    drop_block_ip: u64,
    drop_block_cidr: u64,
    drop_rate: u64,
    drop_sig_tcp: u64,
    parse_err: u64,
}

#[derive(Deserialize)]
struct RateReq {
    rate_per_sec: u64,
    burst: u64,
}

#[derive(Deserialize)]
struct CidrReq {
    cidr: String,
}

#[derive(Deserialize)]
#[derive(Clone, Default)]
struct TcpSignatureReq {
    block_null_scan: bool,
    block_xmas_scan: bool,
}

#[derive(Serialize)]
struct TcpSignatureResp {
    block_null_scan: bool,
    block_xmas_scan: bool,
}

#[derive(Serialize)]
struct EpochResp {
    epoch: u64,
}

#[derive(Serialize)]
struct RulesConfigResp {
    epoch: u64,
    blocked_ips: Vec<String>,
    blocked_cidrs: Vec<String>,
    tcp_signatures: TcpSignatureResp,
}

#[derive(Deserialize)]
struct RulesBatchReq {
    add_ips: Vec<String>,
    remove_ips: Vec<String>,
    add_cidrs: Vec<String>,
    remove_cidrs: Vec<String>,
    tcp_signatures: Option<TcpSignatureReq>,
}

include!(concat!(env!("OUT_DIR"), "/xdp_pass.skel.rs"));

struct AppState {
    skel: Mutex<XdpPassSkel>,
    rules: Mutex<RuleStore>,
}

#[derive(Default)]
struct RuleStore {
    epoch: u64,
    blocked_ips: HashSet<String>,
    blocked_cidrs: HashSet<String>,
    tcp_signatures: TcpSignatureReq,
}

fn ipv4_to_key(ip: &str) -> Result<u32> {
    let addr: Ipv4Addr = ip.parse().context("invalid ipv4")?;
    Ok(u32::from_ne_bytes(addr.octets()))
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
        drop_block_ip: get_idx(1)?,
        drop_block_cidr: get_idx(2)?,
        drop_rate: get_idx(3)?,
        drop_sig_tcp: get_idx(4)?,
        parse_err: get_idx(5)?,
    })
}

fn parse_cidr(cidr: &str) -> Result<Ipv4LpmKey> {
    let (ip, prefix) = cidr
        .split_once('/')
        .context("cidr must be in a.b.c.d/prefix format")?;
    let addr: Ipv4Addr = ip.parse().context("invalid cidr ip")?;
    let prefixlen: u32 = prefix.parse().context("invalid cidr prefix")?;
    if prefixlen > 32 {
        bail!("cidr prefix must be <= 32");
    }
    Ok(Ipv4LpmKey {
        prefixlen,
        addr: u32::from_ne_bytes(addr.octets()),
    })
}

fn normalize_cidr(cidr: &str) -> Result<String> {
    let (ip, prefix) = cidr
        .split_once('/')
        .context("cidr must be in a.b.c.d/prefix format")?;
    let addr: Ipv4Addr = ip.parse().context("invalid cidr ip")?;
    let prefixlen: u32 = prefix.parse().context("invalid cidr prefix")?;
    if prefixlen > 32 {
        bail!("cidr prefix must be <= 32");
    }
    Ok(format!("{addr}/{prefixlen}"))
}

fn set_tcp_signature_cfg(skel: &mut XdpPassSkel, req: &TcpSignatureReq) -> Result<()> {
    let key: u32 = 0;
    let val = TcpSignatureCfg {
        block_null_scan: u8::from(req.block_null_scan),
        block_xmas_scan: u8::from(req.block_xmas_scan),
        pad: [0; 6],
    };
    skel.maps()
        .rules_tcp_sig()
        .update(&key.to_ne_bytes(), &val, MapFlags::ANY)
        .context("update rules_tcp_sig")?;
    Ok(())
}

fn read_tcp_signature_cfg(skel: &mut XdpPassSkel) -> Result<TcpSignatureResp> {
    let key: u32 = 0;
    let v = skel
        .maps()
        .rules_tcp_sig()
        .lookup(&key.to_ne_bytes(), MapFlags::ANY)
        .context("lookup rules_tcp_sig")?;
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&v);
    Ok(TcpSignatureResp {
        block_null_scan: raw[0] != 0,
        block_xmas_scan: raw[1] != 0,
    })
}

fn read_epoch(skel: &mut XdpPassSkel) -> Result<u64> {
    let idx: u32 = 0;
    let v = skel
        .maps()
        .rules_epoch()
        .lookup(&idx.to_ne_bytes(), MapFlags::ANY)
        .context("lookup epoch")?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&v);
    Ok(u64::from_ne_bytes(arr))
}

fn bump_epoch(skel: &mut XdpPassSkel) -> Result<u64> {
    let idx: u32 = 0;
    let current = read_epoch(skel).unwrap_or(0);
    let next = current.saturating_add(1);
    let val = RuleEpoch { epoch: next };
    skel.maps()
        .rules_epoch()
        .update(&idx.to_ne_bytes(), &val, MapFlags::ANY)
        .context("update epoch")?;
    Ok(next)
}

fn next_epoch(skel: &mut XdpPassSkel, rules: &mut RuleStore) -> Result<u64> {
    let next = bump_epoch(skel)?;
    rules.epoch = next;
    Ok(next)
}

fn pin_all_maps(skel: &mut XdpPassSkel, dir: &PathBuf) -> Result<()> {
    std::fs::create_dir_all(dir).context("create pin dir")?;
    skel.maps().pin(dir).context("pin maps")?;
    Ok(())
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
    set_tcp_signature_cfg(
        &mut skel,
        &TcpSignatureReq {
            block_null_scan: true,
            block_xmas_scan: true,
        },
    )?;

    if let Some(pin) = &args.pin_maps {
        let dir = PathBuf::from(pin);
        pin_all_maps(&mut skel, &dir)?;
        info!("pinned maps at {}", dir.display());
    }

    info!("attached xdp_pass to {} in {} mode", args.iface, args.mode);

    let current_epoch = read_epoch(&mut skel).unwrap_or(0);
    let state = Arc::new(AppState {
        skel: Mutex::new(skel),
        rules: Mutex::new(RuleStore {
            epoch: current_epoch,
            blocked_ips: HashSet::new(),
            blocked_cidrs: HashSet::new(),
            tcp_signatures: TcpSignatureReq {
                block_null_scan: true,
                block_xmas_scan: true,
            },
        }),
    });

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/block/:ip", post(block_ip).delete(unblock_ip))
        .route("/block-cidr", post(block_cidr).delete(unblock_cidr))
        .route("/rate", post(set_rate))
        .route("/stats", get(get_stats))
        .route("/signatures/tcp", get(get_tcp_signatures).post(set_tcp_signatures))
        .route("/rules/config", get(get_rules_config))
        .route("/rules/batch", post(apply_rules_batch))
        .route("/rules/epoch", get(get_epoch).post(bump_rules_epoch))
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
    let mut rules = state.rules.lock().unwrap();
    skel.maps()
        .rules_blocklist()
        .update(&key.to_ne_bytes(), &val, MapFlags::ANY)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    rules.blocked_ips.insert(ip);
    next_epoch(&mut skel, &mut rules).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn unblock_ip(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Path(ip): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let key = ipv4_to_key(&ip).map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut skel = state.skel.lock().unwrap();
    let mut rules = state.rules.lock().unwrap();
    skel.maps()
        .rules_blocklist()
        .delete(&key.to_ne_bytes())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    rules.blocked_ips.remove(&ip);
    next_epoch(&mut skel, &mut rules).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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

async fn block_cidr(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(req): Json<CidrReq>,
) -> Result<StatusCode, StatusCode> {
    let key = parse_cidr(&req.cidr).map_err(|_| StatusCode::BAD_REQUEST)?;
    let normalized = normalize_cidr(&req.cidr).map_err(|_| StatusCode::BAD_REQUEST)?;
    let val: u8 = 1;
    let mut skel = state.skel.lock().unwrap();
    let mut rules = state.rules.lock().unwrap();
    skel.maps()
        .rules_cidr_blocklist()
        .update(&key, &val, MapFlags::ANY)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    rules.blocked_cidrs.insert(normalized);
    next_epoch(&mut skel, &mut rules).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn unblock_cidr(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(req): Json<CidrReq>,
) -> Result<StatusCode, StatusCode> {
    let key = parse_cidr(&req.cidr).map_err(|_| StatusCode::BAD_REQUEST)?;
    let normalized = normalize_cidr(&req.cidr).map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut skel = state.skel.lock().unwrap();
    let mut rules = state.rules.lock().unwrap();
    skel.maps()
        .rules_cidr_blocklist()
        .delete(&key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    rules.blocked_cidrs.remove(&normalized);
    next_epoch(&mut skel, &mut rules).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn set_tcp_signatures(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(req): Json<TcpSignatureReq>,
) -> Result<Json<TcpSignatureResp>, StatusCode> {
    let mut skel = state.skel.lock().unwrap();
    let mut rules = state.rules.lock().unwrap();
    set_tcp_signature_cfg(&mut skel, &req).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    rules.tcp_signatures = req.clone();
    next_epoch(&mut skel, &mut rules).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(TcpSignatureResp {
        block_null_scan: req.block_null_scan,
        block_xmas_scan: req.block_xmas_scan,
    }))
}

async fn get_tcp_signatures(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Result<Json<TcpSignatureResp>, StatusCode> {
    let mut skel = state.skel.lock().unwrap();
    let cfg = read_tcp_signature_cfg(&mut skel).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(cfg))
}

async fn get_stats(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Result<Json<Stats>, StatusCode> {
    let mut skel = state.skel.lock().unwrap();
    let stats = read_stats(&mut skel).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(stats))
}

async fn get_epoch(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Result<Json<EpochResp>, StatusCode> {
    let mut skel = state.skel.lock().unwrap();
    let epoch = read_epoch(&mut skel).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(EpochResp { epoch }))
}

async fn bump_rules_epoch(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Result<Json<EpochResp>, StatusCode> {
    let mut skel = state.skel.lock().unwrap();
    let mut rules = state.rules.lock().unwrap();
    let epoch = next_epoch(&mut skel, &mut rules).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(EpochResp { epoch }))
}

async fn get_rules_config(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Result<Json<RulesConfigResp>, StatusCode> {
    let rules = state.rules.lock().unwrap();
    let mut blocked_ips: Vec<String> = rules.blocked_ips.iter().cloned().collect();
    let mut blocked_cidrs: Vec<String> = rules.blocked_cidrs.iter().cloned().collect();
    blocked_ips.sort();
    blocked_cidrs.sort();
    Ok(Json(RulesConfigResp {
        epoch: rules.epoch,
        blocked_ips,
        blocked_cidrs,
        tcp_signatures: TcpSignatureResp {
            block_null_scan: rules.tcp_signatures.block_null_scan,
            block_xmas_scan: rules.tcp_signatures.block_xmas_scan,
        },
    }))
}

async fn apply_rules_batch(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(req): Json<RulesBatchReq>,
) -> Result<Json<EpochResp>, StatusCode> {
    let mut skel = state.skel.lock().unwrap();
    let mut rules = state.rules.lock().unwrap();

    for ip in &req.add_ips {
        let key = ipv4_to_key(ip).map_err(|_| StatusCode::BAD_REQUEST)?;
        let val: u8 = 1;
        skel.maps()
            .rules_blocklist()
            .update(&key.to_ne_bytes(), &val, MapFlags::ANY)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        rules.blocked_ips.insert(ip.clone());
    }

    for ip in &req.remove_ips {
        let key = ipv4_to_key(ip).map_err(|_| StatusCode::BAD_REQUEST)?;
        skel.maps()
            .rules_blocklist()
            .delete(&key.to_ne_bytes())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        rules.blocked_ips.remove(ip);
    }

    for cidr in &req.add_cidrs {
        let key = parse_cidr(cidr).map_err(|_| StatusCode::BAD_REQUEST)?;
        let normalized = normalize_cidr(cidr).map_err(|_| StatusCode::BAD_REQUEST)?;
        let val: u8 = 1;
        skel.maps()
            .rules_cidr_blocklist()
            .update(&key, &val, MapFlags::ANY)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        rules.blocked_cidrs.insert(normalized);
    }

    for cidr in &req.remove_cidrs {
        let key = parse_cidr(cidr).map_err(|_| StatusCode::BAD_REQUEST)?;
        let normalized = normalize_cidr(cidr).map_err(|_| StatusCode::BAD_REQUEST)?;
        skel.maps()
            .rules_cidr_blocklist()
            .delete(&key)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        rules.blocked_cidrs.remove(&normalized);
    }

    if let Some(tcp) = &req.tcp_signatures {
        set_tcp_signature_cfg(&mut skel, tcp).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        rules.tcp_signatures = tcp.clone();
    }

    let epoch = next_epoch(&mut skel, &mut rules).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(EpochResp { epoch }))
}
