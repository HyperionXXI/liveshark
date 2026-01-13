use std::collections::HashMap;
use std::net::IpAddr;

use crate::FlowSummary;

use super::udp::UdpPacket;

#[derive(Debug, Hash, PartialEq, Eq)]
pub(crate) struct FlowKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct FlowStats {
    pub packets: u64,
    pub bytes: u64,
}

pub(crate) fn add_flow_stats(stats: &mut HashMap<FlowKey, FlowStats>, packet: &UdpPacket<'_>) {
    let key = FlowKey {
        src_ip: packet.src_ip,
        src_port: packet.src_port,
        dst_ip: packet.dst_ip,
        dst_port: packet.dst_port,
    };
    let entry = stats.entry(key).or_default();
    entry.packets += 1;
    entry.bytes += packet.payload.len() as u64;
}

pub(crate) fn build_flow_summaries(
    stats: HashMap<FlowKey, FlowStats>,
    duration_s: Option<f64>,
) -> Vec<FlowSummary> {
    let mut flows: Vec<FlowSummary> = stats
        .into_iter()
        .map(|(key, stats)| {
            let (pps, bps) = duration_s
                .map(|d| (stats.packets as f64 / d, stats.bytes as f64 / d))
                .map(|(pps, bps)| (Some(pps), Some(bps)))
                .unwrap_or((None, None));

            FlowSummary {
                app_proto: "udp".to_string(),
                src: format_endpoint(key.src_ip, key.src_port),
                dst: format_endpoint(key.dst_ip, key.dst_port),
                pps,
                bps,
                iat_jitter_ms: None,
            }
        })
        .collect();

    flows.sort_by(|a, b| a.src.cmp(&b.src).then_with(|| a.dst.cmp(&b.dst)));
    flows
}

fn format_endpoint(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(addr) => format!("{}:{}", addr, port),
        IpAddr::V6(addr) => format!("[{}]:{}", addr, port),
    }
}
