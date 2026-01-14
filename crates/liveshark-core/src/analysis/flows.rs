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

#[cfg(test)]
mod tests {
    use super::{FlowKey, FlowStats, build_flow_summaries};
    use std::collections::HashMap;
    use std::net::IpAddr;

    #[test]
    fn summaries_are_sorted_and_no_duration_means_none_rates() {
        let mut stats = HashMap::new();
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let c: IpAddr = "10.0.0.3".parse().unwrap();

        stats.insert(
            FlowKey {
                src_ip: b,
                src_port: 1000,
                dst_ip: c,
                dst_port: 2000,
            },
            FlowStats {
                packets: 10,
                bytes: 100,
            },
        );
        stats.insert(
            FlowKey {
                src_ip: a,
                src_port: 1000,
                dst_ip: c,
                dst_port: 2000,
            },
            FlowStats {
                packets: 5,
                bytes: 50,
            },
        );

        let summaries = build_flow_summaries(stats, None);
        assert_eq!(summaries.len(), 2);
        assert!(summaries[0].src < summaries[1].src);
        assert!(summaries[0].pps.is_none());
        assert!(summaries[0].bps.is_none());
        assert!(summaries[1].pps.is_none());
        assert!(summaries[1].bps.is_none());
    }

    #[test]
    fn summaries_compute_rates_when_duration_known() {
        let mut stats = HashMap::new();
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();

        stats.insert(
            FlowKey {
                src_ip: a,
                src_port: 1000,
                dst_ip: b,
                dst_port: 2000,
            },
            FlowStats {
                packets: 10,
                bytes: 100,
            },
        );

        let summaries = build_flow_summaries(stats, Some(2.0));
        assert_eq!(summaries.len(), 1);
        let summary = &summaries[0];
        assert_eq!(summary.pps, Some(5.0));
        assert_eq!(summary.bps, Some(50.0));
    }
}
