use std::collections::{HashMap, VecDeque};
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
    pub first_ts: Option<f64>,
    pub last_ts: Option<f64>,
    pub prev_iat: Option<f64>,
    pub iat_count: u64,
    pub max_iat_ms: Option<u64>,
    pub jitter_sum: f64,
    pub jitter_samples: VecDeque<(f64, f64)>,
    pub jitter_peak: Option<f64>,
    pub window_packets: u64,
    pub window_bytes: u64,
    pub window_samples: VecDeque<(f64, u64)>,
    pub peak_pps: Option<f64>,
    pub peak_bps: Option<f64>,
    pub peak_window_packets: u64,
    pub peak_window_bytes: u64,
}

const PPS_BPS_WINDOW_S: f64 = 1.0;
const JITTER_WINDOW_S: f64 = 10.0;

pub(crate) fn add_flow_stats(
    stats: &mut HashMap<FlowKey, FlowStats>,
    packet: &UdpPacket<'_>,
    ts: Option<f64>,
) {
    let key = FlowKey {
        src_ip: packet.src_ip,
        src_port: packet.src_port,
        dst_ip: packet.dst_ip,
        dst_port: packet.dst_port,
    };
    let entry = stats.entry(key).or_default();
    entry.packets += 1;
    entry.bytes += packet.payload.len() as u64;
    update_flow_jitter(entry, ts);
    update_flow_rates(entry, ts, packet.payload.len() as u64);
}

pub(crate) fn build_flow_summaries(
    stats: HashMap<FlowKey, FlowStats>,
    _duration_s: Option<f64>,
) -> Vec<FlowSummary> {
    let mut flows: Vec<FlowSummary> = stats
        .into_iter()
        .map(|(key, stats)| {
            let max_iat_ms = if stats.iat_count > 0 {
                stats.max_iat_ms
            } else {
                None
            };
            let (pps_peak_1s, bps_peak_1s) = match (stats.first_ts, stats.last_ts) {
                (Some(start), Some(end)) if end - start >= PPS_BPS_WINDOW_S => (
                    Some(stats.peak_window_packets),
                    Some(stats.peak_window_bytes),
                ),
                _ => (None, None),
            };
            let pps = stats.peak_pps;
            let bps = stats.peak_bps;
            let iat_jitter_ms = stats.jitter_peak.map(|value| value * 1000.0);

            FlowSummary {
                app_proto: "udp".to_string(),
                src: format_endpoint(key.src_ip, key.src_port),
                dst: format_endpoint(key.dst_ip, key.dst_port),
                pps,
                bps,
                iat_jitter_ms,
                max_iat_ms,
                pps_peak_1s,
                bps_peak_1s,
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

fn update_flow_jitter(stats: &mut FlowStats, ts: Option<f64>) {
    let ts = match ts {
        Some(ts) => ts,
        None => return,
    };

    if stats.first_ts.is_none() {
        stats.first_ts = Some(ts);
    }
    if let Some(last_ts) = stats.last_ts {
        let iat = ts - last_ts;
        if iat.is_finite() && iat >= 0.0 {
            stats.iat_count += 1;
            let ms = (iat * 1000.0).round();
            if ms.is_finite() && ms >= 0.0 {
                let ms = ms as u64;
                stats.max_iat_ms = Some(stats.max_iat_ms.map_or(ms, |prev| prev.max(ms)));
            }
        }
        if let Some(prev_iat) = stats.prev_iat {
            let diff = (iat - prev_iat).abs();
            stats.jitter_sum += diff;
            stats.jitter_samples.push_back((ts, diff));
            while let Some((sample_ts, sample)) = stats.jitter_samples.front().copied() {
                if ts - sample_ts <= JITTER_WINDOW_S {
                    break;
                }
                stats.jitter_sum -= sample;
                stats.jitter_samples.pop_front();
            }
            let window_avg = stats.jitter_sum / stats.jitter_samples.len() as f64;
            stats.jitter_peak = Some(
                stats
                    .jitter_peak
                    .map_or(window_avg, |peak| peak.max(window_avg)),
            );
        }
        stats.prev_iat = Some(iat);
    }
    stats.last_ts = Some(ts);
}

fn update_flow_rates(stats: &mut FlowStats, ts: Option<f64>, bytes: u64) {
    let ts = match ts {
        Some(ts) => ts,
        None => return,
    };
    stats.window_packets += 1;
    stats.window_bytes += bytes;
    stats.window_samples.push_back((ts, bytes));
    while let Some((sample_ts, sample_bytes)) = stats.window_samples.front().copied() {
        if ts - sample_ts <= PPS_BPS_WINDOW_S {
            break;
        }
        stats.window_packets = stats.window_packets.saturating_sub(1);
        stats.window_bytes = stats.window_bytes.saturating_sub(sample_bytes);
        stats.window_samples.pop_front();
    }
    let pps = stats.window_packets as f64 / PPS_BPS_WINDOW_S;
    let bps = stats.window_bytes as f64 / PPS_BPS_WINDOW_S;
    stats.peak_pps = Some(stats.peak_pps.map_or(pps, |peak| peak.max(pps)));
    stats.peak_bps = Some(stats.peak_bps.map_or(bps, |peak| peak.max(bps)));
    stats.peak_window_packets = stats.peak_window_packets.max(stats.window_packets);
    stats.peak_window_bytes = stats.peak_window_bytes.max(stats.window_bytes);
}

#[cfg(test)]
mod tests {
    use super::{FlowKey, FlowStats, add_flow_stats, build_flow_summaries};
    use crate::analysis::udp::UdpPacket;
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
                ..Default::default()
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
                ..Default::default()
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
    fn summaries_compute_peak_rates_from_window() {
        let mut stats = HashMap::new();
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let packet = UdpPacket {
            src_ip: a,
            src_port: 1000,
            dst_ip: b,
            dst_port: 2000,
            payload: &[0u8; 10],
        };

        add_flow_stats(&mut stats, &packet, Some(0.0));
        add_flow_stats(&mut stats, &packet, Some(0.2));
        add_flow_stats(&mut stats, &packet, Some(0.4));
        add_flow_stats(&mut stats, &packet, Some(2.0));

        let summaries = build_flow_summaries(stats, Some(2.0));
        let summary = &summaries[0];
        assert_eq!(summary.pps, Some(3.0));
        assert_eq!(summary.bps, Some(30.0));
    }

    #[test]
    fn flow_jitter_is_average_of_iat_diffs() {
        let mut stats = HashMap::new();
        let packet = UdpPacket {
            src_ip: "10.0.0.1".parse().unwrap(),
            src_port: 1000,
            dst_ip: "10.0.0.2".parse().unwrap(),
            dst_port: 2000,
            payload: &[0u8; 4],
        };

        add_flow_stats(&mut stats, &packet, Some(0.0));
        add_flow_stats(&mut stats, &packet, Some(1.0));
        add_flow_stats(&mut stats, &packet, Some(3.0));

        let summaries = build_flow_summaries(stats, Some(3.0));
        let summary = &summaries[0];
        let jitter = summary.iat_jitter_ms.unwrap_or(0.0);
        assert!((jitter - 1000.0).abs() < 0.1);
    }

    #[test]
    fn flow_jitter_missing_timestamps_is_none() {
        let mut stats = HashMap::new();
        let packet = UdpPacket {
            src_ip: "10.0.0.1".parse().unwrap(),
            src_port: 1000,
            dst_ip: "10.0.0.2".parse().unwrap(),
            dst_port: 2000,
            payload: &[0u8; 4],
        };

        add_flow_stats(&mut stats, &packet, None);
        add_flow_stats(&mut stats, &packet, None);

        let summaries = build_flow_summaries(stats, None);
        let summary = &summaries[0];
        assert!(summary.iat_jitter_ms.is_none());
    }

    #[test]
    fn flow_max_iat_ms_is_reported() {
        let mut stats = HashMap::new();
        let packet = UdpPacket {
            src_ip: "10.0.0.1".parse().unwrap(),
            src_port: 1000,
            dst_ip: "10.0.0.2".parse().unwrap(),
            dst_port: 2000,
            payload: &[0u8; 10],
        };

        add_flow_stats(&mut stats, &packet, Some(0.0));
        add_flow_stats(&mut stats, &packet, Some(0.5));
        add_flow_stats(&mut stats, &packet, Some(2.0));

        let summaries = build_flow_summaries(stats, Some(2.0));
        let summary = &summaries[0];
        assert_eq!(summary.max_iat_ms, Some(1500));
    }

    #[test]
    fn flow_peak_1s_metrics_are_reported() {
        let mut stats = HashMap::new();
        let packet = UdpPacket {
            src_ip: "10.0.0.1".parse().unwrap(),
            src_port: 1000,
            dst_ip: "10.0.0.2".parse().unwrap(),
            dst_port: 2000,
            payload: &[0u8; 10],
        };

        add_flow_stats(&mut stats, &packet, Some(0.0));
        add_flow_stats(&mut stats, &packet, Some(0.2));
        add_flow_stats(&mut stats, &packet, Some(0.4));
        add_flow_stats(&mut stats, &packet, Some(2.0));

        let summaries = build_flow_summaries(stats, Some(2.0));
        let summary = &summaries[0];
        assert_eq!(summary.pps_peak_1s, Some(3));
        assert_eq!(summary.bps_peak_1s, Some(30));
    }
}
