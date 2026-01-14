use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use super::dmx::{DmxProtocol, DmxStore};
use crate::{SourceSummary, UniverseSummary};

#[derive(Debug, Default)]
pub(crate) struct UniverseStats {
    pub frames: u64,
    pub sources: HashMap<String, SourceSummary>,
    pub first_ts: Option<f64>,
    pub last_ts: Option<f64>,
    pub per_source: HashMap<String, UniverseSourceStats>,
}

#[derive(Debug, Default)]
pub(crate) struct UniverseSourceStats {
    pub frames: u64,
    pub loss: u64,
    pub burst_count: u64,
    pub max_burst_len: u64,
    pub current_burst: u64,
    pub last_seq: Option<u8>,
    pub first_ts: Option<f64>,
    pub last_ts: Option<f64>,
    pub prev_iat: Option<f64>,
    pub jitter_sum: f64,
    pub jitter_samples: VecDeque<(f64, f64)>,
    pub frame_samples: VecDeque<f64>,
    pub loss_sum: u64,
    pub loss_samples: VecDeque<(f64, u64)>,
    pub burst_start_samples: VecDeque<f64>,
    pub burst_length_samples: VecDeque<(f64, u64)>,
}

const JITTER_WINDOW_S: f64 = 10.0;

fn artnet_source_id(source_ip: &IpAddr, source_port: u16) -> String {
    format!("artnet:{}:{}", source_ip, source_port)
}

fn sacn_source_id(cid: &str, source_ip: &IpAddr, source_port: u16) -> String {
    if cid.is_empty() {
        format!("sacn:{}:{}", source_ip, source_port)
    } else {
        format!("sacn:cid:{}", cid)
    }
}

pub(crate) fn add_artnet_frame(
    stats: &mut HashMap<u16, UniverseStats>,
    universe: u16,
    source_ip: &IpAddr,
    source_port: u16,
    sequence: Option<u8>,
    ts: Option<f64>,
) -> String {
    let entry = stats.entry(universe).or_default();
    entry.frames += 1;
    let source_id = artnet_source_id(source_ip, source_port);
    entry
        .sources
        .entry(source_id.clone())
        .or_insert(SourceSummary {
            source_ip: source_ip.to_string(),
            cid: None,
            source_name: None,
        });
    let source_stats = entry.per_source.entry(source_id.clone()).or_default();
    update_source_stats(source_stats, sequence, ts);
    update_ts_bounds(&mut entry.first_ts, &mut entry.last_ts, ts);
    source_id
}

pub(crate) fn add_sacn_frame(
    stats: &mut HashMap<u16, UniverseStats>,
    universe: u16,
    source_ip: &IpAddr,
    source_port: u16,
    cid: String,
    source_name: Option<String>,
    sequence: Option<u8>,
    ts: Option<f64>,
) -> String {
    let entry = stats.entry(universe).or_default();
    entry.frames += 1;
    let source_id = sacn_source_id(&cid, source_ip, source_port);
    entry
        .sources
        .entry(source_id.clone())
        .or_insert(SourceSummary {
            source_ip: source_ip.to_string(),
            cid: Some(cid),
            source_name,
        });
    let source_stats = entry.per_source.entry(source_id.clone()).or_default();
    update_source_stats(source_stats, sequence, ts);
    update_ts_bounds(&mut entry.first_ts, &mut entry.last_ts, ts);
    source_id
}

pub(crate) fn build_artnet_universe_summaries(
    stats: HashMap<u16, UniverseStats>,
    dmx_store: &DmxStore,
) -> Vec<UniverseSummary> {
    build_universe_summaries(stats, dmx_store, DmxProtocol::ArtNet, "artnet")
}

pub(crate) fn build_sacn_universe_summaries(
    stats: HashMap<u16, UniverseStats>,
    dmx_store: &DmxStore,
) -> Vec<UniverseSummary> {
    build_universe_summaries(stats, dmx_store, DmxProtocol::Sacn, "sacn")
}

fn build_universe_summaries(
    stats: HashMap<u16, UniverseStats>,
    dmx_store: &DmxStore,
    protocol: DmxProtocol,
    proto: &str,
) -> Vec<UniverseSummary> {
    let mut universes: Vec<UniverseSummary> = stats
        .into_iter()
        .map(|(universe, stats)| {
            let fps = fps_from_dmx(dmx_store, universe, protocol, stats.frames);
            let mut sources: Vec<SourceSummary> = stats.sources.into_values().collect();
            sources.sort_by(|a, b| a.source_ip.cmp(&b.source_ip));
            let metrics = compute_metrics(&stats.per_source);

            UniverseSummary {
                universe,
                proto: proto.to_string(),
                sources,
                fps,
                frames_count: stats.frames,
                loss_packets: metrics.loss_packets,
                loss_rate: metrics.loss_rate,
                burst_count: metrics.burst_count,
                max_burst_len: metrics.max_burst_len,
                jitter_ms: metrics.jitter_ms,
            }
        })
        .collect();

    universes.sort_by(|a, b| a.universe.cmp(&b.universe));
    universes
}

fn fps_from_dmx(
    dmx_store: &DmxStore,
    universe: u16,
    protocol: DmxProtocol,
    fallback_frames: u64,
) -> Option<f64> {
    let frames = dmx_store.frames_for_universe(universe, protocol);
    let mut last_ts = None;
    let mut earliest_ts = None;
    let mut counted = 0u64;

    for frame in frames {
        if let Some(ts) = frame.timestamp {
            update_ts_bounds(&mut earliest_ts, &mut last_ts, Some(ts));
            counted += 1;
        }
    }

    let frame_count = if counted > 0 {
        counted
    } else {
        fallback_frames
    };
    let (Some(last_ts), Some(earliest_ts)) = (last_ts, earliest_ts) else {
        return None;
    };
    if last_ts <= earliest_ts || frame_count == 0 {
        return None;
    }
    let window_start = last_ts - 5.0;
    let mut window_count = 0u64;
    for frame in dmx_store.frames_for_universe(universe, protocol) {
        if let Some(ts) = frame.timestamp {
            if ts >= window_start {
                window_count += 1;
            }
        }
    }
    let window_duration = if last_ts - earliest_ts < 5.0 {
        last_ts - earliest_ts
    } else {
        5.0
    };
    match window_duration {
        duration if duration > 0.0 && window_count > 0 => Some(window_count as f64 / duration),
        _ => None,
    }
}

struct UniverseMetrics {
    loss_packets: Option<u64>,
    loss_rate: Option<f64>,
    burst_count: Option<u64>,
    max_burst_len: Option<u64>,
    jitter_ms: Option<f64>,
}

fn update_source_stats(stats: &mut UniverseSourceStats, sequence: Option<u8>, ts: Option<f64>) {
    stats.frames += 1;

    if stats.first_ts.is_none() {
        stats.first_ts = ts;
    }
    if let Some(ts) = ts {
        stats.frame_samples.push_back(ts);
        prune_frame_samples(&mut stats.frame_samples, ts);
    }

    if let (Some(ts), Some(last_ts)) = (ts, stats.last_ts) {
        let iat = ts - last_ts;
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
        }
        stats.prev_iat = Some(iat);
    }
    stats.last_ts = ts;

    if let Some(seq) = sequence {
        if let Some(last) = stats.last_seq {
            let expected = last.wrapping_add(1);
            let gap = seq.wrapping_sub(expected) as u16;
            if gap > 0 && gap < 128 {
                stats.loss += gap as u64;
                if let Some(ts) = ts {
                    stats.loss_sum += gap as u64;
                    stats.loss_samples.push_back((ts, gap as u64));
                    prune_loss_samples(&mut stats.loss_samples, &mut stats.loss_sum, ts);
                }
                if stats.current_burst == 0 {
                    stats.burst_count += 1;
                    if let Some(ts) = ts {
                        stats.burst_start_samples.push_back(ts);
                        prune_burst_starts(&mut stats.burst_start_samples, ts);
                    }
                }
                stats.current_burst += gap as u64;
                if stats.current_burst > stats.max_burst_len {
                    stats.max_burst_len = stats.current_burst;
                }
            } else {
                if stats.current_burst > 0 {
                    if let Some(ts) = ts {
                        stats
                            .burst_length_samples
                            .push_back((ts, stats.current_burst));
                        prune_burst_lengths(&mut stats.burst_length_samples, ts);
                    }
                }
                stats.current_burst = 0;
            }
        }
        stats.last_seq = Some(seq);
    }
}

fn compute_metrics(per_source: &HashMap<String, UniverseSourceStats>) -> UniverseMetrics {
    let mut jitter_sum = 0.0;
    let mut jitter_count = 0u64;
    let mut any_seq = false;
    let mut total_seq_frames = 0u64;
    let mut total_seq_loss = 0u64;
    let mut total_seq_bursts = 0u64;
    let mut total_seq_max_burst = 0u64;

    for stats in per_source.values() {
        if stats.last_seq.is_some() {
            any_seq = true;
            total_seq_frames += frames_in_window(stats);
            total_seq_loss += loss_in_window(stats);
            total_seq_bursts += burst_count_in_window(stats);
            let max_burst = max_burst_len_in_window(stats);
            if max_burst > total_seq_max_burst {
                total_seq_max_burst = max_burst;
            }
        }
        if !stats.jitter_samples.is_empty() {
            jitter_sum += stats.jitter_sum / stats.jitter_samples.len() as f64;
            jitter_count += 1;
        }
    }

    let loss_packets = if any_seq && total_seq_frames > 1 {
        Some(total_seq_loss)
    } else {
        None
    };
    let loss_rate = if let Some(loss) = loss_packets {
        let denom = total_seq_frames + loss;
        if denom > 0 {
            Some(loss as f64 / denom as f64)
        } else {
            None
        }
    } else {
        None
    };
    let burst_count = if any_seq && total_seq_frames > 1 {
        Some(total_seq_bursts)
    } else {
        None
    };
    let max_burst_len = if any_seq && total_seq_frames > 1 {
        Some(total_seq_max_burst)
    } else {
        None
    };
    let jitter_ms = if jitter_count > 0 {
        Some((jitter_sum / jitter_count as f64) * 1000.0)
    } else {
        None
    };

    UniverseMetrics {
        loss_packets,
        loss_rate,
        burst_count,
        max_burst_len,
        jitter_ms,
    }
}

fn update_ts_bounds(first: &mut Option<f64>, last: &mut Option<f64>, ts: Option<f64>) {
    let ts = match ts {
        Some(ts) => ts,
        None => return,
    };
    match first {
        None => *first = Some(ts),
        Some(existing) => {
            if ts < *existing {
                *first = Some(ts);
            }
        }
    }
    match last {
        None => *last = Some(ts),
        Some(existing) => {
            if ts > *existing {
                *last = Some(ts);
            }
        }
    }
}

fn frames_in_window(stats: &UniverseSourceStats) -> u64 {
    if stats.frame_samples.is_empty() {
        stats.frames
    } else {
        stats.frame_samples.len() as u64
    }
}

fn loss_in_window(stats: &UniverseSourceStats) -> u64 {
    if stats.loss_samples.is_empty() {
        stats.loss
    } else {
        stats.loss_sum
    }
}

fn burst_count_in_window(stats: &UniverseSourceStats) -> u64 {
    if stats.burst_start_samples.is_empty() {
        stats.burst_count
    } else {
        stats.burst_start_samples.len() as u64
    }
}

fn max_burst_len_in_window(stats: &UniverseSourceStats) -> u64 {
    if stats.burst_length_samples.is_empty() && stats.current_burst == 0 {
        return stats.max_burst_len;
    }
    let mut max_len = stats.current_burst;
    for (_, len) in &stats.burst_length_samples {
        if *len > max_len {
            max_len = *len;
        }
    }
    max_len
}

fn prune_frame_samples(samples: &mut VecDeque<f64>, now: f64) {
    while let Some(ts) = samples.front().copied() {
        if now - ts <= JITTER_WINDOW_S {
            break;
        }
        samples.pop_front();
    }
}

fn prune_loss_samples(samples: &mut VecDeque<(f64, u64)>, sum: &mut u64, now: f64) {
    while let Some((ts, loss)) = samples.front().copied() {
        if now - ts <= JITTER_WINDOW_S {
            break;
        }
        *sum = sum.saturating_sub(loss);
        samples.pop_front();
    }
}

fn prune_burst_starts(samples: &mut VecDeque<f64>, now: f64) {
    while let Some(ts) = samples.front().copied() {
        if now - ts <= JITTER_WINDOW_S {
            break;
        }
        samples.pop_front();
    }
}

fn prune_burst_lengths(samples: &mut VecDeque<(f64, u64)>, now: f64) {
    while let Some((ts, _)) = samples.front().copied() {
        if now - ts <= JITTER_WINDOW_S {
            break;
        }
        samples.pop_front();
    }
}

pub(crate) fn build_conflicts(stats: &HashMap<u16, UniverseStats>) -> Vec<crate::ConflictSummary> {
    let mut conflicts = Vec::new();

    for (universe, uni) in stats {
        let mut keys: Vec<&String> = uni.per_source.keys().collect();
        keys.sort();
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                let src_a_key = keys[i];
                let src_b_key = keys[j];
                let src_a_stats = &uni.per_source[src_a_key];
                let src_b_stats = &uni.per_source[src_b_key];

                let (start_a, end_a) = match (src_a_stats.first_ts, src_a_stats.last_ts) {
                    (Some(start), Some(end)) => (start, end),
                    _ => continue,
                };
                let (start_b, end_b) = match (src_b_stats.first_ts, src_b_stats.last_ts) {
                    (Some(start), Some(end)) => (start, end),
                    _ => continue,
                };

                let overlap = (end_a.min(end_b) - start_a.max(start_b)).max(0.0);
                if overlap > 1.0 {
                    let src_a_label = source_label(src_a_key);
                    let src_b_label = source_label(src_b_key);
                    let affected_channels = compute_affected_channels();
                    conflicts.push(crate::ConflictSummary {
                        universe: *universe,
                        sources: vec![src_a_label, src_b_label],
                        overlap_duration_s: overlap,
                        affected_channels,
                        severity: "medium".to_string(),
                        conflict_score: overlap,
                    });
                }
            }
        }
    }

    conflicts.sort_by(|a, b| {
        a.universe
            .cmp(&b.universe)
            .then_with(|| a.sources.join(",").cmp(&b.sources.join(",")))
    });
    conflicts
}

fn compute_affected_channels() -> Vec<u16> {
    Vec::new()
}

fn source_label(key: &str) -> String {
    key.to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        UniverseSourceStats, add_artnet_frame, build_artnet_universe_summaries, build_conflicts,
        compute_metrics, update_source_stats,
    };
    use crate::analysis::dmx::{DmxFrame, DmxProtocol, DmxStore};
    use std::collections::{HashMap, VecDeque};
    use std::net::IpAddr;

    #[test]
    fn universe_summary_without_timestamps_has_no_metrics() {
        let mut stats = HashMap::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        add_artnet_frame(&mut stats, 1, &ip, 6454, None, None);

        let dmx_store = DmxStore::default();
        let summaries = build_artnet_universe_summaries(stats, &dmx_store);
        assert_eq!(summaries.len(), 1);
        let summary = &summaries[0];
        assert_eq!(summary.universe, 1);
        assert!(summary.fps.is_none());
        assert!(summary.loss_packets.is_none());
        assert!(summary.loss_rate.is_none());
        assert!(summary.burst_count.is_none());
        assert!(summary.max_burst_len.is_none());
        assert!(summary.jitter_ms.is_none());
    }

    #[test]
    fn conflict_requires_overlap_over_one_second() {
        let mut stats = HashMap::new();
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();

        add_artnet_frame(&mut stats, 1, &ip_a, 6454, None, Some(0.0));
        add_artnet_frame(&mut stats, 1, &ip_a, 6454, None, Some(2.5));
        add_artnet_frame(&mut stats, 1, &ip_b, 6454, None, Some(1.0));
        add_artnet_frame(&mut stats, 1, &ip_b, 6454, None, Some(3.0));

        let conflicts = build_conflicts(&stats);
        assert_eq!(conflicts.len(), 1);
        let conflict = &conflicts[0];
        assert_eq!(conflict.universe, 1);
        assert_eq!(conflict.sources.len(), 2);
        assert!(
            conflict
                .sources
                .contains(&"artnet:10.0.0.1:6454".to_string())
        );
        assert!(
            conflict
                .sources
                .contains(&"artnet:10.0.0.2:6454".to_string())
        );
    }

    #[test]
    fn jitter_uses_sliding_window() {
        let mut source_stats = UniverseSourceStats::default();
        update_source_stats(&mut source_stats, None, Some(0.0));
        update_source_stats(&mut source_stats, None, Some(1.0));
        update_source_stats(&mut source_stats, None, Some(2.0));
        update_source_stats(&mut source_stats, None, Some(13.0));

        let mut per_source = HashMap::new();
        per_source.insert("artnet:10.0.0.1:6454".to_string(), source_stats);
        let metrics = compute_metrics(&per_source);

        let jitter_ms = metrics.jitter_ms.unwrap_or(0.0);
        assert!((jitter_ms - 10000.0).abs() < 0.1);
    }

    #[test]
    fn loss_rate_uses_sequence_tracked_frames() {
        let mut per_source = HashMap::new();
        per_source.insert(
            "artnet:10.0.0.1:6454".to_string(),
            UniverseSourceStats {
                frames: 2,
                loss: 1,
                last_seq: Some(1),
                ..UniverseSourceStats::default()
            },
        );
        per_source.insert(
            "artnet:10.0.0.2:6454".to_string(),
            UniverseSourceStats {
                frames: 10,
                last_seq: None,
                ..UniverseSourceStats::default()
            },
        );

        let metrics = compute_metrics(&per_source);
        let loss_rate = metrics.loss_rate.unwrap_or(0.0);
        assert!((loss_rate - (1.0 / 3.0)).abs() < 0.0001);
    }

    #[test]
    fn loss_uses_windowed_samples() {
        let mut per_source = HashMap::new();
        per_source.insert(
            "artnet:10.0.0.1:6454".to_string(),
            UniverseSourceStats {
                frames: 2,
                loss: 5,
                loss_sum: 2,
                loss_samples: VecDeque::from([(20.0, 2)]),
                frame_samples: VecDeque::from([19.0, 20.0]),
                last_seq: Some(1),
                ..UniverseSourceStats::default()
            },
        );

        let metrics = compute_metrics(&per_source);
        assert_eq!(metrics.loss_packets, Some(2));
        assert_eq!(metrics.loss_rate, Some(0.5));
    }

    #[test]
    fn fps_uses_last_five_seconds() {
        let mut stats = HashMap::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        add_artnet_frame(&mut stats, 1, &ip, 6454, None, Some(0.0));
        add_artnet_frame(&mut stats, 1, &ip, 6454, None, Some(1.0));
        add_artnet_frame(&mut stats, 1, &ip, 6454, None, Some(2.0));
        add_artnet_frame(&mut stats, 1, &ip, 6454, None, Some(7.0));

        let mut dmx_store = DmxStore::default();
        let mut slots = [0u8; 512];
        slots[0] = 1;
        for ts in [0.0, 1.0, 2.0, 7.0] {
            dmx_store.push(DmxFrame {
                universe: 1,
                timestamp: Some(ts),
                source_id: "artnet:10.0.0.1:6454".to_string(),
                protocol: DmxProtocol::ArtNet,
                slots,
            });
        }

        let summaries = build_artnet_universe_summaries(stats, &dmx_store);
        let fps = summaries[0].fps.unwrap_or(0.0);
        assert!((fps - 0.4).abs() < 0.0001);
    }
}
