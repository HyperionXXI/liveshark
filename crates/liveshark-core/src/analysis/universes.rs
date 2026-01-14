use std::collections::HashMap;
use std::net::IpAddr;

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
    pub jitter: f64,
}

pub(crate) fn add_artnet_frame(
    stats: &mut HashMap<u16, UniverseStats>,
    universe: u16,
    source_ip: &IpAddr,
    sequence: Option<u8>,
    ts: Option<f64>,
) {
    let entry = stats.entry(universe).or_default();
    entry.frames += 1;
    let key = source_ip.to_string();
    entry.sources.entry(key.clone()).or_insert(SourceSummary {
        source_ip: key.clone(),
        cid: None,
        source_name: None,
    });
    let source_stats = entry.per_source.entry(key).or_default();
    update_source_stats(source_stats, sequence, ts);
    update_ts_bounds(&mut entry.first_ts, &mut entry.last_ts, ts);
}

pub(crate) fn add_sacn_frame(
    stats: &mut HashMap<u16, UniverseStats>,
    universe: u16,
    source_ip: &IpAddr,
    cid: String,
    source_name: Option<String>,
    sequence: Option<u8>,
    ts: Option<f64>,
) {
    let entry = stats.entry(universe).or_default();
    entry.frames += 1;
    let key = cid.clone();
    entry.sources.entry(key.clone()).or_insert(SourceSummary {
        source_ip: source_ip.to_string(),
        cid: Some(cid),
        source_name,
    });
    let source_stats = entry.per_source.entry(key).or_default();
    update_source_stats(source_stats, sequence, ts);
    update_ts_bounds(&mut entry.first_ts, &mut entry.last_ts, ts);
}

pub(crate) fn build_artnet_universe_summaries(
    stats: HashMap<u16, UniverseStats>,
) -> Vec<UniverseSummary> {
    build_universe_summaries(stats, "artnet")
}

pub(crate) fn build_sacn_universe_summaries(
    stats: HashMap<u16, UniverseStats>,
) -> Vec<UniverseSummary> {
    build_universe_summaries(stats, "sacn")
}

fn build_universe_summaries(
    stats: HashMap<u16, UniverseStats>,
    proto: &str,
) -> Vec<UniverseSummary> {
    let mut universes: Vec<UniverseSummary> = stats
        .into_iter()
        .map(|(universe, stats)| {
            let fps = match (stats.first_ts, stats.last_ts) {
                (Some(start), Some(end)) if end > start => {
                    Some(stats.frames as f64 / (end - start))
                }
                _ => None,
            };
            let mut sources: Vec<SourceSummary> = stats.sources.into_values().collect();
            sources.sort_by(|a, b| a.source_ip.cmp(&b.source_ip));
            let metrics = compute_metrics(&stats.per_source, stats.frames);

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
    if let (Some(ts), Some(last_ts)) = (ts, stats.last_ts) {
        let iat = ts - last_ts;
        if let Some(prev_iat) = stats.prev_iat {
            let diff = (iat - prev_iat).abs();
            stats.jitter += (diff - stats.jitter) / 16.0;
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
                if stats.current_burst == 0 {
                    stats.burst_count += 1;
                }
                stats.current_burst += gap as u64;
                if stats.current_burst > stats.max_burst_len {
                    stats.max_burst_len = stats.current_burst;
                }
            } else {
                stats.current_burst = 0;
            }
        }
        stats.last_seq = Some(seq);
    }
}

fn compute_metrics(
    per_source: &HashMap<String, UniverseSourceStats>,
    frames: u64,
) -> UniverseMetrics {
    let mut total_loss = 0u64;
    let mut total_bursts = 0u64;
    let mut max_burst = 0u64;
    let mut jitter_sum = 0.0;
    let mut jitter_count = 0u64;
    let mut any_seq = false;

    for stats in per_source.values() {
        if stats.last_seq.is_some() {
            any_seq = true;
        }
        total_loss += stats.loss;
        total_bursts += stats.burst_count;
        if stats.max_burst_len > max_burst {
            max_burst = stats.max_burst_len;
        }
        if stats.prev_iat.is_some() {
            jitter_sum += stats.jitter;
            jitter_count += 1;
        }
    }

    let loss_packets = if any_seq && frames > 1 {
        Some(total_loss)
    } else {
        None
    };
    let loss_rate = if let Some(loss) = loss_packets {
        let denom = frames + loss;
        if denom > 0 {
            Some(loss as f64 / denom as f64)
        } else {
            None
        }
    } else {
        None
    };
    let burst_count = if any_seq && frames > 1 {
        Some(total_bursts)
    } else {
        None
    };
    let max_burst_len = if any_seq && frames > 1 {
        Some(max_burst)
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
                    let src_a_label = source_label(uni, src_a_key);
                    let src_b_label = source_label(uni, src_b_key);
                    conflicts.push(crate::ConflictSummary {
                        universe: *universe,
                        sources: vec![src_a_label, src_b_label],
                        overlap_duration_s: overlap,
                        affected_channels: vec![],
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

fn source_label(stats: &UniverseStats, key: &str) -> String {
    stats
        .sources
        .get(key)
        .and_then(|s| s.cid.clone().or_else(|| Some(s.source_ip.clone())))
        .unwrap_or_else(|| key.to_string())
}
