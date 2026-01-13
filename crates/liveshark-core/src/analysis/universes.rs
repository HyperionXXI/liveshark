use std::collections::HashMap;
use std::net::IpAddr;

use crate::{SourceSummary, UniverseSummary};

#[derive(Debug, Default)]
pub(crate) struct UniverseStats {
    pub frames: u64,
    pub sources: HashMap<String, SourceSummary>,
    pub first_ts: Option<f64>,
    pub last_ts: Option<f64>,
}

pub(crate) fn add_artnet_frame(
    stats: &mut HashMap<u16, UniverseStats>,
    universe: u16,
    source_ip: &IpAddr,
    ts: Option<f64>,
) {
    let entry = stats.entry(universe).or_default();
    entry.frames += 1;
    let key = source_ip.to_string();
    entry.sources.entry(key.clone()).or_insert(SourceSummary {
        source_ip: key,
        cid: None,
        source_name: None,
    });
    update_ts_bounds(&mut entry.first_ts, &mut entry.last_ts, ts);
}

pub(crate) fn add_sacn_frame(
    stats: &mut HashMap<u16, UniverseStats>,
    universe: u16,
    source_ip: &IpAddr,
    cid: String,
    source_name: Option<String>,
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

            UniverseSummary {
                universe,
                proto: proto.to_string(),
                sources,
                fps,
                frames_count: stats.frames,
            }
        })
        .collect();

    universes.sort_by(|a, b| a.universe.cmp(&b.universe));
    universes
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
