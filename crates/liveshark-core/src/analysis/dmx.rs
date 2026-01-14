use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DmxProtocol {
    ArtNet,
    Sacn,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DmxFrame {
    pub universe: u16,
    pub timestamp: Option<f64>,
    pub source_id: String,
    pub protocol: DmxProtocol,
    pub slots: [u8; 512],
}

#[derive(Debug, Default)]
pub(crate) struct DmxStore {
    frames_by_universe: HashMap<u16, HashMap<String, Vec<DmxFrame>>>,
}

impl DmxStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn push(&mut self, frame: DmxFrame) {
        let per_universe = self.frames_by_universe.entry(frame.universe).or_default();
        per_universe
            .entry(frame.source_id.clone())
            .or_default()
            .push(frame);
    }

    #[allow(dead_code)]
    pub(crate) fn frames_for(&self, universe: u16, source_id: &str) -> Option<&[DmxFrame]> {
        self.frames_by_universe
            .get(&universe)
            .and_then(|per_source| per_source.get(source_id).map(|v| v.as_slice()))
    }
}

#[cfg(test)]
mod tests {
    use super::{DmxFrame, DmxProtocol, DmxStore};

    #[test]
    fn stores_frames_by_universe_and_source() {
        let mut store = DmxStore::new();
        let mut slots = [0u8; 512];
        slots[0] = 42;

        let frame = DmxFrame {
            universe: 1,
            timestamp: Some(1.0),
            source_id: "artnet:10.0.0.1:6454".to_string(),
            protocol: DmxProtocol::ArtNet,
            slots,
        };

        store.push(frame.clone());
        let stored = store.frames_for(1, "artnet:10.0.0.1:6454").unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0], frame);
    }
}
