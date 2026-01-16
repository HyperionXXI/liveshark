use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

#[derive(Debug, Default)]
pub(crate) struct DmxStateStore {
    states: HashMap<DmxStateKey, [u8; 512]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DmxStateKey {
    universe: u16,
    source_id: String,
    protocol: DmxProtocol,
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

    pub(crate) fn frames_for_universe(
        &self,
        universe: u16,
        protocol: DmxProtocol,
    ) -> Vec<&DmxFrame> {
        let Some(per_source) = self.frames_by_universe.get(&universe) else {
            return Vec::new();
        };

        per_source
            .values()
            .flat_map(|frames| frames.iter())
            .filter(|frame| frame.protocol == protocol)
            .collect()
    }

    #[allow(dead_code)]
    pub(crate) fn frames_for(&self, universe: u16, source_id: &str) -> Option<&[DmxFrame]> {
        self.frames_by_universe
            .get(&universe)
            .and_then(|per_source| per_source.get(source_id).map(|v| v.as_slice()))
    }
}

impl DmxStateStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn apply_partial(
        &mut self,
        universe: u16,
        source_id: String,
        protocol: DmxProtocol,
        partial_slots: &[u8],
    ) -> [u8; 512] {
        let key = DmxStateKey {
            universe,
            source_id,
            protocol,
        };
        let entry = self.states.entry(key).or_insert([0u8; 512]);
        let len = partial_slots.len().min(512);
        if len > 0 {
            entry[..len].copy_from_slice(&partial_slots[..len]);
        }
        *entry
    }
}

#[cfg(test)]
mod tests {
    use super::{DmxFrame, DmxProtocol, DmxStateStore, DmxStore};

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

    #[test]
    fn stateful_reconstruction_retains_last_known_values_artnet() {
        let mut state = DmxStateStore::new();
        let slots = state.apply_partial(
            1,
            "artnet:10.0.0.1:6454".to_string(),
            DmxProtocol::ArtNet,
            &[10, 11, 12, 13, 14, 15, 16, 17, 18, 19],
        );
        assert_eq!(&slots[..10], &[10, 11, 12, 13, 14, 15, 16, 17, 18, 19]);
        assert_eq!(slots[10], 0);
        assert_eq!(slots[511], 0);

        let slots = state.apply_partial(
            1,
            "artnet:10.0.0.1:6454".to_string(),
            DmxProtocol::ArtNet,
            &[42, 43, 44, 45, 46],
        );
        assert_eq!(&slots[..5], &[42, 43, 44, 45, 46]);
        assert_eq!(&slots[5..10], &[15, 16, 17, 18, 19]);
        assert_eq!(slots[10], 0);
        assert_eq!(slots[511], 0);
    }

    #[test]
    fn stateful_reconstruction_retains_last_known_values_sacn() {
        let mut state = DmxStateStore::new();
        let slots = state.apply_partial(
            1,
            "sacn:cid:00112233445566778899aabbccddeeff".to_string(),
            DmxProtocol::Sacn,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        );
        assert_eq!(&slots[..10], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(slots[10], 0);
        assert_eq!(slots[511], 0);

        let slots = state.apply_partial(
            1,
            "sacn:cid:00112233445566778899aabbccddeeff".to_string(),
            DmxProtocol::Sacn,
            &[200, 201, 202, 203, 204],
        );
        assert_eq!(&slots[..5], &[200, 201, 202, 203, 204]);
        assert_eq!(&slots[5..10], &[6, 7, 8, 9, 10]);
        assert_eq!(slots[10], 0);
        assert_eq!(slots[511], 0);
    }

    #[test]
    fn state_isolated_by_universe_and_protocol() {
        let mut state = DmxStateStore::new();
        let source_id = "source:example".to_string();

        let artnet_slots = state.apply_partial(1, source_id.clone(), DmxProtocol::ArtNet, &[9, 8]);
        let sacn_slots = state.apply_partial(1, source_id.clone(), DmxProtocol::Sacn, &[1, 2]);
        let other_universe = state.apply_partial(2, source_id.clone(), DmxProtocol::ArtNet, &[7]);

        assert_eq!(&artnet_slots[..2], &[9, 8]);
        assert_eq!(&sacn_slots[..2], &[1, 2]);
        assert_eq!(other_universe[0], 7);

        let artnet_again = state.apply_partial(1, source_id, DmxProtocol::ArtNet, &[]);
        assert_eq!(&artnet_again[..2], &[9, 8]);
    }
}
