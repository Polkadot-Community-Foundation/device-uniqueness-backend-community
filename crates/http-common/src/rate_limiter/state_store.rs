use std::{sync::Arc, time::Duration};

use governor::{
    nanos::Nanos,
    state::{InMemoryState, NotKeyed, StateStore},
};
use moka::sync::Cache;

pub(crate) struct MokaStateStore(pub moka::sync::Cache<String, Arc<InMemoryState>>);

impl StateStore for MokaStateStore {
    type Key = String;

    fn measure_and_replace<T, F, E>(&self, key: &Self::Key, f: F) -> Result<T, E>
    where
        F: Fn(Option<Nanos>) -> Result<(T, Nanos), E>,
    {
        let entry = self.0.entry(key.clone()).or_default();
        (*entry.into_value()).measure_and_replace(&NotKeyed::NonKey, f)
    }
}

impl MokaStateStore {
    pub(crate) fn new(limit: u64, tti_secs: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(limit)
            .time_to_idle(Duration::from_secs(tti_secs))
            .build();

        MokaStateStore(cache)
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use tokio::time;

    use super::MokaStateStore;

    #[tokio::test]
    async fn limits_respected() {
        let store = MokaStateStore::new(2, 5);
        for k in 0..=2 {
            store
                .0
                .insert(String::from(char::from_u32(k).unwrap()), Default::default());
        }
        assert!(store
            .0
            .get(&String::from(char::from_u32(0).unwrap()))
            .is_some());

        assert!(store
            .0
            .get(&String::from(char::from_u32(2).unwrap()))
            .is_some());

        time::sleep(Duration::from_secs(5)).await;

        assert!(store
            .0
            .get(&String::from(char::from_u32(1).unwrap()))
            .is_none());
        assert!(store
            .0
            .get(&String::from(char::from_u32(2).unwrap()))
            .is_none());
        assert_eq!(store.0.entry_count(), 0);
    }
}
