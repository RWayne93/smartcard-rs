use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReaderHealth {
    Healthy,
    Slow,
    Unresponsive,
    Resetting,
}

impl ReaderHealth {
    pub fn from_elapsed(elapsed: Duration, slow_threshold: Duration) -> Self {
        if elapsed > slow_threshold {
            Self::Slow
        } else {
            Self::Healthy
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaderInfo {
    pub name: String,
    pub atr: Option<Vec<u8>>,
    pub card_present: bool,
    pub health: ReaderHealth,
}

impl ReaderInfo {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            atr: None,
            card_present: false,
            health: ReaderHealth::Healthy,
        }
    }

    pub fn with_atr(mut self, atr: Vec<u8>) -> Self {
        self.atr = Some(atr);
        self
    }

    pub fn with_card_present(mut self, card_present: bool) -> Self {
        self.card_present = card_present;
        self
    }

    pub fn with_health(mut self, health: ReaderHealth) -> Self {
        self.health = health;
        self
    }
}
