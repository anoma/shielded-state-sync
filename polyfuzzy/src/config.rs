//! Safe system configuration
//!
//! The configuration is given
//! by the threat model and the
//! total number of servers.

use strum_macros::EnumIter;

/// An upper bound of flag sizes valid for all safe configurations.
pub const GAMMA: usize = 18;
/// An upper bound for compact public keys for all safe configurations.
pub const M: usize = 7;

/// The assumption on the number of corrupted servers.
#[derive(Clone, EnumIter)]
pub enum ThreatModel {
    /// Up to [NumDetectionServers]-1 corrupted servers.
    DishonestMajority,
    /// Up to ([NumDetectionServers]-1)/2 servers can be corrupted.
    HonestMajority,
}

/// Number of allowed servers
#[derive(Clone, Debug, EnumIter)]
pub enum NumDetectionServers {
    One, // Standard FMD setting.
    Two,
    Three,
    Four,
    Five,
    Six,
}
/// Rate leaked to (a coallition of) the servers is 2^{-n} with 1 ≤ n ≤ 6.
#[derive(Debug, EnumIter)]
pub enum SafeRateFunction {
    One,
    Two,
    Three,
    Four,
    Five,
    Six,
}

impl From<SafeRateFunction> for usize {
    fn from(value: SafeRateFunction) -> Self {
        match value {
            SafeRateFunction::One => 1,
            SafeRateFunction::Two => 2,
            SafeRateFunction::Three => 3,
            SafeRateFunction::Four => 4,
            SafeRateFunction::Five => 5,
            SafeRateFunction::Six => 6,
        }
    }
}

impl SafeRateFunction {
    /// Returns the server and receiver false-positive rates (n,δ).  
    /// The filtering rate δ is for the maximally corrupted servers,
    /// determined by the threat model and the number of total servers.
    pub fn filtering_rates(
        self,
        model: ThreatModel,
        num_servers: NumDetectionServers,
    ) -> (usize, usize) {
        let (t, d) = get_safe_parameters(model, num_servers);

        let n = self.into();
        let delta = n + (d - t) * n / t;
        (n, delta)
    }
}

/// Returns (`corruption_threshold`,`num_detection_keys`)
pub fn get_safe_parameters(model: ThreatModel, num_servers: NumDetectionServers) -> (usize, usize) {
    match (model, num_servers) {
        (ThreatModel::HonestMajority, NumDetectionServers::One) => (1, 1), // Standard FMD.
        (ThreatModel::HonestMajority, NumDetectionServers::Two) => (1, 2),
        (ThreatModel::HonestMajority, NumDetectionServers::Three) => (2, 3),
        (ThreatModel::HonestMajority, NumDetectionServers::Four) => (3, 4),
        (ThreatModel::HonestMajority, NumDetectionServers::Five) => (4, 5),
        (ThreatModel::HonestMajority, NumDetectionServers::Six) => (5, 6),
        (ThreatModel::DishonestMajority, NumDetectionServers::One) => (1, 1), // Standard FMD.
        (ThreatModel::DishonestMajority, NumDetectionServers::Two) => (1, 2),
        (ThreatModel::DishonestMajority, NumDetectionServers::Three) => (1, 3),
        (ThreatModel::DishonestMajority, NumDetectionServers::Four) => (2, 4),
        (ThreatModel::DishonestMajority, NumDetectionServers::Five) => (3, 5),
        (ThreatModel::DishonestMajority, NumDetectionServers::Six) => (3, 6),
    }
}
