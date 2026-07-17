use serde::{Deserialize, Serialize};

pub const NORMALIZED_BODY: &str = r#"{"outcome":"complete"}"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Sender,
    Probe,
    Control,
}

impl Role {
    pub const fn abi(self) -> i32 {
        match self {
            Self::Sender => 0,
            Self::Probe => 1,
            Self::Control => 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnRequest {
    pub session_slot: u16,
    pub trial_id: u64,
    pub role: Role,
    pub bit: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub mode: String,
    pub wasm_sha256: String,
    pub state_bytes: usize,
    pub session_slots: usize,
    pub sender_hot_iterations: u32,
    pub sender_cold_iterations: u32,
    pub sender_control_iterations: u32,
    pub probe_iterations: u32,
    pub execution_cutoff_us: u64,
    pub release_slot_us: u64,
    pub successful_turns: u64,
    pub timed_out_turns: u64,
    pub failed_turns: u64,
}

#[cfg(feature = "bench")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrialRecord {
    pub trial_id: u64,
    pub gap_us: u64,
    pub expected_bit: u8,
    pub sender_latency_ns: u64,
    pub probe_latency_ns: u64,
}

#[cfg(feature = "bench")]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GapSummary {
    pub gap_us: u64,
    pub scored_trials: u64,
    pub zero_mean_us: f64,
    pub one_mean_us: f64,
    pub mean_delta_us: f64,
    pub threshold_us: f64,
    pub high_latency_is_one: bool,
    pub bit_error_rate: f64,
    pub mutual_information_bits_per_trial: f64,
    pub corrected_mutual_information_bits_per_trial: f64,
    pub permutation_p_value: f64,
    pub probe_p50_us: f64,
    pub probe_p95_us: f64,
    pub probe_p99_us: f64,
}

#[cfg(feature = "bench")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub schema_version: u32,
    pub seed: u64,
    pub control: bool,
    pub requested_trials: u64,
    pub calibration_per_bit_and_gap: usize,
    pub wall_time_ms: f64,
    pub trials_per_hour: f64,
    pub bit_error_rate: f64,
    pub mutual_information_bits_per_trial: f64,
    pub corrected_mutual_information_bits_per_trial: f64,
    pub permutation_p_value: f64,
    pub raw_information_bits_observed: f64,
    pub corrected_information_bits_observed: f64,
    pub corrected_bits_per_hour: f64,
    pub successful_turns: u64,
    pub timed_out_turns: u64,
    pub failed_turns: u64,
    pub server: HealthResponse,
    pub gap_summaries: Vec<GapSummary>,
    pub records: Vec<TrialRecord>,
}
