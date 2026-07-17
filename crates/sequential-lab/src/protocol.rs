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
    pub stream_wasm_sha256: String,
    pub stream_state_bytes: usize,
    pub max_chunk_bytes: usize,
    pub max_pending: usize,
    pub successful_turns: u64,
    pub timed_out_turns: u64,
    pub failed_turns: u64,
    pub throttled_turns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamChunkRequest {
    pub session_slot: u16,
    pub sequence: u64,
    pub chunk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamResetRequest {
    pub session_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamChunkResponse {
    pub outcome: String,
    pub session_slot: u16,
    pub sequence: u64,
    pub accumulated_chunks: u64,
    pub accumulated_bytes: usize,
    pub queue_wait_us: u64,
    pub execution_us: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamStateResponse {
    pub session_slot: u16,
    pub accumulated_chunks: u64,
    pub accumulated_bytes: usize,
    pub sha256: String,
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

#[cfg(feature = "bench")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamChunkRecord {
    pub session_slot: u16,
    pub sequence: u64,
    pub scheduled_offset_us: u64,
    pub request_offset_us: u64,
    pub latency_us: u64,
    pub outcome: String,
    pub queue_wait_us: Option<u64>,
    pub execution_us: Option<u64>,
}

#[cfg(feature = "bench")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamScenarioReport {
    pub session_count: usize,
    pub target_chunks_per_second: f64,
    pub duration_ms: u64,
    pub offered_chunks: u64,
    pub attempted_chunks: u64,
    pub completed_chunks: u64,
    pub throttled_chunks: u64,
    pub server_throttled_chunks: u64,
    pub client_backpressured_chunks: u64,
    pub failed_chunks: u64,
    pub min_completed_per_session: u64,
    pub max_completed_per_session: u64,
    pub achieved_chunks_per_second: f64,
    pub completion_ratio: f64,
    pub latency_p50_us: u64,
    pub latency_p95_us: u64,
    pub latency_p99_us: u64,
    pub queue_wait_p50_us: u64,
    pub queue_wait_p95_us: u64,
    pub queue_wait_p99_us: u64,
    pub execution_p50_us: u64,
    pub execution_p95_us: u64,
    pub execution_p99_us: u64,
    pub verified_sessions: usize,
    pub state_mismatches: usize,
    pub records: Vec<StreamChunkRecord>,
}

#[cfg(feature = "bench")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamBenchmarkReport {
    pub schema_version: u32,
    pub chunk_bytes: usize,
    pub duration_secs: u64,
    pub lorem_sha256: String,
    pub server: HealthResponse,
    pub scenarios: Vec<StreamScenarioReport>,
}
