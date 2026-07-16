//! Stable, deliberately small JSON protocol for the synthetic leakage lab.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{error::Error, fmt};

pub const DEFAULT_IDLE_EXPIRY_MS: u64 = 300_000;
pub const MAX_SESSION_ID_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError(pub String);

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for ProtocolError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CreateSessionRequest {
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CreateSessionResponse {
    pub session_id: String,
    pub bearer_token: String,
    pub expires_after_idle_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TurnRequest {
    pub role: WorkerRole,
    pub bit: Option<u8>,
    pub trial_id: u64,
    pub profile_id: String,
    pub payload_len: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TurnResponse {
    pub session_id: String,
    pub trial_id: u64,
    pub fixed_body: String,
    pub server_trace_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerRole {
    Sender,
    Probe,
    Background,
    Control,
}

impl WorkerRole {
    pub fn abi_value(self) -> i32 {
        match self {
            Self::Sender => 0,
            Self::Probe => 1,
            Self::Background => 2,
            Self::Control => 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExperimentProfile {
    pub id: String,
    pub description: String,
    pub attacker_favorable: bool,
    pub max_parallel_turns: usize,
    pub trials: u64,
    pub synthetic_bits: u64,
    pub background_sessions: usize,
    pub sender_sessions: usize,
    pub probe_sessions: usize,
    pub turn_fuel: u64,
    pub sender_hot_iterations: u64,
    pub sender_cold_iterations: u64,
    pub probe_iterations: u64,
    pub wasm_memory_pages: u32,
    pub fixed_response_bytes: usize,
    pub dispatch_jitter_min_us: u64,
    pub dispatch_jitter_max_us: u64,
    pub release_epoch_us: u64,
    pub target_overlap_us: Vec<u64>,
    pub session_idle_expiry_ms: u64,
    pub request_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExperimentStartRequest {
    pub profile_id: String,
    pub seed: Option<u64>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExperimentRunInfo {
    pub run_id: String,
    pub profile: ExperimentProfile,
    pub started_at_unix_ms: u64,
    pub scheduler_version: String,
    pub wasm_sha256_hex: String,
    pub container_config_sha256_hex: Option<String>,
    pub tinfoil_attestation_sha256_hex: Option<String>,
    pub runtime_profile: RuntimeProfile,
    pub completed: bool,
    pub records_dropped: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RuntimeProfile {
    pub wasm_engine: String,
    pub interpreter_only: bool,
    pub wasi_enabled: bool,
    pub imports_enabled: bool,
    pub threads_enabled: bool,
    pub shared_memory_enabled: bool,
    pub clocks_available_to_guest: bool,
    pub runner_process_per_turn: bool,
    pub linux_seccomp_requested: bool,
    pub linux_seccomp_applied: bool,
    pub linux_landlock_requested: bool,
    pub linux_landlock_applied: bool,
    pub no_new_privs_applied: bool,
    pub rlimits_applied: bool,
    pub sandbox_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ServerTimingRecord {
    pub trace_id: u64,
    pub trial_id: u64,
    pub role: WorkerRole,
    pub queued_at_ns: u128,
    pub dispatch_at_ns: u128,
    pub runner_start_at_ns: u128,
    pub wasm_enter_at_ns: u128,
    pub wasm_exit_at_ns: u128,
    pub response_release_at_ns: u128,
    pub fuel_consumed: Option<u64>,
    pub timed_out: bool,
    pub trap: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ClientTimingRecord {
    pub trace_id: u64,
    pub trial_id: u64,
    pub role: WorkerRole,
    pub sent_at_ns: u128,
    pub first_byte_at_ns: Option<u128>,
    pub completed_at_ns: u128,
    pub status: u16,
    pub decoded_bit: Option<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct OverlapSummary {
    pub samples: u64,
    pub min_us: f64,
    pub p50_us: f64,
    pub p95_us: f64,
    pub max_us: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LatencySummary {
    pub samples: u64,
    pub min_us: f64,
    pub p50_us: f64,
    pub p95_us: f64,
    pub p99_us: f64,
    pub max_us: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct UtilizationSummary {
    pub completed_turns: u64,
    pub trapped_turns: u64,
    pub timed_out_turns: u64,
    pub total_wasm_time_ms: f64,
    pub wall_time_ms: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct OffsetLeakageSummary {
    pub target_overlap_us: u64,
    pub calibration_zero_mean_us: f64,
    pub calibration_one_mean_us: f64,
    pub calibration_threshold_us: f64,
    pub high_latency_is_one: bool,
    pub usable_trials: u64,
    pub bit_error_rate: f64,
    pub mutual_information_bits_per_trial: f64,
    pub corrected_mutual_information_bits_per_trial: f64,
    pub permutation_p_value: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LeakageReport {
    pub run_id: String,
    pub profile_id: String,
    pub run_info: ExperimentRunInfo,
    pub synthetic_bits: Vec<u8>,
    pub target_overlap_us_by_trial: Vec<u64>,
    pub total_trials: u64,
    pub calibration_trials: u64,
    pub usable_trials: u64,
    pub probe_aggregation: String,
    pub bit_error_rate: f64,
    pub false_positive_rate: f64,
    pub false_negative_rate: f64,
    pub false_discovery_rate: f64,
    /// Plug-in estimate. Positively biased for short, near-chance runs.
    pub mutual_information_bits_per_trial: f64,
    /// Raw MI less the mean MI seen after permuting labels, floored at zero.
    pub corrected_mutual_information_bits_per_trial: f64,
    pub raw_reliable_bits_per_hour: f64,
    pub corrected_reliable_bits_per_hour: f64,
    /// Corrected rate when the permutation test detects a signal; zero otherwise.
    pub reliable_bits_per_hour: f64,
    pub raw_information_bits_observed: f64,
    pub corrected_information_bits_observed: f64,
    pub scored_trials_per_hour: f64,
    pub permutation_p_value: f64,
    pub statistically_detected: bool,
    pub permutation_null_mean: f64,
    pub permutation_null_p95: f64,
    pub confidence_low: f64,
    pub confidence_high: f64,
    pub offset_summaries: Vec<OffsetLeakageSummary>,
    pub overlap_summary: OverlapSummary,
    pub latency_histogram: LatencySummary,
    pub utilization: UtilizationSummary,
    pub server_records: Vec<ServerTimingRecord>,
    pub client_records: Vec<ClientTimingRecord>,
}

pub fn validate_session_id(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > MAX_SESSION_ID_BYTES {
        return Err(ProtocolError(
            "session_id must contain 1..=128 ASCII bytes".into(),
        ));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
    {
        return Err(ProtocolError(
            "session_id contains a forbidden character".into(),
        ));
    }
    Ok(())
}

pub fn validate_profile(profile: &ExperimentProfile) -> Result<(), ProtocolError> {
    if profile.id.is_empty()
        || profile.id.len() > 64
        || !profile
            .id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(ProtocolError(
            "profile id must match [a-z0-9-]{1,64}".into(),
        ));
    }
    if !(1..=256).contains(&profile.max_parallel_turns) {
        return Err(ProtocolError("max_parallel_turns must be 1..=256".into()));
    }
    if !(64..=4096).contains(&profile.fixed_response_bytes) {
        return Err(ProtocolError(
            "fixed_response_bytes must be 64..=4096".into(),
        ));
    }
    if profile.turn_fuel == 0 || profile.request_timeout_ms == 0 || profile.wasm_memory_pages == 0 {
        return Err(ProtocolError(
            "fuel, timeout, and memory limits must be nonzero".into(),
        ));
    }
    if profile.dispatch_jitter_min_us > profile.dispatch_jitter_max_us {
        return Err(ProtocolError("dispatch jitter bounds are reversed".into()));
    }
    if profile.target_overlap_us.is_empty()
        || !profile.target_overlap_us.contains(&0)
        || !profile
            .target_overlap_us
            .iter()
            .any(|&v| v > 0 && v < 1_000)
        || !profile.target_overlap_us.iter().any(|&v| v >= 1_000)
    {
        return Err(ProtocolError(
            "target_overlap_us must contain zero, sub-ms, and long-overlap values".into(),
        ));
    }
    if !profile.attacker_favorable {
        if profile.release_epoch_us == 0 {
            return Err(ProtocolError(
                "realistic profiles require response quantization".into(),
            ));
        }
        if profile.session_idle_expiry_ms > DEFAULT_IDLE_EXPIRY_MS {
            return Err(ProtocolError(
                "realistic profiles may not exceed five-minute idle expiry".into(),
            ));
        }
    }
    Ok(())
}

/// Returns exactly `len` printable ASCII bytes. It carries no worker result.
pub fn fixed_response(trace_id: u64, len: usize) -> String {
    let seed = format!("trace-{trace_id:016x}-synthetic-only-");
    seed.bytes().cycle().take(len).map(char::from).collect()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn estimate_reliable_bits_per_hour(mi_bits_per_trial: f64, trials_per_hour: f64) -> f64 {
    if !mi_bits_per_trial.is_finite() || !trials_per_hour.is_finite() {
        return 0.0;
    }
    mi_bits_per_trial.max(0.0) * trials_per_hour.max(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> ExperimentProfile {
        ExperimentProfile {
            id: "realistic".into(),
            description: "test".into(),
            attacker_favorable: false,
            max_parallel_turns: 4,
            trials: 10,
            synthetic_bits: 10,
            background_sessions: 1,
            sender_sessions: 1,
            probe_sessions: 1,
            turn_fuel: 100,
            sender_hot_iterations: 10,
            sender_cold_iterations: 1,
            probe_iterations: 5,
            wasm_memory_pages: 8,
            fixed_response_bytes: 128,
            dispatch_jitter_min_us: 0,
            dispatch_jitter_max_us: 100,
            release_epoch_us: 1_000,
            target_overlap_us: vec![0, 250, 5_000],
            session_idle_expiry_ms: DEFAULT_IDLE_EXPIRY_MS,
            request_timeout_ms: 1_000,
        }
    }

    #[test]
    fn session_id_rules_are_strict() {
        for valid in ["a", "session_1", "a.b:c-d"] {
            assert!(validate_session_id(valid).is_ok());
        }
        for invalid in ["", "white space", "slash/no", "snowman-☃"] {
            assert!(validate_session_id(invalid).is_err());
        }
        assert!(validate_session_id(&"a".repeat(129)).is_err());
    }

    #[test]
    fn validates_realistic_profile_constraints() {
        assert!(validate_profile(&profile()).is_ok());
        let mut p = profile();
        p.release_epoch_us = 0;
        assert!(validate_profile(&p).is_err());
        p.attacker_favorable = true;
        assert!(validate_profile(&p).is_ok());
    }

    #[test]
    fn fixed_body_and_hash_are_stable() {
        assert_eq!(fixed_response(7, 100).len(), 100);
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn rate_helper_handles_bad_values() {
        assert_eq!(estimate_reliable_bits_per_hour(0.5, 120.0), 60.0);
        assert_eq!(estimate_reliable_bits_per_hour(f64::NAN, 120.0), 0.0);
        assert_eq!(estimate_reliable_bits_per_hour(-1.0, 120.0), 0.0);
    }
}
