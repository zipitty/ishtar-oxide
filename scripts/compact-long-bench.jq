{
  run_id,
  profile_id,
  seed,
  control,
  total_trials,
  calibration_trials,
  usable_trials,
  bit_error_rate,
  raw_information_bits_observed,
  corrected_information_bits_observed,
  permutation_p_value,
  statistically_detected,
  offset_summaries,
  utilization: {
    wall_time_ms: .utilization.wall_time_ms
  },
  run_info: {
    scheduler_version: .run_info.scheduler_version,
    wasm_sha256_hex: .run_info.wasm_sha256_hex,
    container_config_sha256_hex: .run_info.container_config_sha256_hex,
    tinfoil_attestation_sha256_hex: .run_info.tinfoil_attestation_sha256_hex
  }
}
