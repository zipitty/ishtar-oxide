def sum_or_zero:
  if length == 0 then 0 else add end;

def weighted_average($value_key; $weight_key):
  (map(.[$weight_key]) | sum_or_zero) as $total_weight
  | if $total_weight == 0 then 0
    else (map(.[$value_key] * .[$weight_key]) | sum_or_zero) / $total_weight
    end;

def artifact_summary:
  {
    scheduler_versions: (map(.run_info.scheduler_version) | unique),
    wasm_sha256: (map(.run_info.wasm_sha256_hex) | unique),
    container_config_sha256: (map(.run_info.container_config_sha256_hex) | unique),
    tinfoil_attestation_sha256: (map(.run_info.tinfoil_attestation_sha256_hex) | unique)
  }
  | . + {
      consistent:
        ((.scheduler_versions | length) == 1
         and (.wasm_sha256 | length) == 1
         and (.container_config_sha256 | length) == 1
         and (.tinfoil_attestation_sha256 | length) == 1)
    };

def offset_summary:
  group_by(.target_overlap_us)
  | map(
      . as $offset
      | ($offset | map(.usable_trials) | sum_or_zero) as $usable
      | {
          target_overlap_us: $offset[0].target_overlap_us,
          runs: ($offset | length),
          usable_trials: $usable,
          weighted_bit_error_rate:
            ($offset | weighted_average("bit_error_rate"; "usable_trials")),
          raw_information_bits_observed:
            ($offset
             | map(.mutual_information_bits_per_trial * .usable_trials)
             | sum_or_zero),
          corrected_information_bits_observed:
            ($offset
             | map(.corrected_mutual_information_bits_per_trial * .usable_trials)
             | sum_or_zero),
          detected_runs:
            ($offset | map(select(.permutation_p_value <= 0.05)) | length),
          minimum_run_p_value:
            ($offset | map(.permutation_p_value) | min),
          run_p_values:
            ($offset | map(.permutation_p_value))
        }
    );

def group_summary:
  . as $runs
  | ($runs | map(.usable_trials) | sum_or_zero) as $usable
  | ($runs | map(.utilization.wall_time_ms) | sum_or_zero / 3600000) as $hours
  | ($runs | map(.raw_information_bits_observed) | sum_or_zero) as $raw_information
  | ($runs | map(.corrected_information_bits_observed) | sum_or_zero) as $corrected_information
  | {
      profile_id: $runs[0].profile_id,
      mode: (if $runs[0].control then "control" else "signal" end),
      runs: ($runs | length),
      seeds: ($runs | map(.seed) | sort),
      total_trials: ($runs | map(.total_trials) | sum_or_zero),
      calibration_trials: ($runs | map(.calibration_trials) | sum_or_zero),
      usable_trials: $usable,
      completed_wall_hours: $hours,
      weighted_bit_error_rate:
        ($runs | weighted_average("bit_error_rate"; "usable_trials")),
      raw_information_bits_observed: $raw_information,
      corrected_information_bits_observed: $corrected_information,
      descriptive_raw_bits_per_hour:
        (if $hours == 0 then 0 else $raw_information / $hours end),
      descriptive_corrected_bits_per_hour:
        (if $hours == 0 then 0 else $corrected_information / $hours end),
      detected_runs: ($runs | map(select(.statistically_detected)) | length),
      minimum_run_p_value: ($runs | map(.permutation_p_value) | min),
      run_p_values: ($runs | map(.permutation_p_value)),
      artifacts: ($runs | artifact_summary),
      offsets:
        ($runs
         | map(.offset_summaries[])
         | offset_summary)
    };

{
  generated_at: (now | todateiso8601),
  report_count: length,
  note:
    "Accumulated rates and information are descriptive sums. Run p-values are retained but are not averaged or presented as a combined significance test.",
  groups:
    (sort_by(.profile_id, .control)
     | group_by(.profile_id, .control)
     | map(group_summary))
}
