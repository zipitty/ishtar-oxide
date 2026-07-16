use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ishtar_protocol::{
    ClientTimingRecord, CreateSessionRequest, CreateSessionResponse, ExperimentProfile,
    ExperimentRunInfo, ExperimentStartRequest, LatencySummary, LeakageReport, OffsetLeakageSummary,
    OverlapSummary, ServerTimingRecord, TurnRequest, TurnResponse, UtilizationSummary, WorkerRole,
    estimate_reliable_bits_per_hour,
};
use reqwest::{Client, StatusCode};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

const CALIBRATION_SAMPLES_PER_BIT_AND_OFFSET: usize = 5;

#[derive(Parser)]
#[command(
    name = "ishtar-bench-client",
    about = "External-clock synthetic leakage benchmark"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Profiles {
        #[arg(long)]
        base_url: String,
    },
    Run(RunArgs),
}

#[derive(clap::Args, Clone)]
struct RunArgs {
    #[arg(long)]
    base_url: String,
    #[arg(long)]
    profile: String,
    #[arg(long, env = "LAB_ADMIN_TOKEN")]
    admin_token: String,
    #[arg(long)]
    trials: Option<u64>,
    #[arg(long, default_value_t = 1)]
    seed: u64,
    #[arg(long)]
    control: bool,
    #[arg(long, default_value = "reports/report.json")]
    output: PathBuf,
}

#[derive(Clone)]
struct ClientSession {
    id: String,
    token: String,
}

struct CalibrationModel {
    by_offset: HashMap<u64, OffsetCalibration>,
    scoring_starts_at_trial: u64,
}

struct OffsetCalibration {
    zero_mean_us: f64,
    one_mean_us: f64,
    threshold_us: f64,
    high_latency_is_one: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TrialPlan {
    bit: u8,
    target_overlap_us: u64,
}

#[derive(Clone, Copy)]
struct ScoredPair {
    expected: u8,
    decoded: u8,
    target_overlap_us: u64,
}

struct TrialResult {
    records: Vec<ClientTimingRecord>,
    expected_bit: u8,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Profiles { base_url } => {
            let profiles: Vec<ExperimentProfile> = Client::new()
                .get(endpoint(&base_url, "/v1/profiles"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("{}", serde_json::to_string_pretty(&profiles)?);
            Ok(())
        }
        Command::Run(args) => run_matrix(args).await,
    }
}

async fn run_matrix(args: RunArgs) -> Result<()> {
    if args.admin_token.len() < 16 {
        bail!("admin token must contain at least 16 bytes");
    }
    let client = Client::builder().build()?;
    let profiles: Vec<ExperimentProfile> = client
        .get(endpoint(&args.base_url, "/v1/profiles"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let profile = profiles
        .into_iter()
        .find(|p| p.id == args.profile)
        .context("server did not advertise requested profile")?;
    let trial_count = args
        .trials
        .unwrap_or(profile.trials)
        .min(profile.synthetic_bits);
    let minimum_trials = profile.target_overlap_us.len() as u64
        * (CALIBRATION_SAMPLES_PER_BIT_AND_OFFSET * 2) as u64
        + 8;
    if trial_count < minimum_trials {
        bail!(
            "at least {minimum_trials} trials are required to calibrate both bits at every overlap offset and retain scoring trials"
        );
    }
    let trial_plan = build_trial_plan(args.seed, trial_count, &profile.target_overlap_us);

    let sender = create_sessions(&client, &args.base_url, profile.sender_sessions.max(1))
        .await?
        .into_iter()
        .next()
        .context("sender session")?;
    let probes = create_sessions(&client, &args.base_url, profile.probe_sessions.max(1)).await?;
    let backgrounds = create_sessions(&client, &args.base_url, profile.background_sessions).await?;
    let mut run: ExperimentRunInfo = client
        .post(endpoint(&args.base_url, "/v1/experiments/start"))
        .header("x-lab-admin-token", &args.admin_token)
        .json(&ExperimentStartRequest {
            profile_id: profile.id.clone(),
            seed: Some(args.seed),
            notes: Some(
                if args.control {
                    "mandatory no-signal control"
                } else {
                    "synthetic signal run"
                }
                .into(),
            ),
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let clock = Arc::new(Instant::now());
    let mut client_records = Vec::new();
    let mut expected_bits = Vec::with_capacity(trial_plan.len());
    for (trial_id, planned) in trial_plan.iter().copied().enumerate() {
        let result = run_trial_group(
            &client,
            &args.base_url,
            &profile,
            &sender,
            &probes,
            &backgrounds,
            trial_id as u64,
            planned,
            args.control,
            clock.clone(),
        )
        .await?;
        client_records.extend(result.records);
        expected_bits.push(result.expected_bit);
    }

    run = client
        .post(endpoint(
            &args.base_url,
            &format!("/v1/experiments/{}/stop", run.run_id),
        ))
        .header("x-lab-admin-token", &args.admin_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let server_records: Vec<ServerTimingRecord> = client
        .get(endpoint(
            &args.base_url,
            &format!("/v1/experiments/{}/records", run.run_id),
        ))
        .header("x-lab-admin-token", &args.admin_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let calibration = calibrate(&client_records, &trial_plan)?;
    for trial_id in calibration.scoring_starts_at_trial..trial_count {
        let probe_indexes: Vec<_> = client_records
            .iter()
            .enumerate()
            .filter(|(_, record)| record.role == WorkerRole::Probe && record.trial_id == trial_id)
            .map(|(index, _)| index)
            .collect();
        let decoded = decode_bit(
            probe_indexes.iter().map(|&index| &client_records[index]),
            trial_plan[trial_id as usize].target_overlap_us,
            &calibration,
        );
        for index in probe_indexes {
            client_records[index].decoded_bit = decoded;
        }
    }
    let report = compute_report(
        &run,
        &server_records,
        &client_records,
        &expected_bits,
        &trial_plan,
        &calibration,
        calibration.scoring_starts_at_trial,
        args.seed,
    );
    write_report(&report, &args.output)?;
    println!(
        "wrote {}: usable={}/{} ber={:.4} raw_mi={:.6} corrected_mi={:.6} bits/trial p={:.4} corrected_rate={:.3} bits/hour",
        args.output.display(),
        report.usable_trials,
        report.total_trials,
        report.bit_error_rate,
        report.mutual_information_bits_per_trial,
        report.corrected_mutual_information_bits_per_trial,
        report.permutation_p_value,
        report.reliable_bits_per_hour,
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_trial_group(
    client: &Client,
    base: &str,
    profile: &ExperimentProfile,
    sender: &ClientSession,
    probes: &[ClientSession],
    backgrounds: &[ClientSession],
    trial_id: u64,
    planned: TrialPlan,
    control: bool,
    clock: Arc<Instant>,
) -> Result<TrialResult> {
    let offset = planned.target_overlap_us;
    let sender_role = if control {
        WorkerRole::Control
    } else {
        WorkerRole::Sender
    };
    let sender_bit = if control { None } else { Some(planned.bit) };
    let sender_future = send_turn(
        client.clone(),
        base.to_owned(),
        profile.id.clone(),
        sender.clone(),
        sender_role,
        sender_bit,
        trial_id,
        clock.clone(),
        0,
    );
    let mut tasks = tokio::task::JoinSet::new();
    for session in probes {
        tasks.spawn(send_turn(
            client.clone(),
            base.to_owned(),
            profile.id.clone(),
            session.clone(),
            WorkerRole::Probe,
            None,
            trial_id,
            clock.clone(),
            offset,
        ));
    }
    for (index, session) in backgrounds.iter().enumerate() {
        tasks.spawn(send_turn(
            client.clone(),
            base.to_owned(),
            profile.id.clone(),
            session.clone(),
            WorkerRole::Background,
            None,
            trial_id,
            clock.clone(),
            (index as u64 % 4) * 100,
        ));
    }
    let sender_record = sender_future.await?;
    let mut records = vec![sender_record];
    while let Some(joined) = tasks.join_next().await {
        records.push(joined.context("traffic task panicked")??);
    }
    Ok(TrialResult {
        records,
        expected_bit: planned.bit,
    })
}

#[allow(clippy::too_many_arguments)]
async fn send_turn(
    client: Client,
    base: String,
    profile_id: String,
    session: ClientSession,
    role: WorkerRole,
    bit: Option<u8>,
    trial_id: u64,
    clock: Arc<Instant>,
    delay_us: u64,
) -> Result<ClientTimingRecord> {
    if delay_us != 0 {
        tokio::time::sleep(std::time::Duration::from_micros(delay_us)).await;
    }
    let sent_at_ns = clock.elapsed().as_nanos();
    let response = client
        .post(endpoint(
            &base,
            &format!("/v1/sessions/{}/turn", session.id),
        ))
        .bearer_auth(&session.token)
        .json(&TurnRequest {
            role,
            bit,
            trial_id,
            profile_id,
            payload_len: None,
        })
        .send()
        .await
        .context("send turn")?;
    let first_byte_at_ns = Some(clock.elapsed().as_nanos());
    let status = response.status();
    let bytes = response.bytes().await.context("read turn response")?;
    let completed_at_ns = clock.elapsed().as_nanos();
    let trace_id = if status.is_success() {
        serde_json::from_slice::<TurnResponse>(&bytes)
            .context("decode turn response")?
            .server_trace_id
    } else {
        0
    };
    Ok(ClientTimingRecord {
        trace_id,
        trial_id,
        role,
        sent_at_ns,
        first_byte_at_ns,
        completed_at_ns,
        status: status.as_u16(),
        decoded_bit: None,
    })
}

async fn create_sessions(client: &Client, base: &str, count: usize) -> Result<Vec<ClientSession>> {
    let mut sessions = Vec::with_capacity(count);
    for _ in 0..count {
        let response: CreateSessionResponse = client
            .post(endpoint(base, "/v1/sessions"))
            .json(&CreateSessionRequest { session_id: None })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        sessions.push(ClientSession {
            id: response.session_id,
            token: response.bearer_token,
        });
    }
    Ok(sessions)
}

fn calibrate(records: &[ClientTimingRecord], plan: &[TrialPlan]) -> Result<CalibrationModel> {
    let calibration_trials = plan
        .iter()
        .map(|p| p.target_overlap_us)
        .collect::<std::collections::HashSet<_>>()
        .len()
        * CALIBRATION_SAMPLES_PER_BIT_AND_OFFSET
        * 2;
    let mut samples: HashMap<(u64, u8), Vec<f64>> = HashMap::new();
    for (trial_id, &planned) in plan.iter().take(calibration_trials).enumerate() {
        if let Some(latency) = aggregate_probe_latency(records, trial_id as u64) {
            samples
                .entry((planned.target_overlap_us, planned.bit))
                .or_default()
                .push(latency);
        }
    }
    let mut by_offset = HashMap::new();
    for offset in plan[..calibration_trials]
        .iter()
        .map(|p| p.target_overlap_us)
    {
        let zero = samples
            .get(&(offset, 0))
            .context("missing bit-zero calibration")?;
        let one = samples
            .get(&(offset, 1))
            .context("missing bit-one calibration")?;
        let zero_mean = mean(zero);
        let one_mean = mean(one);
        by_offset.insert(
            offset,
            OffsetCalibration {
                zero_mean_us: zero_mean,
                one_mean_us: one_mean,
                threshold_us: (zero_mean + one_mean) / 2.0,
                high_latency_is_one: one_mean >= zero_mean,
            },
        );
    }
    Ok(CalibrationModel {
        by_offset,
        scoring_starts_at_trial: calibration_trials as u64,
    })
}

fn aggregate_probe_latency(records: &[ClientTimingRecord], trial_id: u64) -> Option<f64> {
    let latencies: Vec<_> = records
        .iter()
        .filter(|r| {
            r.trial_id == trial_id
                && r.role == WorkerRole::Probe
                && r.status == StatusCode::OK.as_u16()
        })
        .map(|r| duration_us(r.sent_at_ns, r.completed_at_ns))
        .collect();
    (!latencies.is_empty()).then(|| mean(&latencies))
}

fn decode_bit<'a>(
    records: impl Iterator<Item = &'a ClientTimingRecord>,
    target_overlap_us: u64,
    calibration: &CalibrationModel,
) -> Option<u8> {
    let latencies: Vec<_> = records
        .filter(|r| r.role == WorkerRole::Probe && r.status == StatusCode::OK.as_u16())
        .map(|r| duration_us(r.sent_at_ns, r.completed_at_ns))
        .collect();
    let model = calibration.by_offset.get(&target_overlap_us)?;
    if latencies.is_empty() {
        return None;
    }
    let high = mean(&latencies) >= model.threshold_us;
    Some(u8::from(if model.high_latency_is_one {
        high
    } else {
        !high
    }))
}

#[allow(clippy::too_many_arguments)]
fn compute_report(
    run_info: &ExperimentRunInfo,
    server_records: &[ServerTimingRecord],
    client_records: &[ClientTimingRecord],
    expected_bits: &[u8],
    trial_plan: &[TrialPlan],
    calibration: &CalibrationModel,
    calibration_trials: u64,
    seed: u64,
) -> LeakageReport {
    let mut decoded_by_trial = HashMap::new();
    for r in client_records
        .iter()
        .filter(|r| r.role == WorkerRole::Probe)
    {
        if let Some(bit) = r.decoded_bit {
            decoded_by_trial.entry(r.trial_id).or_insert(bit);
        }
    }
    let mut pairs: Vec<ScoredPair> = Vec::new();
    for (trial, &expected) in expected_bits.iter().enumerate() {
        let sender_succeeded = client_records.iter().any(|record| {
            record.trial_id == trial as u64
                && matches!(record.role, WorkerRole::Sender | WorkerRole::Control)
                && record.status == StatusCode::OK.as_u16()
        });
        if sender_succeeded && let Some(&decoded) = decoded_by_trial.get(&(trial as u64)) {
            pairs.push(ScoredPair {
                expected,
                decoded,
                target_overlap_us: trial_plan[trial].target_overlap_us,
            });
        }
    }
    let errors = pairs.iter().filter(|p| p.expected != p.decoded).count();
    let zero = pairs.iter().filter(|p| p.expected == 0).count();
    let one = pairs.iter().filter(|p| p.expected == 1).count();
    let fp = pairs
        .iter()
        .filter(|p| p.expected == 0 && p.decoded == 1)
        .count();
    let fn_ = pairs
        .iter()
        .filter(|p| p.expected == 1 && p.decoded == 0)
        .count();
    let decoded_positive = pairs.iter().filter(|p| p.decoded == 1).count();
    let ber = ratio(errors, pairs.len());
    let binary_pairs: Vec<_> = pairs.iter().map(|p| (p.expected, p.decoded)).collect();
    let mi = mutual_information(&binary_pairs);
    let (raw_confidence_low, raw_confidence_high) = bootstrap_mi(&binary_pairs, seed);
    let permutation = permutation_test(&pairs, seed, 2_000);
    let corrected_mi = (mi - permutation.null_mean).max(0.0);
    let statistically_detected = permutation.p_value <= 0.05;
    let wall_ns = client_records
        .iter()
        .map(|r| r.completed_at_ns)
        .max()
        .unwrap_or(0)
        .saturating_sub(
            client_records
                .iter()
                .map(|r| r.sent_at_ns)
                .min()
                .unwrap_or(0),
        );
    let trials_per_hour = if wall_ns == 0 {
        0.0
    } else {
        pairs.len() as f64 * 3.6e12 / wall_ns as f64
    };
    let corrected_rate = estimate_reliable_bits_per_hour(corrected_mi, trials_per_hour);
    let offset_summaries = offset_summaries(&pairs, calibration, seed);
    LeakageReport {
        run_id: run_info.run_id.clone(),
        profile_id: run_info.profile.id.clone(),
        run_info: run_info.clone(),
        synthetic_bits: expected_bits.to_vec(),
        target_overlap_us_by_trial: trial_plan
            .iter()
            .map(|planned| planned.target_overlap_us)
            .collect(),
        total_trials: expected_bits.len() as u64,
        calibration_trials,
        usable_trials: pairs.len() as u64,
        probe_aggregation: "mean_latency_per_trial".into(),
        bit_error_rate: ber,
        false_positive_rate: ratio(fp, zero),
        false_negative_rate: ratio(fn_, one),
        false_discovery_rate: ratio(fp, decoded_positive),
        mutual_information_bits_per_trial: mi,
        corrected_mutual_information_bits_per_trial: corrected_mi,
        raw_reliable_bits_per_hour: estimate_reliable_bits_per_hour(mi, trials_per_hour),
        corrected_reliable_bits_per_hour: corrected_rate,
        reliable_bits_per_hour: if statistically_detected {
            corrected_rate
        } else {
            0.0
        },
        raw_information_bits_observed: mi * pairs.len() as f64,
        corrected_information_bits_observed: corrected_mi * pairs.len() as f64,
        scored_trials_per_hour: trials_per_hour,
        permutation_p_value: permutation.p_value,
        statistically_detected,
        permutation_null_mean: permutation.null_mean,
        permutation_null_p95: permutation.null_p95,
        confidence_low: (raw_confidence_low - permutation.null_mean).max(0.0),
        confidence_high: (raw_confidence_high - permutation.null_mean).max(0.0),
        offset_summaries,
        overlap_summary: overlap_summary(server_records),
        latency_histogram: latency_summary(client_records),
        utilization: utilization_summary(server_records),
        server_records: server_records.to_vec(),
        client_records: client_records.to_vec(),
    }
}

fn mutual_information(pairs: &[(u8, u8)]) -> f64 {
    if pairs.is_empty() {
        return 0.0;
    }
    let n = pairs.len() as f64;
    let mut joint = [[0.0f64; 2]; 2];
    for &(a, b) in pairs {
        if a <= 1 && b <= 1 {
            joint[a as usize][b as usize] += 1.0;
        }
    }
    let rows = [joint[0][0] + joint[0][1], joint[1][0] + joint[1][1]];
    let cols = [joint[0][0] + joint[1][0], joint[0][1] + joint[1][1]];
    let mut mi = 0.0;
    for a in 0..2 {
        for b in 0..2 {
            if joint[a][b] > 0.0 {
                mi += joint[a][b] / n * (joint[a][b] * n / (rows[a] * cols[b])).log2();
            }
        }
    }
    mi.max(0.0)
}

pub fn bootstrap_confidence(values: &[f64], seed: u64) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }
    let mut state = seed.max(1);
    let mut means = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let mut sum = 0.0;
        for _ in values {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            sum += values[state as usize % values.len()];
        }
        means.push(sum / values.len() as f64);
    }
    means.sort_by(f64::total_cmp);
    (means[24], means[974])
}

fn bootstrap_mi(pairs: &[(u8, u8)], seed: u64) -> (f64, f64) {
    if pairs.is_empty() {
        return (0.0, 0.0);
    }
    let mut state = seed.max(1);
    let mut estimates = Vec::with_capacity(1000);
    let mut sample = Vec::with_capacity(pairs.len());
    for _ in 0..1000 {
        sample.clear();
        for _ in pairs {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            sample.push(pairs[state as usize % pairs.len()]);
        }
        estimates.push(mutual_information(&sample));
    }
    estimates.sort_by(f64::total_cmp);
    (estimates[24], estimates[974])
}

struct PermutationResult {
    p_value: f64,
    null_mean: f64,
    null_p95: f64,
}

fn permutation_test(pairs: &[ScoredPair], seed: u64, iterations: usize) -> PermutationResult {
    if pairs.is_empty() || iterations == 0 {
        return PermutationResult {
            p_value: 1.0,
            null_mean: 0.0,
            null_p95: 0.0,
        };
    }
    let observed_pairs: Vec<_> = pairs.iter().map(|p| (p.expected, p.decoded)).collect();
    let observed = mutual_information(&observed_pairs);
    let mut offsets: Vec<_> = pairs.iter().map(|p| p.target_overlap_us).collect();
    offsets.sort_unstable();
    offsets.dedup();
    let groups: Vec<Vec<usize>> = offsets
        .iter()
        .map(|offset| {
            pairs
                .iter()
                .enumerate()
                .filter(|(_, p)| p.target_overlap_us == *offset)
                .map(|(index, _)| index)
                .collect()
        })
        .collect();
    let mut state = seed.max(1) ^ 0x7065_726d_7574_6521;
    let mut expected: Vec<_> = pairs.iter().map(|p| p.expected).collect();
    let mut estimates = Vec::with_capacity(iterations);
    let mut at_least_observed = 0usize;
    for _ in 0..iterations {
        for group in &groups {
            for i in (1..group.len()).rev() {
                let j = random_index(&mut state, i + 1);
                expected.swap(group[i], group[j]);
            }
        }
        let permuted: Vec<_> = pairs
            .iter()
            .enumerate()
            .map(|(index, p)| (expected[index], p.decoded))
            .collect();
        let estimate = mutual_information(&permuted);
        if estimate >= observed - f64::EPSILON {
            at_least_observed += 1;
        }
        estimates.push(estimate);
    }
    let null_mean = mean(&estimates);
    estimates.sort_by(f64::total_cmp);
    PermutationResult {
        p_value: (at_least_observed + 1) as f64 / (iterations + 1) as f64,
        null_mean,
        null_p95: percentile(&estimates, 0.95),
    }
}

fn offset_summaries(
    pairs: &[ScoredPair],
    calibration: &CalibrationModel,
    seed: u64,
) -> Vec<OffsetLeakageSummary> {
    let mut offsets: Vec<_> = pairs.iter().map(|p| p.target_overlap_us).collect();
    offsets.sort_unstable();
    offsets.dedup();
    offsets
        .into_iter()
        .map(|offset| {
            let selected: Vec<_> = pairs
                .iter()
                .copied()
                .filter(|p| p.target_overlap_us == offset)
                .collect();
            let binary: Vec<_> = selected.iter().map(|p| (p.expected, p.decoded)).collect();
            let mi = mutual_information(&binary);
            let permutation = permutation_test(&selected, seed ^ offset, 1_000);
            let model = &calibration.by_offset[&offset];
            OffsetLeakageSummary {
                target_overlap_us: offset,
                calibration_zero_mean_us: model.zero_mean_us,
                calibration_one_mean_us: model.one_mean_us,
                calibration_threshold_us: model.threshold_us,
                high_latency_is_one: model.high_latency_is_one,
                usable_trials: selected.len() as u64,
                bit_error_rate: ratio(
                    selected.iter().filter(|p| p.expected != p.decoded).count(),
                    selected.len(),
                ),
                mutual_information_bits_per_trial: mi,
                corrected_mutual_information_bits_per_trial: (mi - permutation.null_mean).max(0.0),
                permutation_p_value: permutation.p_value,
            }
        })
        .collect()
}

fn overlap_summary(records: &[ServerTimingRecord]) -> OverlapSummary {
    let mut values = Vec::new();
    for sender in records.iter().filter(|r| r.role == WorkerRole::Sender) {
        for probe in records
            .iter()
            .filter(|r| r.role == WorkerRole::Probe && r.trial_id == sender.trial_id)
        {
            let start = sender.wasm_enter_at_ns.max(probe.wasm_enter_at_ns);
            let end = sender.wasm_exit_at_ns.min(probe.wasm_exit_at_ns);
            values.push(end.saturating_sub(start) as f64 / 1000.0);
        }
    }
    values.sort_by(f64::total_cmp);
    OverlapSummary {
        samples: values.len() as u64,
        min_us: percentile(&values, 0.0),
        p50_us: percentile(&values, 0.5),
        p95_us: percentile(&values, 0.95),
        max_us: percentile(&values, 1.0),
    }
}

fn latency_summary(records: &[ClientTimingRecord]) -> LatencySummary {
    let mut values: Vec<_> = records
        .iter()
        .filter(|r| r.role == WorkerRole::Probe)
        .map(|r| duration_us(r.sent_at_ns, r.completed_at_ns))
        .collect();
    values.sort_by(f64::total_cmp);
    LatencySummary {
        samples: values.len() as u64,
        min_us: percentile(&values, 0.0),
        p50_us: percentile(&values, 0.5),
        p95_us: percentile(&values, 0.95),
        p99_us: percentile(&values, 0.99),
        max_us: percentile(&values, 1.0),
    }
}

fn utilization_summary(records: &[ServerTimingRecord]) -> UtilizationSummary {
    let min = records.iter().map(|r| r.queued_at_ns).min().unwrap_or(0);
    let max = records
        .iter()
        .map(|r| r.response_release_at_ns)
        .max()
        .unwrap_or(0);
    UtilizationSummary {
        completed_turns: records.len() as u64,
        trapped_turns: records.iter().filter(|r| r.trap.is_some()).count() as u64,
        timed_out_turns: records.iter().filter(|r| r.timed_out).count() as u64,
        total_wasm_time_ms: records
            .iter()
            .map(|r| r.wasm_exit_at_ns.saturating_sub(r.wasm_enter_at_ns) as f64 / 1e6)
            .sum(),
        wall_time_ms: max.saturating_sub(min) as f64 / 1e6,
    }
}

fn write_report(report: &LeakageReport, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec_pretty(report)?)
        .with_context(|| format!("write {}", path.display()))
}

fn build_trial_plan(seed: u64, trial_count: u64, offsets: &[u64]) -> Vec<TrialPlan> {
    let calibration_len = offsets.len() * CALIBRATION_SAMPLES_PER_BIT_AND_OFFSET * 2;
    let mut calibration = Vec::with_capacity(calibration_len);
    for &offset in offsets {
        for _ in 0..CALIBRATION_SAMPLES_PER_BIT_AND_OFFSET {
            for bit in [0, 1] {
                calibration.push(TrialPlan {
                    bit,
                    target_overlap_us: offset,
                });
            }
        }
    }
    let mut state = seed.max(1) ^ 0x6361_6c69_6272_6174;
    shuffle(&mut calibration, &mut state);

    let scoring_len = trial_count as usize - calibration_len;
    let combinations: Vec<_> = offsets
        .iter()
        .flat_map(|&offset| {
            [0, 1].map(move |bit| TrialPlan {
                bit,
                target_overlap_us: offset,
            })
        })
        .collect();
    let mut scoring = Vec::with_capacity(scoring_len);
    while scoring.len() < scoring_len {
        let mut block = combinations.clone();
        shuffle(&mut block, &mut state);
        scoring.extend(block.into_iter().take(scoring_len - scoring.len()));
    }
    calibration.extend(scoring);
    calibration
}

fn shuffle<T>(values: &mut [T], state: &mut u64) {
    for i in (1..values.len()).rev() {
        let j = random_index(state, i + 1);
        values.swap(i, j);
    }
}

fn random_index(state: &mut u64, upper: usize) -> usize {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state as usize % upper
}
fn endpoint(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}
fn duration_us(start: u128, end: u128) -> f64 {
    end.saturating_sub(start) as f64 / 1000.0
}
fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}
fn ratio(n: usize, d: usize) -> f64 {
    if d == 0 { 0.0 } else { n as f64 / d as f64 }
}
fn percentile(sorted: &[f64], quantile: f64) -> f64 {
    if sorted.is_empty() {
        0.0
    } else {
        sorted[((sorted.len() - 1) as f64 * quantile).round() as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn information_math_covers_perfect_chance_and_inverted() {
        assert!((mutual_information(&[(0, 0), (1, 1), (0, 0), (1, 1)]) - 1.0).abs() < 1e-9);
        assert!((mutual_information(&[(0, 1), (1, 0), (0, 1), (1, 0)]) - 1.0).abs() < 1e-9);
        assert!(mutual_information(&[(0, 0), (0, 1), (1, 0), (1, 1)]).abs() < 1e-9);
        assert_eq!(mutual_information(&[]), 0.0);
    }

    #[test]
    fn bootstrap_is_deterministic_and_bounded() {
        let a = bootstrap_confidence(&[0.0, 1.0, 1.0, 1.0], 7);
        let b = bootstrap_confidence(&[0.0, 1.0, 1.0, 1.0], 7);
        assert_eq!(a, b);
        assert!(a.0 <= 0.75 && a.1 >= 0.75);
    }

    #[test]
    fn trial_plan_is_repeatable_and_balanced() {
        let offsets = [0, 250, 5_000];
        let plan = build_trial_plan(9, 60, &offsets);
        assert_eq!(plan, build_trial_plan(9, 60, &offsets));
        for offset in offsets {
            let zero = plan
                .iter()
                .filter(|p| p.target_overlap_us == offset && p.bit == 0)
                .count();
            let one = plan
                .iter()
                .filter(|p| p.target_overlap_us == offset && p.bit == 1)
                .count();
            assert!(zero.abs_diff(one) <= 1);
        }
    }

    #[test]
    fn permutation_test_rejects_perfect_signal_but_not_balanced_chance() {
        let perfect: Vec<_> = (0..40)
            .map(|i| ScoredPair {
                expected: (i % 2) as u8,
                decoded: (i % 2) as u8,
                target_overlap_us: 0,
            })
            .collect();
        assert!(permutation_test(&perfect, 7, 1_000).p_value < 0.01);

        let chance = [
            ScoredPair {
                expected: 0,
                decoded: 0,
                target_overlap_us: 0,
            },
            ScoredPair {
                expected: 0,
                decoded: 1,
                target_overlap_us: 0,
            },
            ScoredPair {
                expected: 1,
                decoded: 0,
                target_overlap_us: 0,
            },
            ScoredPair {
                expected: 1,
                decoded: 1,
                target_overlap_us: 0,
            },
        ];
        assert!(permutation_test(&chance, 7, 1_000).p_value > 0.5);
    }
}
