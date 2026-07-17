mod protocol;
mod sandbox;
mod wasm;

use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::{Parser, Subcommand};
#[cfg(feature = "bench")]
use protocol::{BenchmarkReport, GapSummary, TrialRecord};
use protocol::{HealthResponse, NORMALIZED_BODY, Role, TurnRequest};
#[cfg(feature = "bench")]
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::{
    env,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
#[cfg(feature = "bench")]
use std::{path::PathBuf, time::Instant};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    sync::{Mutex, Semaphore},
};
use tower_http::limit::RequestBodyLimitLayer;
use zeroize::Zeroizing;

const MAX_REQUEST_BYTES: usize = 1024;
const MAX_PENDING: usize = 256;

#[derive(Parser)]
#[command(name = "ishtar-sequential-lab")]
struct Cli {
    #[command(subcommand)]
    command: CommandLine,
}

#[derive(Subcommand)]
enum CommandLine {
    /// Run the physically separate sequential leakage lab service.
    Serve(ServeArgs),
    #[cfg(feature = "bench")]
    /// Drive sender->gap->probe trials using an external clock.
    Bench(BenchArgs),
}

#[derive(clap::Args, Clone)]
struct ServeArgs {
    #[arg(long, default_value = "127.0.0.1:8081")]
    bind: String,
    #[arg(long, env = "LAB_ADMIN_TOKEN")]
    token: String,
    #[arg(long, default_value_t = 64)]
    session_slots: usize,
    #[arg(long, default_value_t = 65_536)]
    state_bytes: usize,
    #[arg(long, default_value_t = 131_072)]
    sender_hot_iterations: u32,
    #[arg(long, default_value_t = 1_024)]
    sender_cold_iterations: u32,
    #[arg(long, default_value_t = 65_536)]
    sender_control_iterations: u32,
    #[arg(long, default_value_t = 131_072)]
    probe_iterations: u32,
    #[arg(long, default_value_t = 100_000)]
    execution_cutoff_us: u64,
    /// Zero exposes raw completion time. Nonzero must leave cleanup time after the cutoff.
    #[arg(long, default_value_t = 0)]
    release_slot_us: u64,
}

#[cfg(feature = "bench")]
#[derive(clap::Args, Clone)]
struct BenchArgs {
    #[arg(long, default_value = "http://127.0.0.1:8081")]
    base_url: String,
    #[arg(long, env = "LAB_ADMIN_TOKEN")]
    token: String,
    #[arg(long, default_value_t = 1200)]
    trials: u64,
    #[arg(long, default_value_t = 1)]
    seed: u64,
    #[arg(long)]
    control: bool,
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "0,50,250,1000,5000,20000"
    )]
    gaps_us: Vec<u64>,
    #[arg(long, default_value_t = 10)]
    calibration_per_bit_and_gap: usize,
    #[arg(long, default_value_t = 0)]
    sender_slot: u16,
    #[arg(long, default_value_t = 1)]
    probe_slot: u16,
    #[arg(long, default_value = "reports/sequential/report.json")]
    output: PathBuf,
}

#[derive(Clone, Copy)]
struct Policy {
    state_bytes: usize,
    session_slots: usize,
    sender_hot_iterations: u32,
    sender_cold_iterations: u32,
    sender_control_iterations: u32,
    probe_iterations: u32,
    execution_cutoff: Duration,
    release_slot: Option<Duration>,
    fuel: u64,
    max_memory_pages: u32,
    address_space_bytes: u64,
    cpu_seconds: u64,
}

#[derive(Clone)]
struct AppState {
    module: Arc<[u8]>,
    module_sha256: Arc<str>,
    states: Arc<Mutex<Vec<Zeroizing<Vec<u8>>>>>,
    lane: Arc<Semaphore>,
    pending: Arc<AtomicUsize>,
    successful_turns: Arc<AtomicU64>,
    timed_out_turns: Arc<AtomicU64>,
    failed_turns: Arc<AtomicU64>,
    token_hash: [u8; 32],
    policy: Policy,
}

struct PendingGuard(Arc<AtomicUsize>);

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn main() -> Result<()> {
    match env::args().nth(1).as_deref() {
        Some("__runner") => return runner_main(),
        Some("__validate") => {
            return tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(validate_runner());
        }
        _ => {}
    }
    let cli = Cli::parse();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build lab runtime")?
        .block_on(async move {
            match cli.command {
                CommandLine::Serve(args) => serve(args).await,
                #[cfg(feature = "bench")]
                CommandLine::Bench(args) => benchmark::bench(args).await,
            }
        })
}

async fn validate_runner() -> Result<()> {
    let module: Arc<[u8]> = Arc::from(
        wat::parse_str(include_str!("../fixtures/sequential_probe.wat"))
            .context("compile validation fixture")?,
    );
    let policy = Policy {
        state_bytes: 64,
        session_slots: 2,
        sender_hot_iterations: 100,
        sender_cold_iterations: 10,
        sender_control_iterations: 50,
        probe_iterations: 100,
        execution_cutoff: Duration::from_secs(5),
        release_slot: None,
        fuel: 1_000_000,
        max_memory_pages: 129,
        address_space_bytes: 256 * 1024 * 1024,
        cpu_seconds: 2,
    };
    let deadline = tokio::time::Instant::now() + policy.execution_cutoff;
    let output = execute_process_inner(
        module,
        Zeroizing::new(vec![0; policy.state_bytes]),
        Role::Probe,
        0,
        policy.probe_iterations,
        policy,
        deadline,
    )
    .await?;
    let ProcessResult::Success(output) = output else {
        bail!("sandboxed runner did not return state");
    };
    if output.len() != policy.state_bytes {
        bail!("sandboxed runner returned the wrong state size");
    }
    println!("validated fresh-process sequential runner");
    Ok(())
}

async fn serve(args: ServeArgs) -> Result<()> {
    if args.token.len() < 16 {
        bail!("LAB_ADMIN_TOKEN must contain at least 16 bytes");
    }
    if args.session_slots < 2 || args.state_bytes == 0 || args.state_bytes > 65_536 {
        bail!("at least two session slots and 1..=65536 state bytes are required");
    }
    let execution_cutoff = Duration::from_micros(args.execution_cutoff_us);
    if execution_cutoff.is_zero() {
        bail!("execution cutoff must be nonzero");
    }
    let release_slot = match args.release_slot_us {
        0 => None,
        value if value > args.execution_cutoff_us + 1_000 => Some(Duration::from_micros(value)),
        _ => bail!("release slot must reserve at least 1ms after the execution cutoff"),
    };
    let module: Arc<[u8]> = Arc::from(
        wat::parse_str(include_str!("../fixtures/sequential_probe.wat"))
            .context("compile sequential probe fixture")?,
    );
    let policy = Policy {
        state_bytes: args.state_bytes,
        session_slots: args.session_slots,
        sender_hot_iterations: args.sender_hot_iterations,
        sender_cold_iterations: args.sender_cold_iterations,
        sender_control_iterations: args.sender_control_iterations,
        probe_iterations: args.probe_iterations,
        execution_cutoff,
        release_slot,
        fuel: 100_000_000,
        max_memory_pages: 129,
        address_space_bytes: 256 * 1024 * 1024,
        cpu_seconds: 2,
    };
    let state = AppState {
        module_sha256: Arc::from(hex::encode(Sha256::digest(&module))),
        module,
        states: Arc::new(Mutex::new(
            (0..args.session_slots)
                .map(|_| Zeroizing::new(vec![0; args.state_bytes]))
                .collect(),
        )),
        lane: Arc::new(Semaphore::new(1)),
        pending: Arc::new(AtomicUsize::new(0)),
        successful_turns: Arc::new(AtomicU64::new(0)),
        timed_out_turns: Arc::new(AtomicU64::new(0)),
        failed_turns: Arc::new(AtomicU64::new(0)),
        token_hash: Sha256::digest(args.token.as_bytes()).into(),
        policy,
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/turn", post(turn))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BYTES))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(&args.bind)
        .await
        .with_context(|| format!("bind {}", args.bind))?;
    println!("sequential lab listening on {}", args.bind);
    axum::serve(listener, app).await.context("serve lab")?;
    Ok(())
}

async fn health(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<HealthResponse>, LabError> {
    authorize(&headers, &state.token_hash)?;
    Ok(Json(health_response(&state)))
}

fn health_response(state: &AppState) -> HealthResponse {
    HealthResponse {
        status: "ok".into(),
        mode: "fresh_process_per_chunk_global_serialization".into(),
        wasm_sha256: state.module_sha256.to_string(),
        state_bytes: state.policy.state_bytes,
        session_slots: state.policy.session_slots,
        sender_hot_iterations: state.policy.sender_hot_iterations,
        sender_cold_iterations: state.policy.sender_cold_iterations,
        sender_control_iterations: state.policy.sender_control_iterations,
        probe_iterations: state.policy.probe_iterations,
        execution_cutoff_us: state.policy.execution_cutoff.as_micros() as u64,
        release_slot_us: state
            .policy
            .release_slot
            .map_or(0, |duration| duration.as_micros() as u64),
        successful_turns: state.successful_turns.load(Ordering::Relaxed),
        timed_out_turns: state.timed_out_turns.load(Ordering::Relaxed),
        failed_turns: state.failed_turns.load(Ordering::Relaxed),
    }
}

async fn turn(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TurnRequest>,
) -> Result<Response, LabError> {
    authorize(&headers, &state.token_hash)?;
    if request.session_slot as usize >= state.policy.session_slots
        || request.bit > 1
        || (request.role == Role::Probe && request.bit != 0)
    {
        return Err(LabError::bad_request());
    }
    state
        .pending
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            (count < MAX_PENDING).then_some(count + 1)
        })
        .map_err(|_| LabError::too_many())?;
    let pending = PendingGuard(state.pending.clone());
    let slot = tokio::spawn(run_slot(state, request, pending));
    slot.await.map_err(|_| LabError::internal())??;
    Ok(normalized_response())
}

async fn run_slot(
    state: AppState,
    request: TurnRequest,
    _pending: PendingGuard,
) -> Result<(), LabError> {
    let _permit = state
        .lane
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| LabError::internal())?;
    let admitted_at = tokio::time::Instant::now();
    let execution_deadline = admitted_at + state.policy.execution_cutoff;
    let release_deadline = state.policy.release_slot.map(|slot| admitted_at + slot);
    let previous = {
        let states = state.states.lock().await;
        Zeroizing::new(states[request.session_slot as usize].to_vec())
    };
    let iterations = iterations_for(request.role, request.bit, state.policy);
    match execute_process(
        state.module.clone(),
        previous,
        request.role,
        request.bit,
        iterations,
        state.policy,
        execution_deadline,
    )
    .await
    {
        ProcessResult::Success(next) => {
            state.states.lock().await[request.session_slot as usize] = next;
            state.successful_turns.fetch_add(1, Ordering::Relaxed);
        }
        ProcessResult::TimedOut => {
            state.timed_out_turns.fetch_add(1, Ordering::Relaxed);
        }
        ProcessResult::Failed => {
            state.failed_turns.fetch_add(1, Ordering::Relaxed);
        }
    }
    if let Some(deadline) = release_deadline {
        tokio::time::sleep_until(deadline).await;
    }
    Ok(())
}

fn iterations_for(role: Role, bit: u8, policy: Policy) -> u32 {
    match role {
        Role::Sender if bit == 1 => policy.sender_hot_iterations,
        Role::Sender => policy.sender_cold_iterations,
        Role::Control => policy.sender_control_iterations,
        Role::Probe => policy.probe_iterations,
    }
}

enum ProcessResult {
    Success(Zeroizing<Vec<u8>>),
    TimedOut,
    Failed,
}

async fn execute_process(
    module: Arc<[u8]>,
    state: Zeroizing<Vec<u8>>,
    role: Role,
    bit: u8,
    iterations: u32,
    policy: Policy,
    deadline: tokio::time::Instant,
) -> ProcessResult {
    execute_process_inner(module, state, role, bit, iterations, policy, deadline)
        .await
        .unwrap_or(ProcessResult::Failed)
}

async fn execute_process_inner(
    module: Arc<[u8]>,
    state: Zeroizing<Vec<u8>>,
    role: Role,
    bit: u8,
    iterations: u32,
    policy: Policy,
    deadline: tokio::time::Instant,
) -> Result<ProcessResult> {
    let executable = env::current_exe().context("locate lab executable")?;
    let mut child = Command::new(executable)
        .arg("__runner")
        .arg(module.len().to_string())
        .arg(state.len().to_string())
        .arg(policy.fuel.to_string())
        .arg(policy.max_memory_pages.to_string())
        .arg(policy.address_space_bytes.to_string())
        .arg(policy.cpu_seconds.to_string())
        .arg(role.abi().to_string())
        .arg(bit.to_string())
        .arg(iterations.to_string())
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("spawn runner")?;
    let mut stdin = child.stdin.take().context("runner stdin missing")?;
    let write = async {
        stdin.write_all(&module).await?;
        stdin.write_all(&state).await?;
        stdin.shutdown().await
    };
    if tokio::time::timeout_at(deadline, write).await.is_err() {
        terminate(&mut child).await;
        return Ok(ProcessResult::TimedOut);
    }
    drop(stdin);
    let stdout = child.stdout.take().context("runner stdout missing")?;
    let mut output = Zeroizing::new(Vec::with_capacity(policy.state_bytes + 1));
    let completion = async {
        stdout
            .take((policy.state_bytes + 1) as u64)
            .read_to_end(&mut output)
            .await?;
        child.wait().await
    };
    let status = match tokio::time::timeout_at(deadline, completion).await {
        Ok(result) => result.context("wait for runner")?,
        Err(_) => {
            terminate(&mut child).await;
            return Ok(ProcessResult::TimedOut);
        }
    };
    if status.success() && output.len() == policy.state_bytes {
        Ok(ProcessResult::Success(output))
    } else {
        Ok(ProcessResult::Failed)
    }
}

async fn terminate(child: &mut Child) {
    if child.kill().await.is_err() {
        let _ = child.wait().await;
    }
}

fn runner_main() -> Result<()> {
    use std::io::{Read, Write};

    let module_len: usize = runner_arg(2, "module length")?;
    let state_len: usize = runner_arg(3, "state length")?;
    let fuel = runner_arg(4, "fuel")?;
    let max_memory_pages = runner_arg(5, "memory pages")?;
    let address_space_bytes = runner_arg(6, "address space")?;
    let cpu_seconds = runner_arg(7, "CPU seconds")?;
    let role = runner_arg(8, "role")?;
    let bit = runner_arg(9, "bit")?;
    let iterations = runner_arg(10, "iterations")?;
    if module_len == 0 || module_len > 1024 * 1024 || state_len == 0 || state_len > 65_536 {
        bail!("runner input violates bounds");
    }
    let mut input = Zeroizing::new(vec![0; module_len + state_len]);
    std::io::stdin().read_exact(&mut input)?;
    clear_environment();
    sandbox::close_inherited_descriptors()?;
    sandbox::apply(sandbox::Policy {
        address_space_bytes,
        cpu_seconds,
    })?;
    let next = wasm::execute(
        &input[..module_len],
        &input[module_len..],
        role,
        bit,
        iterations,
        fuel,
        max_memory_pages,
    )?;
    std::io::stdout().write_all(&next)?;
    std::io::stdout().flush()?;
    Ok(())
}

fn runner_arg<T>(index: usize, name: &str) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    env::args()
        .nth(index)
        .with_context(|| format!("missing runner {name}"))?
        .parse()
        .with_context(|| format!("invalid runner {name}"))
}

fn clear_environment() {
    let names: Vec<_> = env::vars_os().map(|(name, _)| name).collect();
    for name in names {
        // SAFETY: the runner has not created any threads.
        unsafe { env::remove_var(name) };
    }
}

fn authorize(headers: &HeaderMap, expected: &[u8; 32]) -> Result<(), LabError> {
    let supplied = headers
        .get("x-sequential-lab-token")
        .and_then(|value| value.to_str().ok())
        .map(|value| Sha256::digest(value.as_bytes()))
        .unwrap_or_else(|| Sha256::digest([]));
    if bool::from(supplied.as_slice().ct_eq(expected)) {
        Ok(())
    } else {
        Err(LabError::unauthorized())
    }
}

fn normalized_response() -> Response {
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        NORMALIZED_BODY,
    )
        .into_response()
}

#[derive(Debug)]
struct LabError(StatusCode, &'static str);

impl LabError {
    const fn bad_request() -> Self {
        Self(StatusCode::BAD_REQUEST, "bad request")
    }
    const fn unauthorized() -> Self {
        Self(StatusCode::UNAUTHORIZED, "unauthorized")
    }
    const fn too_many() -> Self {
        Self(StatusCode::TOO_MANY_REQUESTS, "queue full")
    }
    const fn internal() -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
}

impl IntoResponse for LabError {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

#[cfg(feature = "bench")]
mod benchmark {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TrialPlan {
        bit: u8,
        gap_us: u64,
    }

    #[derive(Clone, Copy)]
    struct Scored {
        expected: u8,
        decoded: u8,
        gap_us: u64,
    }

    pub(super) async fn bench(args: BenchArgs) -> Result<()> {
        if args.token.len() < 16 || args.gaps_us.is_empty() || args.sender_slot == args.probe_slot {
            bail!("valid token, at least one gap, and distinct sender/probe slots are required");
        }
        let calibration_len = args.gaps_us.len() * args.calibration_per_bit_and_gap * 2;
        if args.trials as usize <= calibration_len {
            bail!("trials must exceed the {calibration_len} calibration trials");
        }
        let client = Client::builder().build()?;
        let server: HealthResponse = client
            .get(endpoint(&args.base_url, "/health"))
            .header("x-sequential-lab-token", &args.token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if args.sender_slot as usize >= server.session_slots
            || args.probe_slot as usize >= server.session_slots
        {
            bail!("requested session slot is not present on the server");
        }
        let plan = build_trial_plan(
            args.seed,
            args.trials as usize,
            &args.gaps_us,
            args.calibration_per_bit_and_gap,
        );
        let started = Instant::now();
        let mut records = Vec::with_capacity(plan.len());
        for (trial_id, planned) in plan.iter().copied().enumerate() {
            let sender_started = Instant::now();
            send_turn(
                &client,
                &args,
                TurnRequest {
                    session_slot: args.sender_slot,
                    trial_id: trial_id as u64,
                    role: if args.control {
                        Role::Control
                    } else {
                        Role::Sender
                    },
                    bit: planned.bit,
                },
            )
            .await?;
            let sender_latency_ns = sender_started.elapsed().as_nanos() as u64;
            if planned.gap_us != 0 {
                tokio::time::sleep(Duration::from_micros(planned.gap_us)).await;
            }
            let probe_started = Instant::now();
            send_turn(
                &client,
                &args,
                TurnRequest {
                    session_slot: args.probe_slot,
                    trial_id: trial_id as u64,
                    role: Role::Probe,
                    bit: 0,
                },
            )
            .await?;
            records.push(TrialRecord {
                trial_id: trial_id as u64,
                gap_us: planned.gap_us,
                expected_bit: planned.bit,
                sender_latency_ns,
                probe_latency_ns: probe_started.elapsed().as_nanos() as u64,
            });
        }
        let final_server: HealthResponse = client
            .get(endpoint(&args.base_url, "/health"))
            .header("x-sequential-lab-token", &args.token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let successful_turns = final_server
            .successful_turns
            .saturating_sub(server.successful_turns);
        let timed_out_turns = final_server
            .timed_out_turns
            .saturating_sub(server.timed_out_turns);
        let failed_turns = final_server
            .failed_turns
            .saturating_sub(server.failed_turns);
        let expected_turns = args.trials.saturating_mul(2);
        if successful_turns != expected_turns || timed_out_turns != 0 || failed_turns != 0 {
            bail!(
                "incomplete campaign: expected {expected_turns} successful turns, got {successful_turns} successful, {timed_out_turns} timed out, {failed_turns} failed"
            );
        }
        let wall_time = started.elapsed();
        let report = analyze(
            args.seed,
            args.control,
            args.trials,
            args.calibration_per_bit_and_gap,
            wall_time,
            final_server,
            successful_turns,
            timed_out_turns,
            failed_turns,
            &plan,
            records,
        );
        if let Some(parent) = args.output.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&args.output, serde_json::to_vec_pretty(&report)?)
            .with_context(|| format!("write {}", args.output.display()))?;
        println!(
            "wrote {}: BER={:.4} corrected_MI={:.6} p={:.4} corrected_rate={:.3} bits/hour",
            args.output.display(),
            report.bit_error_rate,
            report.corrected_mutual_information_bits_per_trial,
            report.permutation_p_value,
            report.corrected_bits_per_hour
        );
        Ok(())
    }

    async fn send_turn(client: &Client, args: &BenchArgs, request: TurnRequest) -> Result<()> {
        let response = client
            .post(endpoint(&args.base_url, "/v1/turn"))
            .header("x-sequential-lab-token", &args.token)
            .json(&request)
            .send()
            .await
            .context("send turn")?
            .error_for_status()
            .context("turn rejected")?;
        let body = response.text().await.context("read turn response")?;
        if body != NORMALIZED_BODY {
            bail!("turn response was not normalized");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn analyze(
        seed: u64,
        control: bool,
        requested_trials: u64,
        calibration_per_bit_and_gap: usize,
        wall_time: Duration,
        server: HealthResponse,
        successful_turns: u64,
        timed_out_turns: u64,
        failed_turns: u64,
        plan: &[TrialPlan],
        records: Vec<TrialRecord>,
    ) -> BenchmarkReport {
        let calibration_len = server_gaps(plan).len() * calibration_per_bit_and_gap * 2;
        let mut scored = Vec::new();
        let mut summaries = Vec::new();
        for gap in server_gaps(plan) {
            let zero: Vec<_> = records[..calibration_len]
                .iter()
                .filter(|record| record.gap_us == gap && record.expected_bit == 0)
                .map(|record| record.probe_latency_ns as f64 / 1000.0)
                .collect();
            let one: Vec<_> = records[..calibration_len]
                .iter()
                .filter(|record| record.gap_us == gap && record.expected_bit == 1)
                .map(|record| record.probe_latency_ns as f64 / 1000.0)
                .collect();
            let zero_mean = mean(&zero);
            let one_mean = mean(&one);
            let threshold = (zero_mean + one_mean) / 2.0;
            let high_is_one = one_mean >= zero_mean;
            let mut gap_scored = Vec::new();
            for record in records[calibration_len..]
                .iter()
                .filter(|record| record.gap_us == gap)
            {
                let high = record.probe_latency_ns as f64 / 1000.0 >= threshold;
                let decoded = u8::from(if high_is_one { high } else { !high });
                gap_scored.push(Scored {
                    expected: record.expected_bit,
                    decoded,
                    gap_us: gap,
                });
            }
            let permutation = permutation_test(&gap_scored, seed ^ gap, 2_000);
            let binary: Vec<_> = gap_scored
                .iter()
                .map(|pair| (pair.expected, pair.decoded))
                .collect();
            let raw_mi = mutual_information(&binary);
            let mut latencies: Vec<_> = records
                .iter()
                .filter(|record| record.gap_us == gap)
                .map(|record| record.probe_latency_ns as f64 / 1000.0)
                .collect();
            latencies.sort_by(f64::total_cmp);
            summaries.push(GapSummary {
                gap_us: gap,
                scored_trials: gap_scored.len() as u64,
                zero_mean_us: zero_mean,
                one_mean_us: one_mean,
                mean_delta_us: one_mean - zero_mean,
                threshold_us: threshold,
                high_latency_is_one: high_is_one,
                bit_error_rate: error_rate(&gap_scored),
                mutual_information_bits_per_trial: raw_mi,
                corrected_mutual_information_bits_per_trial: (raw_mi - permutation.null_mean)
                    .max(0.0),
                permutation_p_value: permutation.p_value,
                probe_p50_us: percentile(&latencies, 0.50),
                probe_p95_us: percentile(&latencies, 0.95),
                probe_p99_us: percentile(&latencies, 0.99),
            });
            scored.extend(gap_scored);
        }
        let raw_mi = mutual_information(
            &scored
                .iter()
                .map(|pair| (pair.expected, pair.decoded))
                .collect::<Vec<_>>(),
        );
        let permutation = permutation_test(&scored, seed, 4_000);
        let corrected_mi = (raw_mi - permutation.null_mean).max(0.0);
        let wall_hours = wall_time.as_secs_f64() / 3600.0;
        let trials_per_hour = if wall_hours == 0.0 {
            0.0
        } else {
            scored.len() as f64 / wall_hours
        };
        BenchmarkReport {
            schema_version: 1,
            seed,
            control,
            requested_trials,
            calibration_per_bit_and_gap,
            wall_time_ms: wall_time.as_secs_f64() * 1000.0,
            trials_per_hour,
            bit_error_rate: error_rate(&scored),
            mutual_information_bits_per_trial: raw_mi,
            corrected_mutual_information_bits_per_trial: corrected_mi,
            permutation_p_value: permutation.p_value,
            raw_information_bits_observed: raw_mi * scored.len() as f64,
            corrected_information_bits_observed: corrected_mi * scored.len() as f64,
            corrected_bits_per_hour: if permutation.p_value <= 0.05 {
                corrected_mi * trials_per_hour
            } else {
                0.0
            },
            successful_turns,
            timed_out_turns,
            failed_turns,
            server,
            gap_summaries: summaries,
            records,
        }
    }

    fn build_trial_plan(
        seed: u64,
        count: usize,
        gaps: &[u64],
        calibration_per_bit_and_gap: usize,
    ) -> Vec<TrialPlan> {
        let mut calibration = Vec::new();
        for &gap_us in gaps {
            for _ in 0..calibration_per_bit_and_gap {
                calibration.push(TrialPlan { bit: 0, gap_us });
                calibration.push(TrialPlan { bit: 1, gap_us });
            }
        }
        let mut random = seed.max(1) ^ 0x7365_7175_656e_7469;
        shuffle(&mut calibration, &mut random);
        let combinations: Vec<_> = gaps
            .iter()
            .flat_map(|&gap_us| [0, 1].map(move |bit| TrialPlan { bit, gap_us }))
            .collect();
        let mut output = calibration;
        while output.len() < count {
            let mut block = combinations.clone();
            shuffle(&mut block, &mut random);
            output.extend(block.into_iter().take(count - output.len()));
        }
        output
    }

    fn server_gaps(plan: &[TrialPlan]) -> Vec<u64> {
        let mut gaps: Vec<_> = plan.iter().map(|planned| planned.gap_us).collect();
        gaps.sort_unstable();
        gaps.dedup();
        gaps
    }

    fn shuffle<T>(values: &mut [T], state: &mut u64) {
        for index in (1..values.len()).rev() {
            let selected = random_index(state, index + 1);
            values.swap(index, selected);
        }
    }

    fn random_index(state: &mut u64, upper: usize) -> usize {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state as usize % upper
    }

    struct Permutation {
        p_value: f64,
        null_mean: f64,
    }

    fn permutation_test(pairs: &[Scored], seed: u64, iterations: usize) -> Permutation {
        if pairs.is_empty() {
            return Permutation {
                p_value: 1.0,
                null_mean: 0.0,
            };
        }
        let observed = mutual_information(
            &pairs
                .iter()
                .map(|pair| (pair.expected, pair.decoded))
                .collect::<Vec<_>>(),
        );
        let gaps = {
            let mut values: Vec<_> = pairs.iter().map(|pair| pair.gap_us).collect();
            values.sort_unstable();
            values.dedup();
            values
        };
        let groups: Vec<Vec<usize>> = gaps
            .iter()
            .map(|gap| {
                pairs
                    .iter()
                    .enumerate()
                    .filter(|(_, pair)| pair.gap_us == *gap)
                    .map(|(index, _)| index)
                    .collect()
            })
            .collect();
        let mut random = seed.max(1) ^ 0x7065_726d_7574_6521;
        let mut expected: Vec<_> = pairs.iter().map(|pair| pair.expected).collect();
        let mut sum = 0.0;
        let mut at_least = 0;
        for _ in 0..iterations {
            for group in &groups {
                for index in (1..group.len()).rev() {
                    let selected = random_index(&mut random, index + 1);
                    expected.swap(group[index], group[selected]);
                }
            }
            let estimate = mutual_information(
                &pairs
                    .iter()
                    .enumerate()
                    .map(|(index, pair)| (expected[index], pair.decoded))
                    .collect::<Vec<_>>(),
            );
            sum += estimate;
            if estimate >= observed - f64::EPSILON {
                at_least += 1;
            }
        }
        Permutation {
            p_value: (at_least + 1) as f64 / (iterations + 1) as f64,
            null_mean: sum / iterations as f64,
        }
    }

    fn mutual_information(pairs: &[(u8, u8)]) -> f64 {
        if pairs.is_empty() {
            return 0.0;
        }
        let mut joint = [[0.0; 2]; 2];
        for &(expected, decoded) in pairs {
            joint[expected as usize][decoded as usize] += 1.0;
        }
        let rows = [joint[0][0] + joint[0][1], joint[1][0] + joint[1][1]];
        let cols = [joint[0][0] + joint[1][0], joint[0][1] + joint[1][1]];
        let total = pairs.len() as f64;
        let mut information = 0.0;
        for expected in 0..2 {
            for decoded in 0..2 {
                let count = joint[expected][decoded];
                if count > 0.0 {
                    information +=
                        count / total * (count * total / (rows[expected] * cols[decoded])).log2();
                }
            }
        }
        information.max(0.0)
    }

    fn error_rate(pairs: &[Scored]) -> f64 {
        if pairs.is_empty() {
            0.0
        } else {
            pairs
                .iter()
                .filter(|pair| pair.expected != pair.decoded)
                .count() as f64
                / pairs.len() as f64
        }
    }

    fn mean(values: &[f64]) -> f64 {
        if values.is_empty() {
            0.0
        } else {
            values.iter().sum::<f64>() / values.len() as f64
        }
    }

    fn percentile(sorted: &[f64], quantile: f64) -> f64 {
        if sorted.is_empty() {
            0.0
        } else {
            sorted[((sorted.len() - 1) as f64 * quantile).round() as usize]
        }
    }

    fn endpoint(base: &str, path: &str) -> String {
        format!("{}{}", base.trim_end_matches('/'), path)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn plan_is_balanced_and_repeatable() {
            let gaps = [0, 250, 5_000];
            let first = build_trial_plan(7, 120, &gaps, 5);
            assert_eq!(first, build_trial_plan(7, 120, &gaps, 5));
            for gap in gaps {
                let zero = first
                    .iter()
                    .filter(|planned| planned.gap_us == gap && planned.bit == 0)
                    .count();
                let one = first
                    .iter()
                    .filter(|planned| planned.gap_us == gap && planned.bit == 1)
                    .count();
                assert!(zero.abs_diff(one) <= 1);
            }
        }

        #[test]
        fn information_detects_perfect_and_chance_channels() {
            assert!((mutual_information(&[(0, 0), (1, 1), (0, 0), (1, 1)]) - 1.0).abs() < 1e-9);
            assert_eq!(mutual_information(&[(0, 0), (0, 1), (1, 0), (1, 1)]), 0.0);
        }
    }
}
