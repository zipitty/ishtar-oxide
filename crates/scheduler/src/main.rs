mod sandbox;
mod wasm;

use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ishtar_protocol::{
    CreateSessionRequest, CreateSessionResponse, DEFAULT_IDLE_EXPIRY_MS, ExperimentProfile,
    ExperimentRunInfo, ExperimentStartRequest, RuntimeProfile, ServerTimingRecord, TurnRequest,
    TurnResponse, WorkerRole, fixed_response, sha256_hex, validate_profile, validate_session_id,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    env,
    path::{Path as FsPath, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tokio::{
    io::AsyncWriteExt,
    process::Command,
    sync::{Mutex, Semaphore},
};
use tower_http::limit::RequestBodyLimitLayer;
use uuid::Uuid;
use wasm::{
    LoadedModule, WasmLimits, WorkerInput, WorkerOutput, execute_turn, load_restricted_module,
};

const MAX_REQUEST_BYTES: usize = 16 * 1024;
const SESSION_TOKEN_BYTES: usize = 32;
const MAX_SESSIONS: usize = 4096;
const MAX_PENDING_TURNS: usize = 1024;

#[derive(Clone)]
struct AppState {
    sessions: Arc<Mutex<HashMap<String, SessionState>>>,
    profiles: Arc<HashMap<String, ExperimentProfile>>,
    semaphores: Arc<HashMap<String, Arc<Semaphore>>>,
    module: Arc<LoadedModule>,
    runtime_profile: RuntimeProfile,
    runs: Arc<Mutex<HashMap<String, RunState>>>,
    active_run: Arc<Mutex<Option<String>>>,
    admin_token_hash: [u8; 32],
    process_start: Instant,
    trace_counter: Arc<AtomicU64>,
    pending_turns: Arc<AtomicUsize>,
    container_config_sha256_hex: Option<String>,
    tinfoil_attestation_sha256_hex: Option<String>,
}

struct SessionState {
    token_hash: [u8; 32],
    state_blob: Vec<u8>,
    created_at: Instant,
    last_used_at: Instant,
    idle_expiry: Duration,
    in_flight: bool,
}

struct RunState {
    info: ExperimentRunInfo,
    records: Vec<ServerTimingRecord>,
    max_records: usize,
}

struct PendingTurnGuard(Arc<AtomicUsize>);

impl Drop for PendingTurnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct HealthResponse {
    status: &'static str,
    scheduler_version: String,
    wasm_sha256_hex: String,
    runtime_profile: RuntimeProfile,
    sessions_in_memory: usize,
}

#[derive(Debug)]
struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "unauthorized".into(),
        }
    }
    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }
    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }
    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
    fn too_many(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: message.into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct ErrorBody {
            error: String,
        }
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

fn main() -> Result<()> {
    match env::args().nth(1).as_deref() {
        Some("__runner") => return runner_main(),
        Some("__healthcheck") => return healthcheck_main(),
        Some("__validate_artifacts") => return validate_artifacts_main(),
        _ => {}
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build scheduler runtime")?
        .block_on(server_main())
}

async fn server_main() -> Result<()> {
    let profile_dir = PathBuf::from(env::var("PROFILE_DIR").unwrap_or_else(|_| "profiles".into()));
    let wasm_path = PathBuf::from(
        env::var("WASM_PATH")
            .unwrap_or_else(|_| "target/wasm32-unknown-unknown/release/bench_wasm.wasm".into()),
    );
    let profiles = load_profiles(&profile_dir)?;
    let max_pages = profiles
        .values()
        .map(|p| p.wasm_memory_pages)
        .max()
        .unwrap_or(32);
    let module = Arc::new(load_restricted_module(
        &wasm_path,
        &WasmLimits {
            max_memory_pages: max_pages,
        },
    )?);
    let validation_profile = profiles
        .get("realistic")
        .context("realistic profile is required")?;
    validate_runner_process(&module, validation_profile)
        .context("sandboxed runner startup validation failed")?;
    let admin = env::var("LAB_ADMIN_TOKEN").context("LAB_ADMIN_TOKEN must be set")?;
    if admin.len() < 16 {
        bail!("LAB_ADMIN_TOKEN must contain at least 16 bytes");
    }
    let semaphores = profiles
        .iter()
        .map(|(id, p)| (id.clone(), Arc::new(Semaphore::new(p.max_parallel_turns))))
        .collect();
    let config_hash = env::var_os("TINFOIL_CONFIG_PATH")
        .and_then(|path| std::fs::read(path).ok())
        .map(|bytes| sha256_hex(&bytes));
    let attestation_hash = env::var_os("TINFOIL_ATTESTATION_PATH")
        .and_then(|path| std::fs::read(path).ok())
        .map(|bytes| sha256_hex(&bytes));
    let state = AppState {
        sessions: Default::default(),
        profiles: Arc::new(profiles),
        semaphores: Arc::new(semaphores),
        module,
        runtime_profile: wasm::runtime_profile(),
        runs: Default::default(),
        active_run: Default::default(),
        admin_token_hash: hash_token(admin.as_bytes()),
        process_start: Instant::now(),
        trace_counter: Arc::new(AtomicU64::new(1)),
        pending_turns: Arc::new(AtomicUsize::new(0)),
        container_config_sha256_hex: config_hash,
        tinfoil_attestation_sha256_hex: attestation_hash,
    };
    let expiry_state = state.clone();
    tokio::spawn(expire_sessions(expiry_state));

    let app = app(state)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BYTES));
    let port = env::var("PORT").unwrap_or_else(|_| "8080".into());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .context("bind HTTP listener")?;
    axum::serve(listener, app).await.context("serve HTTP")?;
    Ok(())
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/profiles", get(get_profiles))
        .route("/v1/sessions", post(create_session))
        .route("/v1/sessions/{session_id}/turn", post(run_turn))
        .route("/v1/experiments/start", post(start_experiment))
        .route("/v1/experiments/{run_id}/stop", post(stop_experiment))
        .route("/v1/experiments/{run_id}/records", get(get_run_records))
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        scheduler_version: scheduler_version(),
        wasm_sha256_hex: state.module.sha256_hex.clone(),
        runtime_profile: state.runtime_profile.clone(),
        sessions_in_memory: state.sessions.lock().await.len(),
    })
}

async fn get_profiles(State(state): State<AppState>) -> Json<Vec<ExperimentProfile>> {
    let mut profiles: Vec<_> = state.profiles.values().cloned().collect();
    profiles.sort_by(|a, b| a.id.cmp(&b.id));
    Json(profiles)
}

async fn create_session(
    State(state): State<AppState>,
    Json(request): Json<CreateSessionRequest>,
) -> Result<Json<CreateSessionResponse>, AppError> {
    let id = request
        .session_id
        .unwrap_or_else(|| Uuid::new_v4().simple().to_string());
    validate_session_id(&id).map_err(|e| AppError::bad_request(e.to_string()))?;
    let mut token_bytes = [0u8; SESSION_TOKEN_BYTES];
    getrandom::fill(&mut token_bytes)
        .map_err(|_| AppError::internal("OS randomness unavailable"))?;
    let token = URL_SAFE_NO_PAD.encode(token_bytes);
    let now = Instant::now();
    let session = SessionState {
        token_hash: hash_token(token.as_bytes()),
        state_blob: Vec::new(),
        created_at: now,
        last_used_at: now,
        idle_expiry: Duration::from_millis(DEFAULT_IDLE_EXPIRY_MS),
        in_flight: false,
    };
    let mut sessions = state.sessions.lock().await;
    if sessions.len() >= MAX_SESSIONS {
        return Err(AppError::too_many("session capacity reached"));
    }
    if sessions.contains_key(&id) {
        return Err(AppError::conflict("session_id already exists"));
    }
    sessions.insert(id.clone(), session);
    drop(sessions);
    Ok(Json(CreateSessionResponse {
        session_id: id,
        bearer_token: token,
        expires_after_idle_ms: DEFAULT_IDLE_EXPIRY_MS,
    }))
}

async fn run_turn(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<TurnRequest>,
) -> Result<Json<TurnResponse>, AppError> {
    validate_session_id(&session_id).map_err(|e| AppError::bad_request(e.to_string()))?;
    if request.payload_len.unwrap_or(0) != 0 {
        return Err(AppError::bad_request(
            "payloads are forbidden; use synthetic bits only",
        ));
    }
    let bit = match (request.role, request.bit) {
        (WorkerRole::Sender, Some(bit @ 0..=1)) => bit,
        (WorkerRole::Sender, _) => {
            return Err(AppError::bad_request("sender bit must be zero or one"));
        }
        (_, None) => 0,
        (_, Some(_)) => return Err(AppError::bad_request("only sender turns accept a bit")),
    };
    let profile = state
        .profiles
        .get(&request.profile_id)
        .cloned()
        .ok_or_else(|| AppError::not_found("unknown profile_id"))?;
    let pending = state
        .pending_turns
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            (count < MAX_PENDING_TURNS).then_some(count + 1)
        })
        .map_err(|_| AppError::too_many("turn queue capacity reached"))?;
    let _pending_guard = PendingTurnGuard(state.pending_turns.clone());
    debug_assert!(pending < MAX_PENDING_TURNS);
    {
        let mut sessions = state.sessions.lock().await;
        let session = sessions
            .get_mut(&session_id)
            .ok_or_else(|| AppError::not_found("unknown session"))?;
        check_session_token(&headers, session)?;
        if session.in_flight {
            return Err(AppError::conflict("session already has a turn in flight"));
        }
        session.in_flight = true;
        session.last_used_at = Instant::now();
        session.idle_expiry = Duration::from_millis(profile.session_idle_expiry_ms);
    }

    let trace_id = state.trace_counter.fetch_add(1, Ordering::Relaxed);
    let queued_at_ns = monotonic_ns(state.process_start);
    let jitter = choose_jitter_us(
        trace_id,
        profile.dispatch_jitter_min_us,
        profile.dispatch_jitter_max_us,
    );
    if jitter != 0 {
        tokio::time::sleep(Duration::from_micros(jitter)).await;
    }
    let semaphore = state
        .semaphores
        .get(&profile.id)
        .expect("profile semaphore")
        .clone();
    let permit = semaphore
        .acquire_owned()
        .await
        .map_err(|_| AppError::internal("scheduler closed"))?;
    let dispatch_at_ns = monotonic_ns(state.process_start);
    let runner_start_at_ns = dispatch_at_ns;
    let wasm_enter_at_ns = monotonic_ns(state.process_start);
    let profile_word = iterations_for(&profile, request.role, bit).min(u32::MAX as u64) as u32;
    let input = WorkerInput {
        role: request.role,
        bit,
        trial_id: request.trial_id,
        profile_word,
    };
    let execution = execute_turn_process(&state.module, input, &profile).await;
    drop(permit);
    let wasm_exit_at_ns = monotonic_ns(state.process_start);
    let (fuel_consumed, timed_out, trap) = match execution {
        Ok(output) if output.result == 0 => (Some(output.fuel_consumed), false, None),
        Ok(output) => (
            Some(output.fuel_consumed),
            false,
            Some(format!("guest logical failure {}", output.result)),
        ),
        Err(error) if error.to_string() == "turn timed out" => {
            (None, true, Some("turn timed out".into()))
        }
        Err(error) => (None, false, Some(sanitize_error(&error.to_string()))),
    };
    let release_epoch = profile.release_epoch_us;
    if release_epoch != 0 {
        let elapsed_us = monotonic_ns(state.process_start) as u64 / 1_000;
        let remainder = elapsed_us % release_epoch;
        let wait = if remainder == 0 {
            release_epoch
        } else {
            release_epoch - remainder
        };
        tokio::time::sleep(Duration::from_micros(wait)).await;
    }
    let response_release_at_ns = monotonic_ns(state.process_start);
    let record = ServerTimingRecord {
        trace_id,
        trial_id: request.trial_id,
        role: request.role,
        queued_at_ns,
        dispatch_at_ns,
        runner_start_at_ns,
        wasm_enter_at_ns,
        wasm_exit_at_ns,
        response_release_at_ns,
        fuel_consumed,
        timed_out,
        trap: trap.clone(),
    };
    record_if_active(&state, &profile.id, record).await;
    {
        let mut sessions = state.sessions.lock().await;
        if let Some(session) = sessions.get_mut(&session_id) {
            session.in_flight = false;
            session.last_used_at = Instant::now();
            session.state_blob.clear();
        }
    }
    if timed_out {
        return Err(AppError {
            status: StatusCode::REQUEST_TIMEOUT,
            message: "turn timed out".into(),
        });
    }
    if trap.is_some() {
        return Err(AppError::bad_request("guest turn trapped"));
    }
    Ok(Json(TurnResponse {
        session_id,
        trial_id: request.trial_id,
        fixed_body: fixed_response(trace_id, profile.fixed_response_bytes),
        server_trace_id: trace_id,
    }))
}

async fn start_experiment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ExperimentStartRequest>,
) -> Result<Json<ExperimentRunInfo>, AppError> {
    check_admin(&headers, &state.admin_token_hash)?;
    if request.notes.as_ref().is_some_and(|n| n.len() > 1024) {
        return Err(AppError::bad_request("notes too long"));
    }
    let profile = state
        .profiles
        .get(&request.profile_id)
        .cloned()
        .ok_or_else(|| AppError::not_found("unknown profile_id"))?;
    let mut active = state.active_run.lock().await;
    if active.is_some() {
        return Err(AppError::conflict("an experiment is already active"));
    }
    let run_id = Uuid::new_v4().simple().to_string();
    let info = ExperimentRunInfo {
        run_id: run_id.clone(),
        profile,
        started_at_unix_ms: unix_ms(),
        scheduler_version: scheduler_version(),
        wasm_sha256_hex: state.module.sha256_hex.clone(),
        container_config_sha256_hex: state.container_config_sha256_hex.clone(),
        tinfoil_attestation_sha256_hex: state.tinfoil_attestation_sha256_hex.clone(),
        runtime_profile: state.runtime_profile.clone(),
        completed: false,
        records_dropped: 0,
    };
    let turns_per_trial = profile_turns_per_trial(&info.profile);
    let max_records = (info.profile.trials as usize)
        .saturating_mul(turns_per_trial)
        .min(1_000_000);
    state.runs.lock().await.insert(
        run_id.clone(),
        RunState {
            info: info.clone(),
            records: Vec::new(),
            max_records,
        },
    );
    *active = Some(run_id);
    Ok(Json(info))
}

async fn stop_experiment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(run_id): Path<String>,
) -> Result<Json<ExperimentRunInfo>, AppError> {
    check_admin(&headers, &state.admin_token_hash)?;
    let mut active = state.active_run.lock().await;
    if active.as_deref() != Some(&run_id) {
        return Err(AppError::conflict("run is not active"));
    }
    let mut runs = state.runs.lock().await;
    let run = runs
        .get_mut(&run_id)
        .ok_or_else(|| AppError::not_found("unknown run_id"))?;
    run.info.completed = true;
    *active = None;
    Ok(Json(run.info.clone()))
}

async fn get_run_records(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(run_id): Path<String>,
) -> Result<Json<Vec<ServerTimingRecord>>, AppError> {
    check_admin(&headers, &state.admin_token_hash)?;
    let runs = state.runs.lock().await;
    let run = runs
        .get(&run_id)
        .ok_or_else(|| AppError::not_found("unknown run_id"))?;
    if !run.info.completed {
        return Err(AppError::conflict("run is still active"));
    }
    Ok(Json(run.records.clone()))
}

fn check_admin(headers: &HeaderMap, expected_hash: &[u8; 32]) -> Result<(), AppError> {
    let token = headers
        .get("x-lab-admin-token")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(AppError::unauthorized)?;
    constant_time_hash_check(token.as_bytes(), expected_hash)
}

fn check_session_token(headers: &HeaderMap, session: &SessionState) -> Result<(), AppError> {
    let value = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(AppError::unauthorized)?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or_else(AppError::unauthorized)?;
    constant_time_hash_check(token.as_bytes(), &session.token_hash)
}

fn constant_time_hash_check(token: &[u8], expected: &[u8; 32]) -> Result<(), AppError> {
    let actual = hash_token(token);
    if bool::from(actual.ct_eq(expected)) {
        Ok(())
    } else {
        Err(AppError::unauthorized())
    }
}

async fn expire_sessions(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        let now = Instant::now();
        state.sessions.lock().await.retain(|_, session| {
            let _age = now.saturating_duration_since(session.created_at);
            session.in_flight
                || now.saturating_duration_since(session.last_used_at) <= session.idle_expiry
        });
    }
}

async fn record_if_active(state: &AppState, profile_id: &str, record: ServerTimingRecord) {
    let active = state.active_run.lock().await.clone();
    if let Some(run_id) = active {
        let mut runs = state.runs.lock().await;
        if let Some(run) = runs.get_mut(&run_id) {
            if run.info.profile.id == profile_id {
                if run.records.len() < run.max_records {
                    run.records.push(record);
                } else {
                    run.info.records_dropped = run.info.records_dropped.saturating_add(1);
                }
            }
        }
    }
}

fn load_profiles(dir: &FsPath) -> Result<HashMap<String, ExperimentProfile>> {
    let mut result = HashMap::new();
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("read profile directory {}", dir.display()))?
    {
        let path = entry?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let profile: ExperimentProfile = serde_json::from_slice(&std::fs::read(&path)?)
            .with_context(|| format!("parse profile {}", path.display()))?;
        validate_profile(&profile)
            .with_context(|| format!("validate profile {}", path.display()))?;
        if result.insert(profile.id.clone(), profile).is_some() {
            bail!("duplicate profile id");
        }
    }
    if result.is_empty() {
        bail!("no valid profiles found");
    }
    Ok(result)
}

fn iterations_for(profile: &ExperimentProfile, role: WorkerRole, bit: u8) -> u64 {
    match role {
        WorkerRole::Sender if bit == 1 => profile.sender_hot_iterations,
        WorkerRole::Sender => profile.sender_cold_iterations,
        WorkerRole::Probe => profile.probe_iterations,
        WorkerRole::Background => profile.probe_iterations / 2,
        WorkerRole::Control => profile.sender_cold_iterations,
    }
}

fn profile_turns_per_trial(profile: &ExperimentProfile) -> usize {
    profile
        .sender_sessions
        .saturating_add(profile.probe_sessions)
        .saturating_add(profile.background_sessions)
        .max(1)
}

fn choose_jitter_us(trace_id: u64, min: u64, max: u64) -> u64 {
    if min >= max {
        return min;
    }
    let mixed = trace_id.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(17);
    min + mixed % (max - min + 1)
}

fn hash_token(token: &[u8]) -> [u8; 32] {
    Sha256::digest(token).into()
}
fn monotonic_ns(base: Instant) -> u128 {
    base.elapsed().as_nanos()
}
fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn scheduler_version() -> String {
    format!(
        "{}+{}",
        env!("CARGO_PKG_VERSION"),
        option_env!("GIT_COMMIT").unwrap_or("unknown")
    )
}
fn sanitize_error(error: &str) -> String {
    error.chars().take(160).collect()
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnerRequest {
    input: WorkerInput,
    profile: ExperimentProfile,
}

async fn execute_turn_process(
    module: &LoadedModule,
    input: WorkerInput,
    profile: &ExperimentProfile,
) -> Result<WorkerOutput> {
    let executable = env::current_exe().context("locate scheduler executable")?;
    let mut child = Command::new(executable)
        .arg("__runner")
        .arg(&module.path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("spawn isolated runner")?;
    let request = serde_json::to_vec(&RunnerRequest {
        input,
        profile: profile.clone(),
    })?;
    let mut stdin = child.stdin.take().context("runner stdin missing")?;
    stdin
        .write_all(&request)
        .await
        .context("write runner request")?;
    stdin.shutdown().await.context("close runner stdin")?;
    drop(stdin);
    let output = tokio::time::timeout(
        Duration::from_millis(profile.request_timeout_ms),
        child.wait_with_output(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("turn timed out"))??;
    if !output.status.success() {
        bail!(
            "runner failed: {}",
            sanitize_error(&String::from_utf8_lossy(&output.stderr))
        );
    }
    serde_json::from_slice(&output.stdout).context("decode runner output")
}

fn runner_main() -> Result<()> {
    use std::io::{Read, Write};
    let path = env::args_os()
        .nth(2)
        .context("runner module path missing")?;
    let mut request = Vec::new();
    std::io::stdin()
        .take(MAX_REQUEST_BYTES as u64)
        .read_to_end(&mut request)?;
    let request: RunnerRequest =
        serde_json::from_slice(&request).context("decode runner request")?;
    let module = load_restricted_module(
        FsPath::new(&path),
        &WasmLimits {
            max_memory_pages: request.profile.wasm_memory_pages,
        },
    )?;
    let policy = sandbox::SandboxPolicy {
        address_space_bytes: 256 * 1024 * 1024,
        cpu_seconds: (request.profile.request_timeout_ms / 1000).saturating_add(1),
        open_files: 8,
    };
    let _status = sandbox::apply_runner_sandbox(&policy)?;
    let output = execute_turn(&module, request.input, &request.profile)?;
    std::io::stdout().write_all(&serde_json::to_vec(&output)?)?;
    Ok(())
}

fn healthcheck_main() -> Result<()> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};

    let port = env::var("PORT").unwrap_or_else(|_| "8080".into());
    let address = format!("127.0.0.1:{port}")
        .to_socket_addrs()?
        .next()
        .context("healthcheck address did not resolve")?;
    let timeout = Duration::from_secs(2);
    let mut stream = TcpStream::connect_timeout(&address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut response = [0u8; 64];
    let count = stream.read(&mut response)?;
    if response[..count].starts_with(b"HTTP/1.1 200") {
        Ok(())
    } else {
        bail!("scheduler health endpoint did not return HTTP 200")
    }
}

fn validate_artifacts_main() -> Result<()> {
    let profile_dir = PathBuf::from(env::var("PROFILE_DIR").unwrap_or_else(|_| "profiles".into()));
    let wasm_path = PathBuf::from(
        env::var("WASM_PATH")
            .unwrap_or_else(|_| "target/wasm32-unknown-unknown/release/bench_wasm.wasm".into()),
    );
    let profiles = load_profiles(&profile_dir)?;
    let max_pages = profiles
        .values()
        .map(|profile| profile.wasm_memory_pages)
        .max()
        .context("no profiles found")?;
    let module = load_restricted_module(
        &wasm_path,
        &WasmLimits {
            max_memory_pages: max_pages,
        },
    )?;
    let profile = profiles
        .get("realistic")
        .context("realistic profile is required")?;
    validate_runner_process(&module, profile)?;
    println!(
        "validated {} profiles, restricted WASM {}, and sandboxed runner",
        profiles.len(),
        module.sha256_hex
    );
    Ok(())
}

fn validate_runner_process(module: &LoadedModule, profile: &ExperimentProfile) -> Result<()> {
    use std::io::Write;

    let mut child = std::process::Command::new(env::current_exe()?)
        .arg("__runner")
        .arg(&module.path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawn sandbox validation runner")?;
    let request = RunnerRequest {
        input: WorkerInput {
            role: WorkerRole::Control,
            bit: 0,
            trial_id: 0,
            profile_word: 1,
        },
        profile: profile.clone(),
    };
    child
        .stdin
        .take()
        .context("sandbox validation stdin missing")?
        .write_all(&serde_json::to_vec(&request)?)?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!(
            "sandbox validation runner failed: {}",
            sanitize_error(&String::from_utf8_lossy(&output.stderr))
        );
    }
    let result: WorkerOutput = serde_json::from_slice(&output.stdout)?;
    if result.result != 0 {
        bail!("sandbox validation guest returned {}", result.result);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_files_are_valid_and_allowlisted() {
        let profiles = load_profiles(FsPath::new("../../profiles")).unwrap();
        assert_eq!(profiles.len(), 4);
        assert!(profiles.contains_key("realistic"));
    }

    #[test]
    fn hashed_token_check_rejects_wrong_value() {
        let expected = hash_token(b"correct");
        assert!(constant_time_hash_check(b"correct", &expected).is_ok());
        assert!(constant_time_hash_check(b"wrong", &expected).is_err());
    }
}
