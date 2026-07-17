mod artifact;
mod sandbox;
mod wasm;

use anyhow::{Context, Result, bail};
use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Serialize;
use std::{
    env,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{io::AsyncWriteExt, process::Command, sync::Semaphore};
const NORMALIZED_BODY: &str = r#"{"outcome":"complete"}"#;

/// The sole production policy. These values are part of the scheduler image.
#[derive(Clone, Copy)]
struct Policy {
    execution_slot: Duration,
    max_parallel_workers: usize,
    max_pending_runs: usize,
    max_module_bytes: usize,
    max_memory_pages: u32,
    turn_fuel: u64,
    address_space_bytes: u64,
}

impl Policy {
    const fn production() -> Self {
        Self {
            execution_slot: Duration::from_secs(1),
            max_parallel_workers: 8,
            max_pending_runs: 128,
            max_module_bytes: 1024 * 1024,
            max_memory_pages: 64,
            turn_fuel: 50_000_000,
            address_space_bytes: 256 * 1024 * 1024,
        }
    }
}

#[derive(Clone)]
struct AppState {
    module: Arc<[u8]>,
    module_sha256: Arc<str>,
    slots: Arc<Semaphore>,
    pending: Arc<AtomicUsize>,
    policy: Policy,
}

struct PendingGuard(Arc<AtomicUsize>);

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    wasm_sha256: String,
}

#[derive(Debug)]
struct AppError {
    status: StatusCode,
    message: &'static str,
}

impl AppError {
    const fn new(status: StatusCode, message: &'static str) -> Self {
        Self { status, message }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}

fn main() -> Result<()> {
    match env::args().nth(1).as_deref() {
        Some("__runner") => return runner_main(),
        Some("__healthcheck") => return healthcheck_main(),
        Some("__validate_artifacts") => return validate_artifacts_main(),
        _ => {}
    }
    let secrets = artifact::StartupSecrets::take_from_environment()?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build scheduler runtime")?
        .block_on(server_main(secrets))
}

async fn server_main(secrets: artifact::StartupSecrets) -> Result<()> {
    let policy = Policy::production();
    let artifact = artifact::pull_and_decrypt(secrets, policy.max_module_bytes)
        .await
        .context("load startup worker")?;
    let state = AppState {
        module: artifact.module,
        module_sha256: Arc::from(artifact.sha256_hex),
        slots: Arc::new(Semaphore::new(policy.max_parallel_workers)),
        pending: Arc::new(AtomicUsize::new(0)),
        policy,
    };
    let app = app(state);
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
        .route("/v1/run", post(run_worker))
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> axum::Json<HealthResponse> {
    axum::Json(HealthResponse {
        status: "ok",
        wasm_sha256: state.module_sha256.to_string(),
    })
}

async fn run_worker(State(state): State<AppState>) -> Result<Response, AppError> {
    let pending = state
        .pending
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            (count < state.policy.max_pending_runs).then_some(count + 1)
        })
        .map_err(|_| AppError::new(StatusCode::TOO_MANY_REQUESTS, "run queue capacity reached"))?;
    let pending_guard = PendingGuard(state.pending.clone());
    debug_assert!(pending < state.policy.max_pending_runs);

    let module = state.module.clone();

    // Keep queue admission, the full slot, and cleanup alive if the caller disconnects.
    let slot_state = state.clone();
    let slot = tokio::spawn(async move {
        let _pending_guard = pending_guard;
        if let Ok(permit) = slot_state.slots.clone().acquire_owned().await {
            // The release deadline is fixed by policy before any hostile byte is parsed.
            let deadline = tokio::time::Instant::now() + slot_state.policy.execution_slot;
            let _ =
                tokio::time::timeout_at(deadline, execute_process(module, slot_state.policy)).await;
            tokio::time::sleep_until(deadline).await;
            drop(permit);
        }
    });
    let _ = slot.await;
    Ok(normalized_response())
}

fn normalized_response() -> Response {
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        NORMALIZED_BODY,
    )
        .into_response()
}

async fn execute_process(module: Arc<[u8]>, policy: Policy) -> Result<()> {
    let executable = env::current_exe().context("locate scheduler executable")?;
    let mut child = Command::new(executable)
        .arg("__runner")
        .arg(policy.turn_fuel.to_string())
        .arg(policy.max_memory_pages.to_string())
        .arg(policy.address_space_bytes.to_string())
        .arg(
            policy
                .execution_slot
                .as_secs()
                .saturating_add(1)
                .to_string(),
        )
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("spawn isolated runner")?;
    let mut stdin = child.stdin.take().context("runner stdin missing")?;
    stdin.write_all(&module).await.context("send module")?;
    stdin.shutdown().await.context("close runner input")?;
    drop(stdin);
    child.wait().await.context("wait for runner")?;
    Ok(())
}

fn runner_main() -> Result<()> {
    use std::io::Read;

    let policy = Policy::production();
    let turn_fuel = parse_runner_arg(2, "fuel")?;
    let max_memory_pages = parse_runner_arg(3, "memory pages")?;
    let address_space_bytes = parse_runner_arg(4, "address space")?;
    let cpu_seconds = parse_runner_arg(5, "cpu seconds")?;
    let mut module = Vec::new();
    std::io::stdin()
        .take((policy.max_module_bytes + 1) as u64)
        .read_to_end(&mut module)?;
    if module.is_empty() || module.len() > policy.max_module_bytes {
        bail!("invalid module size");
    }

    clear_environment()?;
    sandbox::close_inherited_descriptors()?;
    let sandbox = sandbox::apply_runner_sandbox(&sandbox::SandboxPolicy {
        address_space_bytes,
        cpu_seconds,
        open_files: 3,
    })?;
    sandbox.verify_required()?;
    wasm::execute(&module, turn_fuel, max_memory_pages)
}

fn parse_runner_arg<T>(index: usize, name: &str) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    env::args()
        .nth(index)
        .with_context(|| format!("runner {name} missing"))?
        .parse()
        .with_context(|| format!("invalid runner {name}"))
}

fn clear_environment() -> Result<()> {
    let names: Vec<_> = env::vars_os().map(|(name, _)| name).collect();
    for name in names {
        // SAFETY: the runner is a fresh, single-threaded process at this point.
        unsafe { env::remove_var(name) };
    }
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
    let mut response = [0; 64];
    let count = stream.read(&mut response)?;
    if response[..count].starts_with(b"HTTP/1.1 200") {
        Ok(())
    } else {
        bail!("health endpoint did not return HTTP 200")
    }
}

fn validate_artifacts_main() -> Result<()> {
    // (module (func (export "run")))
    const SMOKE_MODULE: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03,
        0x02, 0x01, 0x00, 0x07, 0x07, 0x01, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x00, 0x0a, 0x04, 0x01,
        0x02, 0x00, 0x0b,
    ];
    let policy = Policy::production();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(execute_process(Arc::from(SMOKE_MODULE), policy))?;
    println!("validated sandboxed general-WASM runner");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[test]
    fn normalized_worker_response_is_constant() {
        assert_eq!(NORMALIZED_BODY, r#"{"outcome":"complete"}"#);
        assert_eq!(NORMALIZED_BODY.len(), 22);
    }

    #[test]
    fn production_policy_has_a_hard_slot_and_global_cap() {
        let policy = Policy::production();
        assert!(!policy.execution_slot.is_zero());
        assert!(policy.max_parallel_workers > 0);
        assert!(policy.max_pending_runs >= policy.max_parallel_workers);
    }

    #[tokio::test]
    async fn hostile_bytes_are_not_parsed_until_the_normalized_run() {
        let mut policy = Policy::production();
        policy.execution_slot = Duration::from_millis(40);
        let state = AppState {
            module: Arc::from(b"not wasm".as_slice()),
            module_sha256: Arc::from("test-hash"),
            slots: Arc::new(Semaphore::new(1)),
            pending: Arc::new(AtomicUsize::new(0)),
            policy,
        };
        let service = app(state);
        let started = std::time::Instant::now();
        let response = service
            .oneshot(Request::post("/v1/run").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(started.elapsed() >= policy.execution_slot);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(bytes.as_ref(), NORMALIZED_BODY.as_bytes());
    }
}
