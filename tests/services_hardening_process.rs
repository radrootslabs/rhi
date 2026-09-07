#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    collections::BTreeSet,
    fs,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt as _,
    path::PathBuf,
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use nostr::{Keys, SecretKey};
use rhi::{
    RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform, parse_rhi_cli_v1_from,
    resolve_rhi_runtime_context,
};
use sha2::{Digest as _, Sha256};
use tungstenite::{Error as WebSocketError, Message, accept};

const CONFIG_EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const PROCESS_QUALIFICATION_CONTRACT: &str =
    include_str!("../contracts/services_hardening/process_qualification.v1.json");
const FAILURE_QUALIFICATION_CONTRACT: &[u8] =
    include_bytes!("../contracts/services_hardening/failure_qualification.v1.json");
const SOURCE_LOCK: &str = include_str!("../radroots.service.source-lock.v3.toml");
const PROCESS_DEADLINE: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(2);
const CONNECT_DEADLINE_MILLISECONDS: u64 = 5_000;
const RELAY_HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(5_000);
const RELAY_IO_TIMEOUT: Duration = Duration::from_millis(100);
const PARALLEL_INSPECTIONS: usize = 8;
const SOAK_ITERATIONS: usize = 32;
const MAXIMUM_STDOUT_BYTES: usize = 1_048_576;
const MAXIMUM_STDERR_BYTES: usize = 8_192;
#[cfg(target_os = "linux")]
const PROCESS_TEMPORARY_ROOT: &str = "/tmp";
#[cfg(target_os = "macos")]
const PROCESS_TEMPORARY_ROOT: &str = "/private/tmp";

struct RelayHarness {
    address: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl RelayHarness {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("test relay listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking test relay");
        let address = listener.local_addr().expect("test relay address");
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let mut sessions = Vec::new();
            while !thread_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let session_stop = Arc::clone(&thread_stop);
                        sessions.push(thread::spawn(move || relay_session(stream, &session_stop)));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("test relay accept failed: {error}"),
                }
            }
            for session in sessions {
                session.join().expect("test relay session");
            }
        });
        Self {
            address,
            stop,
            thread: Some(thread),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("ws://{}/{path}", self.address)
    }
}

impl Drop for RelayHarness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("test relay");
        }
    }
}

fn relay_session(stream: TcpStream, stop: &AtomicBool) {
    stream
        .set_read_timeout(Some(RELAY_HANDSHAKE_TIMEOUT))
        .expect("relay handshake read timeout");
    stream
        .set_write_timeout(Some(RELAY_HANDSHAKE_TIMEOUT))
        .expect("relay handshake write timeout");
    let mut websocket = match accept(stream) {
        Ok(websocket) => websocket,
        Err(_) => return,
    };
    websocket
        .get_mut()
        .set_read_timeout(Some(RELAY_IO_TIMEOUT))
        .expect("relay read timeout");
    websocket
        .get_mut()
        .set_write_timeout(Some(RELAY_IO_TIMEOUT))
        .expect("relay write timeout");
    while !stop.load(Ordering::SeqCst) {
        let message = match websocket.read() {
            Ok(message) => message,
            Err(WebSocketError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(WebSocketError::ConnectionClosed | WebSocketError::AlreadyClosed) => break,
            Err(_) => break,
        };
        match message {
            Message::Text(text) => relay_text(&mut websocket, text.as_str()),
            Message::Ping(bytes) => {
                if websocket.send(Message::Pong(bytes)).is_err() {
                    break;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
}

fn relay_text(websocket: &mut tungstenite::WebSocket<TcpStream>, text: &str) {
    let Ok(message) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    let Some(parts) = message.as_array() else {
        return;
    };
    match parts.first().and_then(serde_json::Value::as_str) {
        Some("REQ") => {
            let Some(subscription) = parts.get(1).and_then(serde_json::Value::as_str) else {
                return;
            };
            let response = serde_json::json!(["EOSE", subscription]).to_string();
            let _ = websocket.send(Message::Text(response.into()));
        }
        Some("EVENT") => {
            let Some(event_id) = parts
                .get(1)
                .and_then(|event| event.get("id"))
                .and_then(serde_json::Value::as_str)
            else {
                return;
            };
            let response = serde_json::json!(["OK", event_id, true, ""]).to_string();
            let _ = websocket.send(Message::Text(response.into()));
        }
        _ => {}
    }
}

struct ProcessFixture {
    root: tempfile::TempDir,
    config: PathBuf,
    runtime: rhi::RhiRuntimeContext,
}

impl ProcessFixture {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("rhi-")
            .tempdir_in(PROCESS_TEMPORARY_ROOT)
            .expect("short repo-local root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("secure repo-local root");
        let config = root.path().join("rhi.toml");
        let invocation = parse_rhi_cli_v1_from([
            "rhi",
            "--profile",
            "repo-local",
            "--instance",
            "primary",
            "--repo-local-root",
            root.path().to_str().expect("UTF-8 test root"),
            "--config",
            config.to_str().expect("UTF-8 config path"),
            "run",
        ])
        .expect("runtime invocation");
        let runtime = resolve_rhi_runtime_context(
            &RadrootsPathResolver::new(
                RadrootsPlatform::current(),
                RadrootsHostEnvironment::default(),
            ),
            &invocation,
        )
        .expect("runtime context");
        Self {
            root,
            config,
            runtime,
        }
    }

    fn command(&self, command: &[&str]) -> Command {
        let mut process = Command::new(env!("CARGO_BIN_EXE_rhi"));
        process
            .args(["--profile", "repo-local", "--instance", "primary"])
            .arg("--repo-local-root")
            .arg(self.root.path())
            .arg("--config")
            .arg(&self.config)
            .args(command)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        process
    }

    fn run(&self, command: &[&str]) -> Output {
        BoundedProcess::spawn(self.command(command)).wait()
    }

    fn run_with_stdin(&self, command: &[&str], bytes: &[u8]) -> Output {
        let mut process = self.command(command);
        process.stdin(Stdio::piped());
        let mut child = BoundedProcess::spawn(process);
        child
            .child
            .stdin
            .take()
            .expect("process stdin")
            .write_all(bytes)
            .expect("bounded stdin");
        child.wait()
    }
}

struct BoundedProcess {
    child: Child,
    stdout_reader: Option<thread::JoinHandle<Vec<u8>>>,
    stderr_reader: Option<thread::JoinHandle<Vec<u8>>>,
    completed: bool,
}

impl BoundedProcess {
    fn spawn(mut command: Command) -> Self {
        let child = command.spawn().expect("RHI process");
        Self::from_child(child)
    }

    fn from_child(mut child: Child) -> Self {
        let stdout = child.stdout.take().expect("captured process stdout");
        let stderr = child.stderr.take().expect("captured process stderr");
        Self {
            child,
            stdout_reader: Some(read_bounded(stdout, MAXIMUM_STDOUT_BYTES)),
            stderr_reader: Some(read_bounded(stderr, MAXIMUM_STDERR_BYTES)),
            completed: false,
        }
    }

    fn id(&self) -> u32 {
        self.child.id()
    }

    fn try_wait(&mut self) -> Option<ExitStatus> {
        self.child.try_wait().expect("poll RHI process")
    }

    fn collect(&mut self, status: ExitStatus) -> Output {
        self.completed = true;
        let stdout = self
            .stdout_reader
            .take()
            .expect("stdout reader available")
            .join()
            .expect("join stdout reader");
        let stderr = self
            .stderr_reader
            .take()
            .expect("stderr reader available")
            .join()
            .expect("join stderr reader");
        assert!(stdout.len() <= MAXIMUM_STDOUT_BYTES);
        assert!(stderr.len() <= MAXIMUM_STDERR_BYTES);
        Output {
            status,
            stdout,
            stderr,
        }
    }

    fn wait(mut self) -> Output {
        let deadline = Instant::now() + PROCESS_DEADLINE;
        loop {
            if let Some(status) = self.try_wait() {
                return self.collect(status);
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let status = self.child.wait().expect("reap RHI process");
                let output = self.collect(status);
                panic!("RHI process exceeded deadline: {:?}", output.stderr);
            }
            thread::sleep(POLL_INTERVAL);
        }
    }
}

impl Drop for BoundedProcess {
    fn drop(&mut self) {
        if !self.completed {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(reader) = self.stdout_reader.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
    }
}

fn read_bounded(
    reader: impl std::io::Read + Send + 'static,
    maximum_bytes: usize,
) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let limit = u64::try_from(maximum_bytes)
            .expect("output bound fits u64")
            .checked_add(1)
            .expect("output bound plus sentinel fits u64");
        let mut output = Vec::with_capacity(maximum_bytes.min(8_192));
        reader
            .take(limit)
            .read_to_end(&mut output)
            .expect("read bounded process output");
        output
    })
}

fn identity_secret() -> [u8; 32] {
    let mut candidate: [u8; 32] =
        Sha256::digest(b"radroots.rhi.step-213.process-identity.v1").into();
    while SecretKey::from_slice(&candidate).is_err() {
        candidate = Sha256::digest(candidate).into();
    }
    candidate
}

fn provisioning_document(secret: [u8; 32]) -> [u8; 117] {
    let mut document = [0_u8; 117];
    document[..4].copy_from_slice(b"RHIP");
    document[4] = 1;
    document[5..37].copy_from_slice(&secret);
    document[37..69].copy_from_slice(&Sha256::digest(b"rhi-step-213-data-key"));
    document[69..93].copy_from_slice(&[3; 24]);
    document[93..117].copy_from_slice(&[4; 24]);
    document
}

fn configuration(
    fixture: &ProcessFixture,
    expected_public_key: &str,
    primary_relay: &str,
    secondary_relay: &str,
) -> String {
    CONFIG_EXAMPLE
        .replace(
            "/var/lib/radroots/services/rhi/default/secrets/service.identity.ncrypt",
            fixture
                .runtime
                .identity_path()
                .to_str()
                .expect("UTF-8 identity path"),
        )
        .replace(&"2".repeat(64), expected_public_key)
        .replace("wss://relay.example.com/", primary_relay)
        .replace("wss://relay-secondary.example.com/", secondary_relay)
        .replace(
            "connect_deadline_ms = 10000",
            &format!("connect_deadline_ms = {CONNECT_DEADLINE_MILLISECONDS}"),
        )
        .replace("request_deadline_ms = 15000", "request_deadline_ms = 1000")
}

fn diagnostic_code(output: &Output) -> String {
    let value: serde_json::Value = serde_json::from_slice(&output.stderr).expect("diagnostic JSON");
    value["code"].as_str().expect("diagnostic code").to_owned()
}

fn assert_success(output: &Output) {
    assert_eq!(output.status.code(), Some(0), "stderr: {:?}", output.stderr);
    assert_eq!(diagnostic_code(output), "success");
}

fn bootstrap(fixture: &ProcessFixture, configuration: &str, secret: [u8; 32]) -> String {
    let expected_public_key = Keys::new(SecretKey::from_slice(&secret).expect("secret"))
        .public_key()
        .to_hex();
    let config = fixture.run_with_stdin(&["config", "init"], configuration.as_bytes());
    assert_success(&config);
    assert_eq!(config.stdout, b"config_initialized\n");

    for directory in [
        fixture.runtime.context().paths().state(),
        fixture.runtime.context().paths().secrets(),
        fixture.runtime.context().paths().run(),
    ] {
        fs::create_dir_all(directory).expect("secure runtime directory");
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .expect("secure runtime mode");
    }
    let credential = fixture
        .runtime
        .context()
        .paths()
        .secrets()
        .join("service_wrapping_key");
    fs::write(&credential, Sha256::digest(b"rhi-step-213-wrapping-key"))
        .expect("wrapping credential");
    fs::set_permissions(&credential, fs::Permissions::from_mode(0o600)).expect("credential mode");

    let state = fixture.run(&["state", "init"]);
    assert_success(&state);
    assert_eq!(state.stdout, b"state_initialized\n");
    let identity = fixture.run_with_stdin(
        &["--output", "json", "identity", "init"],
        &provisioning_document(secret),
    );
    assert_success(&identity);
    let identity_value: serde_json::Value =
        serde_json::from_slice(&identity.stdout).expect("identity result");
    assert_eq!(identity_value["public_key"], expected_public_key);

    for command in [
        &["config", "validate"][..],
        &["state", "verify"][..],
        &["state", "migrate"][..],
    ] {
        assert_success(&fixture.run(command));
    }
    expected_public_key
}

fn wait_for_live_status(fixture: &ProcessFixture, daemon: &mut BoundedProcess) -> Output {
    let deadline = Instant::now() + PROCESS_DEADLINE;
    let mut last_diagnostic = Vec::new();
    loop {
        if let Some(status) = daemon.try_wait() {
            let output = daemon.collect(status);
            panic!(
                "RHI daemon exited before admin became ready: {status}; stderr={:?}",
                output.stderr
            );
        }
        if fixture.runtime.artifacts().admin_socket().exists() {
            let status = fixture.run(&["status"]);
            if status.status.success() {
                return status;
            }
            last_diagnostic = status.stderr;
        }
        if Instant::now() >= deadline {
            panic!(
                "RHI admin did not become ready before deadline; socket={}; stderr={last_diagnostic:?}",
                fixture.runtime.artifacts().admin_socket().exists()
            );
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn interrupt_and_wait(daemon: BoundedProcess) -> Output {
    let signal = Command::new("/bin/kill")
        .arg("-INT")
        .arg(daemon.id().to_string())
        .status()
        .expect("send interrupt");
    assert!(signal.success());
    daemon.wait()
}

#[test]
fn process_qualification_contract_freezes_the_exact_wave_closure() {
    let contract: serde_json::Value =
        serde_json::from_str(PROCESS_QUALIFICATION_CONTRACT).expect("process contract");
    assert_eq!(
        contract
            .as_object()
            .expect("process contract object")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "actual_process_corpus",
            "binary",
            "bounds",
            "component_qualification",
            "contract_version",
            "deferred",
            "invariants",
            "schema",
            "service",
            "source_lock",
            "step",
        ])
    );
    assert_eq!(contract["schema"], "radroots.rhi.process-qualification.v1");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["step"], 215);
    assert_eq!(contract["service"], "rhi");
    assert_eq!(contract["binary"], "rhi");
    assert_eq!(
        contract["source_lock"],
        serde_json::json!({
            "schema": "radroots.service.source-lock.v2",
            "lib_revision": "053d0c750bf9cd683c6ea37cefe7e79617ba629f"
        })
    );
    assert_eq!(
        contract["component_qualification"],
        serde_json::json!({
            "schema": "radroots.rhi.failure-qualification.v1",
            "step": 214,
            "sha256": "f05da8e559f463f99c67c3c7e22eafa57935be91fb0094f2aa2f98a58544b8b9"
        })
    );
    assert_eq!(
        contract["bounds"],
        serde_json::json!({
            "process_deadline_ms": 30_000,
            "poll_interval_ms": 2,
            "connect_deadline_ms": 5_000,
            "relay_handshake_timeout_ms": 5_000,
            "relay_io_timeout_ms": 100,
            "parallel_inspection_processes": 8,
            "soak_iterations": 32,
            "maximum_stdout_bytes": 1_048_576,
            "maximum_stderr_bytes": 8_192
        })
    );
    assert_eq!(
        PROCESS_DEADLINE,
        Duration::from_millis(
            contract["bounds"]["process_deadline_ms"]
                .as_u64()
                .expect("process deadline"),
        )
    );
    assert_eq!(
        POLL_INTERVAL,
        Duration::from_millis(
            contract["bounds"]["poll_interval_ms"]
                .as_u64()
                .expect("poll interval"),
        )
    );
    assert_eq!(
        RELAY_HANDSHAKE_TIMEOUT,
        Duration::from_millis(
            contract["bounds"]["relay_handshake_timeout_ms"]
                .as_u64()
                .expect("relay handshake timeout"),
        )
    );
    assert_eq!(
        RELAY_IO_TIMEOUT,
        Duration::from_millis(
            contract["bounds"]["relay_io_timeout_ms"]
                .as_u64()
                .expect("relay timeout"),
        )
    );
    assert_eq!(
        CONNECT_DEADLINE_MILLISECONDS,
        contract["bounds"]["connect_deadline_ms"]
    );
    assert_eq!(
        u64::try_from(PARALLEL_INSPECTIONS).expect("inspection bound"),
        contract["bounds"]["parallel_inspection_processes"]
    );
    assert_eq!(
        u64::try_from(SOAK_ITERATIONS).expect("soak bound"),
        contract["bounds"]["soak_iterations"]
    );
    assert_eq!(
        u64::try_from(MAXIMUM_STDOUT_BYTES).expect("stdout bound"),
        contract["bounds"]["maximum_stdout_bytes"]
    );
    assert_eq!(
        u64::try_from(MAXIMUM_STDERR_BYTES).expect("stderr bound"),
        contract["bounds"]["maximum_stderr_bytes"]
    );
    assert_eq!(
        contract["actual_process_corpus"],
        serde_json::json!([
            "actual_binary_executes_offline_bootstrap_and_reaches_real_runtime_dependency_boundary",
            "actual_binary_runs_the_task_graph_serves_admin_and_shuts_down_on_interrupt",
            "actual_binary_is_bounded_under_parallel_inspection_and_reopen_soak"
        ])
    );
    assert_eq!(
        contract["invariants"],
        serde_json::json!({
            "actual_executable_required": true,
            "loopback_relay_only": true,
            "production_failpoint_surface": false,
            "test_environment_selector": false,
            "detached_test_worker": false,
            "parallel_inspection_is_read_only": true,
            "every_daemon_is_interrupted_joined_and_reaped": true,
            "admin_socket_absent_after_shutdown": true,
            "state_verifies_after_every_reopen": true,
            "captured_output_bounded": true,
            "diagnostics_path_secret_free": true
        })
    );
    assert_eq!(
        contract["deferred"],
        serde_json::json!([
            "native_release_artifacts_step_216",
            "rcld_promotion_step_217",
            "parent_pin_alignment_step_217",
            "nix",
            "oci",
            "signing",
            "publication",
            "deployment"
        ])
    );
    assert_eq!(
        lower_hex(&Sha256::digest(FAILURE_QUALIFICATION_CONTRACT)),
        contract["component_qualification"]["sha256"]
    );
    assert!(SOURCE_LOCK.contains("revision = \"055096853fca95e15d0f813d33a14aca13be3881\""));
}

#[test]
fn actual_binary_executes_offline_bootstrap_and_reaches_real_runtime_dependency_boundary() {
    let fixture = ProcessFixture::new();
    let secret = identity_secret();
    let expected_public_key = Keys::new(SecretKey::from_slice(&secret).expect("secret"))
        .public_key()
        .to_hex();
    let configuration = configuration(
        &fixture,
        &expected_public_key,
        "ws://127.0.0.1:9/",
        "ws://127.0.0.1:10/",
    );
    bootstrap(&fixture, &configuration, secret);

    let run = fixture.run(&["run"]);
    assert_eq!(run.status.code(), Some(3));
    assert!(run.stdout.is_empty());
    assert_eq!(diagnostic_code(&run), "service_or_dependency_unavailable");
    let diagnostic = String::from_utf8(run.stderr).expect("diagnostic UTF-8");
    assert!(!diagnostic.contains(fixture.root.path().to_str().expect("UTF-8 root")));
    assert!(!diagnostic.contains("relay.example"));
    assert!(!diagnostic.contains("service_wrapping_key"));
}

#[test]
fn actual_binary_runs_the_task_graph_serves_admin_and_shuts_down_on_interrupt() {
    let relay = RelayHarness::start();
    let fixture = ProcessFixture::new();
    let secret = identity_secret();
    let expected_public_key = Keys::new(SecretKey::from_slice(&secret).expect("secret"))
        .public_key()
        .to_hex();
    let configuration = configuration(
        &fixture,
        &expected_public_key,
        &relay.url("primary"),
        &relay.url("secondary"),
    );
    bootstrap(&fixture, &configuration, secret);

    let mut daemon = BoundedProcess::spawn(fixture.command(&["run"]));
    let status = wait_for_live_status(&fixture, &mut daemon);
    assert_success(&status);
    let status_value: serde_json::Value =
        serde_json::from_slice(&status.stdout).expect("live status JSON");
    assert_eq!(status_value["service"], "rhi");
    assert_eq!(status_value["phase"], "ready");
    assert_eq!(status_value["ready"], true);
    assert_eq!(status_value["persistence"]["schema_version"], 11);

    let shutdown = interrupt_and_wait(daemon);
    assert_success(&shutdown);
    assert!(shutdown.stdout.is_empty());
    assert!(!fixture.runtime.artifacts().admin_socket().exists());
}

#[test]
fn actual_binary_is_bounded_under_parallel_inspection_and_reopen_soak() {
    let fixture = ProcessFixture::new();
    let secret = identity_secret();
    let expected_public_key = Keys::new(SecretKey::from_slice(&secret).expect("secret"))
        .public_key()
        .to_hex();
    let configuration = configuration(
        &fixture,
        &expected_public_key,
        "ws://127.0.0.1:9/",
        "ws://127.0.0.1:10/",
    );
    bootstrap(&fixture, &configuration, secret);

    let inspections = (0..PARALLEL_INSPECTIONS)
        .map(|_| BoundedProcess::spawn(fixture.command(&["config", "validate"])))
        .collect::<Vec<_>>();
    for inspection in inspections {
        assert_success(&inspection.wait());
    }

    for _ in 0..SOAK_ITERATIONS {
        assert_success(&fixture.run(&["state", "verify"]));
    }
    assert!(!fixture.runtime.artifacts().admin_socket().exists());
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}
