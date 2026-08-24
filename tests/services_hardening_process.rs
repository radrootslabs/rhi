#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    fs,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt as _,
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
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
const PROCESS_DEADLINE: Duration = Duration::from_secs(30);
const RELAY_IO_TIMEOUT: Duration = Duration::from_millis(100);

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
        .set_read_timeout(Some(RELAY_IO_TIMEOUT))
        .expect("relay read timeout");
    stream
        .set_write_timeout(Some(RELAY_IO_TIMEOUT))
        .expect("relay write timeout");
    let mut websocket = match accept(stream) {
        Ok(websocket) => websocket,
        Err(_) => return,
    };
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
            .tempdir_in("/private/tmp")
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
        wait_bounded(self.command(command).spawn().expect("RHI process"))
    }

    fn run_with_stdin(&self, command: &[&str], bytes: &[u8]) -> Output {
        let mut process = self.command(command);
        process.stdin(Stdio::piped());
        let mut child = process.spawn().expect("RHI process");
        child
            .stdin
            .take()
            .expect("process stdin")
            .write_all(bytes)
            .expect("bounded stdin");
        wait_bounded(child)
    }
}

fn wait_bounded(mut child: Child) -> Output {
    let deadline = Instant::now() + PROCESS_DEADLINE;
    loop {
        if child.try_wait().expect("poll RHI process").is_some() {
            let output = child.wait_with_output().expect("collect RHI process");
            assert!(output.stdout.len() <= 1_048_576);
            assert!(output.stderr.len() <= 8_192);
            return output;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().expect("reap RHI process");
            panic!("RHI process exceeded deadline: {:?}", output.stderr);
        }
        thread::sleep(Duration::from_millis(2));
    }
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
        .replace("connect_deadline_ms = 10000", "connect_deadline_ms = 100")
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

fn wait_for_live_status(fixture: &ProcessFixture, daemon: &mut Child) -> Output {
    let deadline = Instant::now() + PROCESS_DEADLINE;
    let mut last_diagnostic = Vec::new();
    loop {
        if let Some(status) = daemon.try_wait().expect("poll RHI daemon") {
            let mut stderr = Vec::new();
            daemon
                .stderr
                .take()
                .expect("RHI daemon stderr")
                .read_to_end(&mut stderr)
                .expect("read RHI daemon stderr");
            panic!("RHI daemon exited before admin became ready: {status}; stderr={stderr:?}");
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
        thread::sleep(Duration::from_millis(2));
    }
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

    let mut daemon = fixture.command(&["run"]).spawn().expect("RHI daemon");
    let status = wait_for_live_status(&fixture, &mut daemon);
    assert_success(&status);
    let status_value: serde_json::Value =
        serde_json::from_slice(&status.stdout).expect("live status JSON");
    assert_eq!(status_value["service"], "rhi");
    assert_eq!(status_value["phase"], "ready");
    assert_eq!(status_value["ready"], true);
    assert_eq!(status_value["persistence"]["schema_version"], 11);

    let signal = Command::new("/bin/kill")
        .arg("-INT")
        .arg(daemon.id().to_string())
        .status()
        .expect("send interrupt");
    assert!(signal.success());
    let shutdown = wait_bounded(daemon);
    assert_success(&shutdown);
    assert!(shutdown.stdout.is_empty());
    assert!(!fixture.runtime.artifacts().admin_socket().exists());
}
