//! RHI-owned process lifecycle and retry policy.

use core::future::Future;
use core::time::Duration;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{ArgAction, Args, ValueHint};
use serde::{Deserialize, Serialize};

#[derive(Args, Debug, Clone)]
pub struct ServiceCliArgs {
    #[arg(long, value_name = "PATH", value_hint = ValueHint::FilePath)]
    pub config: Option<PathBuf>,
    #[arg(long, value_name = "PATH", value_hint = ValueHint::FilePath)]
    pub identity: Option<PathBuf>,
    #[arg(long, action = ArgAction::SetTrue)]
    pub allow_generate_identity: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NostrServiceConfig {
    pub logs_dir: String,
    #[serde(default)]
    pub relays: Vec<String>,
    #[serde(default)]
    pub nip89_identifier: Option<String>,
    #[serde(default)]
    pub nip89_extra_tags: Vec<Vec<String>>,
}

const fn default_base_ms() -> u64 {
    500
}
const fn default_max_ms() -> u64 {
    30_000
}
const fn default_factor() -> u32 {
    2
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackoffConfig {
    #[serde(default = "default_base_ms")]
    pub base_ms: u64,
    #[serde(default = "default_max_ms")]
    pub max_ms: u64,
    #[serde(default = "default_factor")]
    pub factor: u32,
    #[serde(default)]
    pub jitter_ms: u64,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            base_ms: default_base_ms(),
            max_ms: default_max_ms(),
            factor: default_factor(),
            jitter_ms: 0,
        }
    }
}

impl BackoffConfig {
    fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let base = self.base_ms.max(1);
        let max = self.max_ms.max(base);
        let factor = u64::from(self.factor.max(1));
        let mut delay = base;
        for _ in 0..attempt.saturating_sub(1).min(10) {
            delay = delay.saturating_mul(factor).min(max);
        }
        if self.jitter_ms > 0 {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos();
            delay = delay
                .saturating_add(u64::from(nanos) % (self.jitter_ms + 1))
                .min(max);
        }
        Duration::from_millis(delay)
    }
}

#[derive(Debug, Clone)]
pub struct Backoff {
    config: BackoffConfig,
    attempt: u32,
}

impl Backoff {
    pub fn new(config: BackoffConfig) -> Self {
        Self { config, attempt: 0 }
    }
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
    pub fn next_delay(&mut self) -> Duration {
        self.attempt = self.attempt.saturating_add(1);
        self.config.delay_for_attempt(self.attempt)
    }
}

pub async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl+C handler")
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install termination handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = core::future::pending::<()>();
    wait_for_shutdown(ctrl_c, terminate).await;
}

async fn wait_for_shutdown<C, T>(ctrl_c: C, terminate: T)
where
    C: Future<Output = ()>,
    T: Future<Output = ()>,
{
    tokio::select! { _ = ctrl_c => {}, _ = terminate => {} }
}
