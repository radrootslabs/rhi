#![forbid(unsafe_code)]

use std::process::ExitCode;

use rhi::{RhiLogRecord, RhiProcessResult};

struct RhiOsSignalSource {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
}

impl RhiOsSignalSource {
    fn new() -> Option<Self> {
        #[cfg(unix)]
        {
            let interrupt =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).ok()?;
            let terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok()?;
            Some(Self {
                interrupt,
                terminate,
            })
        }
        #[cfg(not(unix))]
        {
            Some(Self {})
        }
    }
}

impl rhi::RhiProcessSignalSource for RhiOsSignalSource {
    fn next_signal(&mut self) -> rhi::RhiProcessSignalFuture<'_> {
        #[cfg(unix)]
        {
            Box::pin(async move {
                tokio::select! {
                    observed = self.interrupt.recv() => observed.map(|()| rhi::RhiProcessSignal::Interrupt),
                    observed = self.terminate.recv() => observed.map(|()| rhi::RhiProcessSignal::Terminate),
                }
            })
        }
        #[cfg(not(unix))]
        {
            Box::pin(async move {
                tokio::signal::ctrl_c()
                    .await
                    .ok()
                    .map(|()| rhi::RhiProcessSignal::Interrupt)
            })
        }
    }
}

fn main() -> ExitCode {
    match rhi::parse_rhi_cli_v1_from(std::env::args_os()) {
        Ok(invocation) => {
            let result =
                rhi::execute_rhi_cli_v1_with_signal_source(invocation, RhiOsSignalSource::new);
            eprintln!("{}", RhiLogRecord::process_result(result));
            result.exit_code()
        }
        Err(_) => {
            let result = RhiProcessResult::InputOrConfiguration;
            eprintln!("{}", RhiLogRecord::process_result(result));
            result.exit_code()
        }
    }
}
