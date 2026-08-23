#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use rhi::{
    RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform, RhiCommandV1,
    RhiRuntimeContext, parse_rhi_cli_v1_from, resolve_rhi_runtime_context, run_rhi,
};

fn main() -> ExitCode {
    let invocation = match parse_rhi_cli_v1_from(std::env::args_os()) {
        Ok(invocation) => invocation,
        Err(_) => return ExitCode::FAILURE,
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return ExitCode::FAILURE,
    };
    exit_code_from_run(runtime.block_on(execute(invocation)))
}

fn exit_code_from_run(result: Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("RHI command failed");
            ExitCode::FAILURE
        }
    }
}

async fn execute(invocation: rhi::RhiCliInvocationV1) -> Result<()> {
    let resolver = RadrootsPathResolver::new(RadrootsPlatform::current(), host_environment());
    let context = resolve_rhi_runtime_context(&resolver, &invocation)
        .map_err(|_| anyhow::anyhow!("RHI runtime context is invalid"))?;
    match invocation.command() {
        RhiCommandV1::Run => execute_run(&context).await,
        _ => bail!("RHI command execution is not available in this checkpoint"),
    }
}

async fn execute_run(context: &RhiRuntimeContext) -> Result<()> {
    let settings = rhi::config::load_settings_from_path(context.selected_config_path(), context)
        .context("load RHI configuration")?;
    init_rhi_logging(&settings)?;
    run_rhi(&settings, context).await
}

fn init_rhi_logging(settings: &rhi::config::Settings) -> Result<()> {
    use tracing_subscriber::fmt::writer::MakeWriterExt as _;

    std::fs::create_dir_all(&settings.config.logging.output_dir)
        .context("create RHI log directory")?;
    let appender = tracing_appender::rolling::daily(&settings.config.logging.output_dir, "rhi.log");
    let (writer, guard) = tracing_appender::non_blocking(appender);
    static LOG_GUARD: std::sync::OnceLock<tracing_appender::non_blocking::WorkerGuard> =
        std::sync::OnceLock::new();
    let filter = tracing_subscriber::EnvFilter::new(&settings.config.logging.filter);
    if settings.config.logging.stdout {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(writer.and(std::io::stdout))
            .try_init()
            .map_err(|_| anyhow::anyhow!("initialize RHI logging"))?;
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(writer)
            .try_init()
            .map_err(|_| anyhow::anyhow!("initialize RHI logging"))?;
    }
    LOG_GUARD
        .set(guard)
        .map_err(|_| anyhow::anyhow!("RHI logging is already initialized"))
}

fn host_environment() -> RadrootsHostEnvironment {
    let path = |name| {
        std::env::var_os(name)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    };
    RadrootsHostEnvironment {
        home_dir: path("HOME"),
        xdg_config_home: path("XDG_CONFIG_HOME"),
        xdg_data_home: path("XDG_DATA_HOME"),
        xdg_state_home: path("XDG_STATE_HOME"),
        xdg_cache_home: path("XDG_CACHE_HOME"),
        xdg_runtime_dir: path("XDG_RUNTIME_DIR"),
        appdata_dir: path("APPDATA"),
        localappdata_dir: path("LOCALAPPDATA"),
    }
}

#[cfg(test)]
mod tests {
    use super::exit_code_from_run;
    use std::process::ExitCode;

    #[test]
    fn process_result_is_stable() {
        assert_eq!(exit_code_from_run(Ok(())), ExitCode::SUCCESS);
        assert_eq!(
            exit_code_from_run(Err(anyhow::anyhow!("secret path"))),
            ExitCode::FAILURE
        );
    }
}
