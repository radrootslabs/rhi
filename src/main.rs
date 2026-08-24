#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::path::PathBuf;
use std::process::ExitCode;

use rhi::{
    RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform, parse_rhi_cli_v1_from,
    plan_rhi_cli_v1, resolve_rhi_runtime_context,
};

fn main() -> ExitCode {
    let invocation = match parse_rhi_cli_v1_from(std::env::args_os()) {
        Ok(invocation) => invocation,
        Err(_) => return ExitCode::FAILURE,
    };
    exit_code_from_run(execute(invocation))
}

fn exit_code_from_run(result: Result<(), ()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("RHI command failed");
            ExitCode::FAILURE
        }
    }
}

fn execute(invocation: rhi::RhiCliInvocationV1) -> Result<(), ()> {
    let _plan = plan_rhi_cli_v1(&invocation);
    let resolver = RadrootsPathResolver::new(RadrootsPlatform::current(), host_environment());
    let _context = resolve_rhi_runtime_context(&resolver, &invocation).map_err(|_| ())?;
    Err(())
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
    use super::{execute, exit_code_from_run};
    use rhi::parse_rhi_cli_v1_from;
    use std::process::ExitCode;

    #[test]
    fn process_result_is_stable() {
        assert_eq!(exit_code_from_run(Ok(())), ExitCode::SUCCESS);
        assert_eq!(exit_code_from_run(Err(())), ExitCode::FAILURE);
    }

    #[test]
    fn admitted_command_fails_closed_without_creating_runtime_state() {
        let root = tempfile::tempdir().expect("temporary repo-local root");
        let invocation = parse_rhi_cli_v1_from([
            "rhi",
            "--profile",
            "repo-local",
            "--instance",
            "default",
            "--repo-local-root",
            root.path().to_str().expect("UTF-8 test root"),
            "run",
        ])
        .expect("valid invocation");

        assert_eq!(execute(invocation), Err(()));
        assert_eq!(
            std::fs::read_dir(root.path()).expect("read root").count(),
            0
        );
    }
}
