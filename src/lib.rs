#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod adapters;
pub mod cli;
pub mod config;
pub mod features;
pub mod host_identity;
pub mod host_nostr;
pub mod host_paths;
pub mod host_runtime;
pub mod identity_storage;
pub mod paths;
pub mod rhi;

pub use cli::Args as cli_args;

use anyhow::{Context, Result, anyhow, bail};
use radroots_event::{
    envelope::kind::TRADE_MUTATION_EVENT_KINDS,
    profile::{AuthoredProfile, Nip05Identifier},
};
use std::time::Duration;

use crate::features::trade_agreement_attestation::{
    TradeAgreementAttestationRuntime, TradeAgreementAttestationRuntimeConfig,
    trade_mutation_subscription_kinds,
};
use crate::host_nostr::{ApplicationHandlerSpec, Metadata, ProfileBuilder};
use crate::identity_storage::load_service_identity;
use crate::rhi::{Rhi, start_subscriber_with_policy};
use radroots_nostr::event::{build_application_handler, build_profile};
use tracing::{info, warn};

#[cfg(test)]
static RUN_RHI_AUTO_STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static RUN_RHI_SKIP_SUBSCRIBER: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
static RUN_RHI_BOOTSTRAP_HOOK: std::sync::OnceLock<std::sync::Mutex<Option<Result<(), String>>>> =
    std::sync::OnceLock::new();

#[derive(Clone, Copy)]
enum RunRhiWaitOutcome {
    Shutdown,
    Stopped,
}

#[cfg(test)]
static RUN_RHI_WAIT_HOOK: std::sync::OnceLock<std::sync::Mutex<Option<RunRhiWaitOutcome>>> =
    std::sync::OnceLock::new();

#[cfg(test)]
fn run_rhi_bootstrap_hook() -> &'static std::sync::Mutex<Option<Result<(), String>>> {
    RUN_RHI_BOOTSTRAP_HOOK.get_or_init(|| std::sync::Mutex::new(None))
}

#[cfg(test)]
fn run_rhi_wait_hook() -> &'static std::sync::Mutex<Option<RunRhiWaitOutcome>> {
    RUN_RHI_WAIT_HOOK.get_or_init(|| std::sync::Mutex::new(None))
}

#[cfg(test)]
fn take_bootstrap_hook_result() -> Option<Result<(), String>> {
    run_rhi_bootstrap_hook()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
}

#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn take_bootstrap_hook_result() -> Option<Result<(), String>> {
    None
}

async fn bootstrap_presence(
    client: &crate::host_nostr::Client,
    metadata: &Metadata,
    handler_spec: &ApplicationHandlerSpec,
) -> Result<()> {
    if let Some(result) = take_bootstrap_hook_result() {
        return result.map_err(anyhow::Error::msg);
    }

    client.connect().await;
    client.wait_for_connection(Duration::from_secs(5)).await;

    let profile_event = build_authored_service_profile_event(metadata)?
        .sign_with_keys(client.keys())
        .context("sign strict RHI service Profile")?;
    client
        .send_event(&profile_event)
        .await
        .context("publish strict RHI service Profile")?;

    let handler_event = build_application_handler(handler_spec)
        .context("build RHI application-handler event")?
        .sign_with_keys(client.keys())
        .context("sign RHI application-handler event")?;
    client
        .send_event(&handler_event)
        .await
        .context("publish RHI application-handler event")?;
    Ok(())
}

fn build_authored_service_profile_event(metadata: &Metadata) -> Result<ProfileBuilder> {
    let profile = authored_service_profile(metadata)?;
    build_profile(&profile).context("build strict RHI service Profile event")
}

fn authored_service_profile(metadata: &Metadata) -> Result<AuthoredProfile> {
    if metadata.picture.is_some() || metadata.banner.is_some() {
        bail!(
            "RHI service Profile media requires byte-verified Blossom descriptors and proven BUD-02 upload completion"
        );
    }
    if metadata.website.is_some() || metadata.lud06.is_some() || metadata.lud16.is_some() {
        bail!("RHI service Profile contains fields outside the strict authored contract");
    }

    let name = metadata
        .name
        .clone()
        .ok_or_else(|| anyhow!("RHI service Profile requires metadata.name"))?;
    let mut profile =
        AuthoredProfile::new(name).context("validate strict RHI service Profile name")?;
    if let Some(display_name) = metadata.display_name.as_ref() {
        profile = profile.with_display_name(display_name.clone());
    }
    if let Some(about) = metadata.about.as_ref() {
        profile = profile.with_about(about.clone());
    }
    if let Some(nip05) = metadata.nip05.as_deref() {
        profile = profile.with_nip05(
            Nip05Identifier::parse(nip05)
                .context("validate strict RHI service Profile NIP-05 identifier")?,
        );
    }

    for key in metadata.custom.keys() {
        if key != "bot" {
            bail!("RHI service Profile contains unsupported metadata field `{key}`");
        }
    }
    if let Some(bot) = metadata.custom.get("bot") {
        profile = profile.with_bot(
            bot.as_bool()
                .ok_or_else(|| anyhow!("RHI service Profile `bot` field must be a Boolean"))?,
        );
    }

    Ok(profile)
}

#[cfg_attr(coverage_nightly, coverage(off))]
async fn wait_for_shutdown_or_stopped(handle: crate::rhi::RhiHandle) -> RunRhiWaitOutcome {
    #[cfg(test)]
    if let Some(outcome) = run_rhi_wait_hook()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
    {
        return outcome;
    }

    tokio::select! {
        _ = crate::host_runtime::shutdown_signal() => RunRhiWaitOutcome::Shutdown,
        _ = handle.stopped() => RunRhiWaitOutcome::Stopped,
    }
}

pub async fn run_rhi(settings: &config::Settings, args: &cli_args) -> Result<()> {
    let identity = load_service_identity(
        args.service.identity.as_deref(),
        args.service.allow_generate_identity,
    )?;
    let keys = identity.keys().clone();
    let agreement_attestation_runtime =
        TradeAgreementAttestationRuntime::load(TradeAgreementAttestationRuntimeConfig {
            state_path: settings.config.subscriber.state.path.clone(),
            replay_window_secs: settings.config.subscriber.state.replay_window_secs,
            replay_overlap_secs: settings.config.subscriber.state.replay_overlap_secs,
        })
        .await?;

    let rhi = Rhi::with_agreement_attestation_runtime_and_policy(
        keys.clone(),
        agreement_attestation_runtime,
        settings.config.trade_agreement_attestation.clone(),
    );
    let client = rhi.client.clone();
    let service_cfg = settings.config.service.clone();
    let relays = service_cfg.relays.clone();

    for relay in &relays {
        client.add_relay(relay).await?;
    }

    let md = settings.metadata.clone();

    if !relays.is_empty() {
        let handler_kinds = trade_mutation_subscription_kinds();
        let mut handler_spec = ApplicationHandlerSpec::new(handler_kinds)
            .with_metadata(md.clone())
            .with_extra_tags(service_cfg.nip89_extra_tags.clone())
            .with_relays(relays.clone());
        if let Some(identifier) = service_cfg.nip89_identifier.clone() {
            handler_spec = handler_spec.with_identifier(identifier);
        }
        if let Err(e) = bootstrap_presence(&client, &md, &handler_spec).await {
            warn!("Failed to publish service presence on startup: {e}");
        } else {
            info!("Published service presence on startup");
        }
    }

    #[cfg(test)]
    if RUN_RHI_SKIP_SUBSCRIBER.load(std::sync::atomic::Ordering::Relaxed) {
        return Ok(());
    }

    let handle = start_subscriber_with_policy(
        client.clone(),
        keys.clone(),
        rhi.agreement_attestation_runtime.clone(),
        rhi.agreement_attestation_policy.clone(),
        settings.config.subscriber.backoff.clone(),
    )
    .await;

    let stop_handle = handle.clone();

    #[cfg(test)]
    if RUN_RHI_AUTO_STOP.load(std::sync::atomic::Ordering::Relaxed) {
        stop_handle.stop();
    }

    match wait_for_shutdown_or_stopped(handle).await {
        RunRhiWaitOutcome::Shutdown => {
            info!("Shutting down");
            stop_handle.stop();
        }
        RunRhiWaitOutcome::Stopped => {}
    }

    let sdk_client = client.into_inner();
    sdk_client.unsubscribe_all().await;
    sdk_client.disconnect().await;

    Ok(())
}

pub fn release_product_handler_kinds() -> &'static [u32] {
    &TRADE_MUTATION_EVENT_KINDS
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        RUN_RHI_AUTO_STOP, RUN_RHI_SKIP_SUBSCRIBER, RunRhiWaitOutcome, authored_service_profile,
        bootstrap_presence, build_authored_service_profile_event, release_product_handler_kinds,
        run_rhi, run_rhi_bootstrap_hook, run_rhi_wait_hook,
    };
    use crate::{cli_args, config};
    use radroots_event::envelope::kind::TRADE_MUTATION_EVENT_KINDS;
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;
    use tokio::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::const_new(());

    async fn test_guard() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().await;
        RUN_RHI_AUTO_STOP.store(false, Ordering::Relaxed);
        RUN_RHI_SKIP_SUBSCRIBER.store(false, Ordering::Relaxed);
        *run_rhi_bootstrap_hook()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        *run_rhi_wait_hook()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        guard
    }

    fn settings_with_relays(relays: Vec<String>) -> config::Settings {
        config::Settings {
            metadata: serde_json::from_str(r#"{"name":"rhi-test"}"#).expect("metadata"),
            config: config::Configuration {
                service: crate::host_runtime::NostrServiceConfig {
                    logs_dir: std::env::temp_dir()
                        .join("rhi-test-logs")
                        .display()
                        .to_string(),
                    relays,
                    nip89_identifier: Some("rhi".to_string()),
                    nip89_extra_tags: Vec::new(),
                },
                logging: config::LoggingConfig {
                    output_dir: std::env::temp_dir().join("rhi-test-logs"),
                    filter: "info".to_string(),
                    stdout: true,
                },
                subscriber: config::SubscriberConfig {
                    backoff: crate::host_runtime::BackoffConfig {
                        base_ms: 1,
                        max_ms: 2,
                        factor: 1,
                        jitter_ms: 0,
                    },
                    state: config::SubscriberStateConfig {
                        path: unique_state_path("settings"),
                        ..Default::default()
                    },
                },
                trade_agreement_attestation:
                    crate::features::trade_agreement_attestation::TradeAgreementAttestationPolicy::default(),
            },
        }
    }

    fn args_for_identity(path: PathBuf) -> cli_args {
        cli_args {
            command: None,
            service: crate::host_runtime::ServiceCliArgs {
                config: Some(PathBuf::from("config.toml")),
                identity: Some(path),
                allow_generate_identity: true,
            },
        }
    }

    fn unique_identity_path(suffix: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("rhi-{suffix}-{nanos}.secret.json"))
    }

    fn unique_state_path(suffix: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir()
            .join(format!("rhi-state-{suffix}-{nanos}"))
            .join("state.json")
    }

    #[tokio::test]
    async fn run_rhi_starts_and_stops_without_relays() {
        let _guard = test_guard().await;
        RUN_RHI_AUTO_STOP.store(true, Ordering::Relaxed);
        let identity_path = unique_identity_path("no-relays");
        let args = args_for_identity(identity_path);
        let settings = settings_with_relays(Vec::new());
        run_rhi(&settings, &args).await.expect("run rhi");
    }

    #[tokio::test]
    async fn run_rhi_bootstraps_release_product_handler_kinds_when_relays_exist() {
        let _guard = test_guard().await;
        RUN_RHI_SKIP_SUBSCRIBER.store(true, Ordering::Relaxed);
        *run_rhi_bootstrap_hook()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Ok(()));
        let identity_path = unique_identity_path("relays");
        let args = args_for_identity(identity_path);
        let settings = settings_with_relays(vec!["wss://relay.example.com".to_string()]);
        run_rhi(&settings, &args).await.expect("run rhi");
        assert_eq!(release_product_handler_kinds(), TRADE_MUTATION_EVENT_KINDS);
    }

    #[tokio::test]
    async fn run_rhi_stops_on_wait_hook() {
        let _guard = test_guard().await;
        *run_rhi_wait_hook()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(RunRhiWaitOutcome::Stopped);
        let identity_path = unique_identity_path("wait-hook");
        let args = args_for_identity(identity_path);
        let settings = settings_with_relays(Vec::new());
        run_rhi(&settings, &args).await.expect("run rhi");
    }

    #[tokio::test]
    async fn bootstrap_presence_reports_hook_error() {
        let _guard = test_guard().await;
        *run_rhi_bootstrap_hook()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(Err("forced bootstrap failure".to_string()));
        let keys = crate::host_nostr::Keys::generate();
        let client = crate::host_nostr::Client::new(keys.clone());
        let metadata: crate::host_nostr::Metadata =
            serde_json::from_str(r#"{"name":"rhi-test"}"#).expect("metadata");
        let spec =
            crate::host_nostr::ApplicationHandlerSpec::new(TRADE_MUTATION_EVENT_KINDS.to_vec())
                .with_identifier("rhi")
                .with_metadata(metadata.clone());
        let err = bootstrap_presence(&client, &metadata, &spec)
            .await
            .expect_err("forced error");
        assert!(format!("{err:#}").contains("forced bootstrap failure"));
    }

    #[test]
    fn service_profile_uses_only_strict_authored_fields() {
        let metadata: crate::host_nostr::Metadata = serde_json::from_str(
            r#"{
                "name":"rhi",
                "display_name":"Radroots agreement attestation",
                "about":"Attests trade agreement projections",
                "nip05":"rhi@EXAMPLE.COM",
                "bot":true
            }"#,
        )
        .expect("metadata");

        let profile = authored_service_profile(&metadata).expect("strict profile");

        assert_eq!(profile.name(), "rhi");
        assert_eq!(
            profile.display_name(),
            Some("Radroots agreement attestation")
        );
        assert_eq!(profile.about(), Some("Attests trade agreement projections"));
        assert_eq!(
            profile.nip05().map(|identifier| identifier.as_str()),
            Some("rhi@example.com")
        );
        assert_eq!(profile.bot(), Some(true));
        assert!(profile.picture().is_none());
        assert!(profile.banner().is_none());

        let keys = crate::host_nostr::Keys::generate();
        let event = build_authored_service_profile_event(&metadata)
            .expect("strict Profile event")
            .sign_with_keys(&keys)
            .expect("sign strict Profile event");
        assert_eq!(event.kind.as_u16(), 0);
        assert!(event.tags.is_empty());
        assert_eq!(
            event.content,
            r#"{"name":"rhi","display_name":"Radroots agreement attestation","about":"Attests trade agreement projections","nip05":"rhi@example.com","bot":true}"#
        );
    }

    #[test]
    fn service_profile_rejects_unverified_media_and_unsupported_fields() {
        for (metadata, expected) in [
            (
                r#"{"name":"rhi","picture":"https://cdn.example/rhi.png"}"#,
                "byte-verified Blossom descriptors",
            ),
            (
                r#"{"name":"rhi","website":"https://radroots.org"}"#,
                "outside the strict authored contract",
            ),
            (
                r#"{"name":"rhi","bot":"yes"}"#,
                "`bot` field must be a Boolean",
            ),
            (
                r#"{"name":"rhi","legacy_role":"worker"}"#,
                "unsupported metadata field `legacy_role`",
            ),
            (r#"{}"#, "requires metadata.name"),
            (
                r#"{"name":"rhi","nip05":"RHI@example.com"}"#,
                "validate strict RHI service Profile NIP-05 identifier",
            ),
        ] {
            let metadata = serde_json::from_str(metadata).expect("metadata");
            let error = authored_service_profile(&metadata).expect_err("must fail closed");
            assert!(format!("{error:#}").contains(expected), "{error:#}");
        }
    }
}
