#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod adapters;
pub mod cli;
pub mod config;
pub mod features;
pub mod identity_storage;
pub mod paths;
pub mod rhi;

pub use cli::Args as cli_args;

use anyhow::{Context, Result, anyhow, bail};
use radroots_event::{
    kinds::TRADE_MUTATION_EVENT_KINDS,
    profile::{RadrootsAuthoredProfile, RadrootsNip05Identifier},
};
use std::time::Duration;

use crate::features::trade_agreement_attestation::{
    TradeAgreementAttestationRuntime, TradeAgreementAttestationRuntimeConfig,
    trade_mutation_subscription_kinds,
};
use crate::identity_storage::load_service_identity;
use crate::rhi::{Rhi, start_subscriber_with_policy};
use radroots_nostr::prelude::{
    RadrootsNostrApplicationHandlerSpec, RadrootsNostrMetadata, RadrootsNostrProfileEventBuilder,
    radroots_nostr_build_profile_event, radroots_nostr_publish_application_handler,
};
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
    client: &radroots_nostr::prelude::RadrootsNostrClient,
    metadata: &RadrootsNostrMetadata,
    handler_spec: &RadrootsNostrApplicationHandlerSpec,
) -> Result<()> {
    if let Some(result) = take_bootstrap_hook_result() {
        return result.map_err(anyhow::Error::msg);
    }

    client.connect().await;
    client.wait_for_connection(Duration::from_secs(5)).await;

    let builder = build_authored_service_profile_event(metadata)?;
    client
        .send_profile_event_builder(builder)
        .await
        .context("publish strict RHI service Profile")?;

    radroots_nostr_publish_application_handler(client, handler_spec)
        .await
        .context("publish RHI application-handler event")?;
    Ok(())
}

fn build_authored_service_profile_event(
    metadata: &RadrootsNostrMetadata,
) -> Result<RadrootsNostrProfileEventBuilder> {
    let profile = authored_service_profile(metadata)?;
    radroots_nostr_build_profile_event(&profile).context("build strict RHI service Profile event")
}

fn authored_service_profile(metadata: &RadrootsNostrMetadata) -> Result<RadrootsAuthoredProfile> {
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
        RadrootsAuthoredProfile::new(name).context("validate strict RHI service Profile name")?;
    if let Some(display_name) = metadata.display_name.as_ref() {
        profile = profile.with_display_name(display_name.clone());
    }
    if let Some(about) = metadata.about.as_ref() {
        profile = profile.with_about(about.clone());
    }
    if let Some(nip05) = metadata.nip05.as_deref() {
        profile = profile.with_nip05(
            RadrootsNip05Identifier::parse(nip05)
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
        _ = radroots_runtime::shutdown_signal() => RunRhiWaitOutcome::Shutdown,
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
        let handler_spec = RadrootsNostrApplicationHandlerSpec {
            kinds: handler_kinds,
            identifier: service_cfg.nip89_identifier.clone(),
            metadata: Some(md.clone()),
            extra_tags: service_cfg.nip89_extra_tags.clone(),
            relays: relays.clone(),
            nostrconnect_url: None,
        };
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
    use radroots_event::kinds::TRADE_MUTATION_EVENT_KINDS;
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_guard() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                service: radroots_runtime::RadrootsNostrServiceConfig {
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
                    backoff: radroots_runtime::BackoffConfig {
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
            service: radroots_runtime::RadrootsServiceCliArgs {
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
        let _guard = test_guard();
        RUN_RHI_AUTO_STOP.store(true, Ordering::Relaxed);
        let identity_path = unique_identity_path("no-relays");
        let args = args_for_identity(identity_path);
        let settings = settings_with_relays(Vec::new());
        run_rhi(&settings, &args).await.expect("run rhi");
    }

    #[tokio::test]
    async fn run_rhi_bootstraps_release_product_handler_kinds_when_relays_exist() {
        let _guard = test_guard();
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
        let _guard = test_guard();
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
        let _guard = test_guard();
        *run_rhi_bootstrap_hook()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(Err("forced bootstrap failure".to_string()));
        let keys = radroots_nostr::prelude::RadrootsNostrKeys::generate();
        let client = radroots_nostr::prelude::RadrootsNostrClient::new(keys.clone());
        let metadata: radroots_nostr::prelude::RadrootsNostrMetadata =
            serde_json::from_str(r#"{"name":"rhi-test"}"#).expect("metadata");
        let spec = radroots_nostr::prelude::RadrootsNostrApplicationHandlerSpec {
            kinds: TRADE_MUTATION_EVENT_KINDS.to_vec(),
            identifier: Some("rhi".to_string()),
            metadata: Some(metadata.clone()),
            extra_tags: Vec::new(),
            relays: Vec::new(),
            nostrconnect_url: None,
        };
        let err = bootstrap_presence(&client, &metadata, &spec)
            .await
            .expect_err("forced error");
        assert!(format!("{err:#}").contains("forced bootstrap failure"));
    }

    #[test]
    fn service_profile_uses_only_strict_authored_fields() {
        let metadata: radroots_nostr::prelude::RadrootsNostrMetadata = serde_json::from_str(
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

        let keys = radroots_nostr::prelude::RadrootsNostrKeys::generate();
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
