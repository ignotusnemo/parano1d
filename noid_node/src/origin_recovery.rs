// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Recover the canonical fork certificate without waiting for
//! another block. Peer agreement selects a byte source, never proof authority.

use super::*;

#[derive(Debug)]
pub(super) enum OriginRecoveryError {
    InvalidTerminal(String),
    Unavailable(String),
}

impl std::fmt::Display for OriginRecoveryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTerminal(error) | Self::Unavailable(error) => formatter.write_str(error),
        }
    }
}

impl OriginRecoveryError {
    pub(super) fn snapshot_outcome(
        self,
        authority: RetainedSnapshotHeaderAuthority,
    ) -> SnapshotBoundaryVerificationOutcome {
        match self {
            Self::InvalidTerminal(error) => {
                SnapshotBoundaryVerificationOutcome::TerminalRejected { error, authority }
            }
            Self::Unavailable(error) => {
                SnapshotBoundaryVerificationOutcome::OriginUnavailable { error, authority }
            }
        }
    }
}

#[derive(Default)]
pub(super) struct CanonicalOriginRecovery {
    task: Option<tokio::task::JoinHandle<()>>,
    last_attempt: Option<Instant>,
}

impl CanonicalOriginRecovery {
    pub(super) fn start(
        &mut self,
        chain: &Arc<RwLock<MdbxChainContext>>,
        runtime: Option<&Arc<noid_miner::HistoryProtocolRuntime>>,
        commands: &noid_p2p::NetworkCommandSender,
        peer: libp2p::PeerId,
        height: u64,
        hash: [u8; 32],
    ) {
        if !noid_chain::consensus::params::v2_active(height)
            || self.task.as_ref().is_some_and(|task| !task.is_finished())
            || self
                .last_attempt
                .is_some_and(|last| last.elapsed() < Duration::from_secs(5))
        {
            return;
        }
        let Some(runtime) = runtime.cloned() else {
            return;
        };
        let chain = Arc::clone(chain);
        let commands = commands.clone();
        self.last_attempt = Some(Instant::now());
        self.task = Some(tokio::spawn(async move {
            if let Err(error) = recover(chain, runtime, commands, peer, height, hash).await {
                tracing::warn!(%error, %peer, height, "canonical fork-origin recovery will retry");
            }
        }));
    }
}

impl Drop for CanonicalOriginRecovery {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn recover(
    chain: Arc<RwLock<MdbxChainContext>>,
    runtime: Arc<noid_miner::HistoryProtocolRuntime>,
    commands: noid_p2p::NetworkCommandSender,
    peer: libp2p::PeerId,
    height: u64,
    hash: [u8; 32],
) -> Result<(), String> {
    // Disk reads and decoding stay outside the P2P control loop. At most one
    // worker exists, including during retries and repeated same-tip messages.
    let local_runtime = Arc::clone(&runtime);
    let snapshot = tokio::task::spawn_blocking(move || {
        let ctx = chain.blocking_read();
        if ctx.tip_height() != height || ctx.tip_hash() != hash {
            return Ok(None);
        }
        let terminal = ctx
            .store
            .get_history_step_terminal_at(height, hash)
            .map_err(|e| e.to_string())?
            .ok_or("canonical terminal missing during fork-origin recovery")?;
        let Some(origin) = local_runtime.requested_origin(&terminal)? else {
            return Ok(None);
        };
        if local_runtime.has_verified_origin(&origin)? {
            return Ok(None);
        }
        let epoch_height = noid_chain::consensus::tx_epoch_anchor_height_for_child(height);
        let epoch = ctx
            .get_header_from_store(epoch_height)
            .map_err(|e| e.to_string())?
            .ok_or("canonical terminal epoch anchor missing during fork-origin recovery")?;
        Ok::<_, String>(Some((*ctx.tip_header(), epoch, terminal)))
    })
    .await
    .map_err(|e| e.to_string())??;
    let Some((header, epoch, terminal)) = snapshot else {
        return Ok(());
    };
    ensure_terminal_origin(&runtime, &terminal, peer, &commands)
        .await
        .map_err(|e| e.to_string())?;
    tokio::task::spawn_blocking(move || {
        noid_miner::install_inbound_verifier_cpu(|| {
            // This also persists the checked replacement. No State or header
            // is accepted from a peer's same-tip confirmation.
            runtime.verify_terminal(&terminal, &header, &epoch)
        })
        .map_err(|e| e.to_string())?
    })
    .await
    .map_err(|e| e.to_string())??;
    tracing::info!(%peer, height, "canonical fork origin recovered without advancing the tip");
    Ok(())
}

/// Authenticate the terminal's origin, upgrading an unusable local certificate
/// from the peer when needed. A local legacy-only file must not prevent a
/// retired-history build from fetching its matrix-free replacement.
pub(super) async fn ensure_terminal_origin(
    runtime: &Arc<noid_miner::HistoryProtocolRuntime>,
    terminal: &[u8],
    peer: libp2p::PeerId,
    commands: &noid_p2p::NetworkCommandSender,
) -> Result<(), OriginRecoveryError> {
    let Some(requested) = runtime
        .requested_origin(terminal)
        .map_err(OriginRecoveryError::InvalidTerminal)?
    else {
        return Ok(());
    };
    ensure_requested_origin(runtime, requested, peer, commands)
        .await
        .map_err(OriginRecoveryError::Unavailable)
}

async fn ensure_requested_origin(
    runtime: &Arc<noid_miner::HistoryProtocolRuntime>,
    requested: noid_miner::history_protocol::ForkOrigin,
    peer: libp2p::PeerId,
    commands: &noid_p2p::NetworkCommandSender,
) -> Result<(), String> {
    if runtime.has_verified_origin(&requested)? {
        return Ok(());
    }
    let local = match runtime.origin_bytes(requested.request_binding()) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(%error, "local fork-origin file unavailable; requesting a checked replacement");
            None
        }
    };
    if let Some(bytes) = local {
        let local_runtime = Arc::clone(runtime);
        let local_requested = requested.clone();
        let checked: Result<(), String> = tokio::task::spawn_blocking(move || {
            noid_miner::install_inbound_verifier_cpu(|| {
                let checked = local_runtime.install_origin_bytes(&bytes)?;
                if checked.origin() != &local_requested {
                    return Err("local fork-origin certificate does not match the terminal".into());
                }
                Ok(())
            })
            .map_err(|e| e.to_string())?
        })
        .await
        .map_err(|e| e.to_string())?;
        match checked {
            Ok(()) => return Ok(()),
            Err(error) => {
                tracing::warn!(%error, "local fork-origin certificate could not be verified; requesting a checked replacement")
            }
        }
    }
    // The local bytes have been dropped before acquiring a network allocation.
    // Fetch failure cannot grant verification or replace the retained file.
    let (reply, response) = tokio::sync::oneshot::channel();
    commands
        .send(noid_p2p::NetworkCommand::FetchForkOrigin {
            peer,
            request: requested.request_binding(),
            reply,
        })
        .await
        .map_err(|e| e.to_string())?;
    let response = tokio::time::timeout(Duration::from_secs(50), response)
        .await
        .map_err(|_| "fork-origin request timed out")?
        .map_err(|_| "fork-origin response channel closed")??;
    let runtime = Arc::clone(runtime);
    tokio::task::spawn_blocking(move || {
        noid_miner::install_inbound_verifier_cpu(|| {
            // Keep the network allocation permit until certificate checking
            // finishes. Local files have the same strict decoder and proof path.
            let encoded = response
                .bytes
                .as_deref()
                .ok_or("peer does not retain the requested fork origin")?;
            let checked = runtime.install_origin_bytes(encoded)?;
            if checked.origin() != &requested {
                return Err("fork-origin certificate does not match the terminal".into());
            }
            Ok(())
        })
        .map_err(|e| e.to_string())?
    })
    .await
    .map_err(|e| e.to_string())?
}
