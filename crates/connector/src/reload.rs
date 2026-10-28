use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use notify::{
    Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
    event::{AccessKind, AccessMode},
};
use tokio::{
    signal::unix::Signal,
    sync::{mpsc, watch},
};
use tracing::{info, warn};

use crate::config::{self, Settings, Targets};

const DEBOUNCE: Duration = Duration::from_millis(500);
const KUBERNETES_DATA_LINK: &str = "..data";

pub async fn run(
    path: PathBuf,
    mut current: Settings,
    targets: watch::Sender<Arc<Targets>>,
    mut hangup: Signal,
) {
    let (changes_tx, mut changes) = mpsc::unbounded_channel();
    let _watcher = match watch_config(&path, changes_tx) {
        Ok(watcher) => Some(watcher),
        Err(err) => {
            warn!(
                error = format!("{err:#}"),
                "cannot watch the config file; reload it with SIGHUP"
            );
            None
        }
    };
    loop {
        tokio::select! {
            Some(()) = hangup.recv() => info!("SIGHUP received; reloading configuration"),
            Some(()) = changes.recv() => {
                debounce(&mut changes).await;
                info!("config file changed; reloading configuration");
            }
            else => return,
        }
        apply(&path, &mut current, &targets);
    }
}

fn watch_config(
    path: &Path,
    changes: mpsc::UnboundedSender<()>,
) -> anyhow::Result<RecommendedWatcher> {
    let dir = path
        .parent()
        .context("config path has no parent directory")?;
    let name = path
        .file_name()
        .context("config path has no file name")?
        .to_os_string();
    let mut watcher =
        notify::recommended_watcher(move |event: notify::Result<Event>| match event {
            Ok(event) if is_config_change(&event, &name) => {
                let _ = changes.send(());
            }
            Ok(_) => {}
            Err(err) => warn!(error = %err, "config file watcher failed"),
        })?;
    watcher
        .watch(dir, RecursiveMode::NonRecursive)
        .with_context(|| format!("watching {}", dir.display()))?;
    Ok(watcher)
}

fn is_config_change(event: &Event, name: &OsStr) -> bool {
    let modifying = match event.kind {
        EventKind::Access(AccessKind::Close(AccessMode::Write)) => true,
        EventKind::Access(_) => false,
        _ => true,
    };
    modifying
        && event.paths.iter().any(|changed| {
            changed
                .file_name()
                .is_some_and(|file| file == name || file == KUBERNETES_DATA_LINK)
        })
}

async fn debounce(changes: &mut mpsc::UnboundedReceiver<()>) {
    while let Ok(Some(())) = tokio::time::timeout(DEBOUNCE, changes.recv()).await {}
}

fn apply(path: &Path, current: &mut Settings, targets: &watch::Sender<Arc<Targets>>) {
    let next = match config::load(path) {
        Ok(next) => next,
        Err(err) => {
            warn!(
                error = format!("{err:#}"),
                "invalid configuration; keeping the previous one"
            );
            return;
        }
    };
    if next.key_path != current.key_path {
        warn!(
            key_path = %next.key_path.display(),
            "key_path changed; restart the connector to apply it"
        );
    }
    if next.server != current.server {
        warn!("server address changed; restart the connector to apply it");
    }
    if next.targets == current.targets {
        info!("exposures unchanged");
        return;
    }
    info!(exposures = next.targets.len(), "exposures reloaded");
    targets.send_replace(Arc::new(next.targets.clone()));
    current.targets = next.targets;
}
