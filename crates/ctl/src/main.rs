use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, anyhow, bail};
use clap::{Parser, Subcommand, ValueEnum};
use iroh::{Endpoint, SecretKey};
use remoc::robs::{RecvError, hash_map::HashMapEvent};
use serde::Deserialize;
use toml_file_refs::{ConfigLoader, LoadError};
use tracing_subscriber::EnvFilter;
use tunnelrs_proto::{
    ADMIN_ALPN, Admin, AdminClient, AdminSession, ConnectorId, ConnectorInfo, DbId, Enrollment,
    Hostname, Liveness, RouteInfo, RouteStatus, RouteSubscription, RouteView, ServerAddr, TlsMode,
    Watch, bind_endpoint, consume_session, load_or_create_secret_key,
};

#[derive(Parser)]
#[command(name = "tunnelrs-ctl", about = "Administer a tunnelrs server")]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Print this key's public ID for the server's [[admin_keys]]")]
    Id,
    #[command(flatten)]
    Remote(RemoteCommand),
}

#[derive(Subcommand)]
enum RemoteCommand {
    #[command(about = "Print route changes as they happen, until ctrl-c")]
    Watch,
    #[command(flatten)]
    Admin(AdminCommand),
}

#[derive(Subcommand)]
enum AdminCommand {
    #[command(about = "List connectors with enrollment, grants and sessions")]
    List,
    #[command(about = "Approve a connector; without --hosts it gets what it requested")]
    Approve {
        #[arg(value_parser = parse_connector_id)]
        id: ConnectorId,
        #[arg(long = "hosts", value_name = "PATTERN")]
        hosts: Vec<String>,
        #[arg(long = "tls", value_enum)]
        tls: Vec<TlsArg>,
    },
    #[command(about = "Deny a connector and close its sessions")]
    Deny {
        #[arg(value_parser = parse_connector_id)]
        id: ConnectorId,
    },
    #[command(about = "Revoke a connector's grant and close its sessions")]
    Revoke {
        #[arg(value_parser = parse_connector_id)]
        id: ConnectorId,
    },
    #[command(about = "Drop a stored offline route so its hostname is free again")]
    Forget { hostname: Hostname },
    #[command(about = "Show route status per hostname and pool size")]
    Routes,
}

#[derive(Clone, Copy, ValueEnum)]
enum TlsArg {
    Terminate,
    Passthrough,
}

impl From<TlsArg> for TlsMode {
    fn from(arg: TlsArg) -> Self {
        match arg {
            TlsArg::Terminate => TlsMode::Terminate,
            TlsArg::Passthrough => TlsMode::Passthrough,
        }
    }
}

fn parse_connector_id(text: &str) -> Result<ConnectorId, String> {
    text.parse()
        .map_err(|err| format!("invalid connector id: {err}"))
}

#[derive(Deserialize)]
struct KeyConfig {
    key_path: Option<String>,
}

#[derive(Deserialize)]
struct Config {
    key_path: Option<String>,
    server: ServerAddr,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let config_path = match cli.config {
        Some(path) => path,
        None => config_dir()?.join("tunnelrs").join("ctl.toml"),
    };
    let command = match cli.command {
        Command::Id => {
            let key = load_key(key_config(&config_path)?.key_path)?;
            println!("{}", key.public());
            return Ok(());
        }
        Command::Remote(command) => command,
    };
    let config: Config = ConfigLoader::new().load(&config_path)?;
    let key = load_key(config.key_path)?;
    let endpoint = bind_endpoint(key, &config.server.relays, None, vec![], None).await?;
    let result = execute(&endpoint, &config.server, command).await;
    endpoint.close().await;
    result
}

fn key_config(path: &Path) -> anyhow::Result<KeyConfig> {
    match ConfigLoader::new().load(path) {
        Ok(config) => Ok(config),
        Err(LoadError::ReadConfig { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(KeyConfig { key_path: None })
        }
        Err(err) => Err(err.into()),
    }
}

fn load_key(key_path: Option<String>) -> anyhow::Result<SecretKey> {
    let path = match key_path {
        Some(path) => expand_home(&path)?,
        None => config_dir()?.join("tunnelrs").join("ctl.key"),
    };
    load_or_create_secret_key(&path)
}

fn home_dir() -> anyhow::Result<PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .context("HOME is not set")
}

fn config_dir() -> anyhow::Result<PathBuf> {
    match std::env::var_os("XDG_CONFIG_HOME").filter(|dir| !dir.is_empty()) {
        Some(dir) => Ok(PathBuf::from(dir)),
        None => Ok(home_dir()?.join(".config")),
    }
}

fn expand_home(path: &str) -> anyhow::Result<PathBuf> {
    if path == "~" {
        home_dir()
    } else if let Some(rest) = path.strip_prefix("~/") {
        Ok(home_dir()?.join(rest))
    } else {
        Ok(PathBuf::from(path))
    }
}

async fn execute(
    endpoint: &Endpoint,
    server: &ServerAddr,
    command: RemoteCommand,
) -> anyhow::Result<()> {
    tracing::debug!(server = %server.id, "connecting");
    let conn = endpoint
        .connect(server.endpoint_addr(), ADMIN_ALPN)
        .await
        .with_context(|| format!("connecting to server {}", server.id))?;
    let session = consume_session::<AdminSession>(&conn).await?;
    match (command, session) {
        (RemoteCommand::Watch, session) => tokio::select! {
            result = watch(&session) => result,
            signal = tokio::signal::ctrl_c() => signal.context("waiting for ctrl-c"),
        },
        (RemoteCommand::Admin(command), AdminSession::Admin(admin)) => {
            admin_command(&admin, command).await
        }
        (RemoteCommand::Admin(_), AdminSession::Watch(_)) => {
            bail!("this key has the watcher role")
        }
    }
}

async fn admin_command(admin: &AdminClient, command: AdminCommand) -> anyhow::Result<()> {
    match command {
        AdminCommand::List => print_connectors(&admin.list().await?),
        AdminCommand::Approve { id, hosts, tls } => {
            let hosts = (!hosts.is_empty()).then_some(hosts);
            let tls_modes = (!tls.is_empty()).then(|| tls.into_iter().map(TlsMode::from).collect());
            admin.approve(id, hosts, tls_modes).await?;
            println!("approved {id}");
        }
        AdminCommand::Deny { id } => {
            admin.deny(id).await?;
            println!("denied {id}");
        }
        AdminCommand::Revoke { id } => {
            admin.revoke(id).await?;
            println!("revoked {id}");
        }
        AdminCommand::Forget { hostname } => {
            admin.forget(hostname.clone()).await?;
            println!("forgot {hostname}");
        }
        AdminCommand::Routes => print_routes(&admin.routes().await?),
    }
    Ok(())
}

fn print_connectors(connectors: &[ConnectorInfo]) {
    if connectors.is_empty() {
        println!("no connectors");
        return;
    }
    let rows = connectors
        .iter()
        .map(|info| {
            vec![
                info.id.to_string(),
                enrollment_name(info.enrollment).to_owned(),
                info.sessions.to_string(),
                join_or_dash(&info.patterns),
                info.tls_modes
                    .as_ref()
                    .map_or_else(|| "any".to_owned(), |modes| tls_list(modes)),
                join_or_dash(&info.requested),
            ]
        })
        .collect();
    print_table(
        &[
            "ID",
            "ENROLLMENT",
            "SESSIONS",
            "PATTERNS",
            "TLS",
            "REQUESTED",
        ],
        rows,
    );
}

fn print_routes(routes: &[RouteInfo]) {
    let route_rows: Vec<Vec<String>> = routes
        .iter()
        .filter_map(|route| {
            route.view.as_ref().map(|view| {
                vec![
                    route.hostname.clone(),
                    tls_name(view.tls).to_owned(),
                    liveness_text(view.liveness),
                    pool_size(view).to_string(),
                    members_text(view),
                ]
            })
        })
        .collect();
    let claim_rows: Vec<Vec<String>> = routes
        .iter()
        .flat_map(|route| {
            route
                .claims
                .iter()
                .filter(|claim| claim.status != RouteStatus::Accepted)
                .map(|claim| {
                    let (status, reason) = status_parts(&claim.status);
                    vec![
                        route.hostname.clone(),
                        claim.connector.to_string(),
                        status.to_owned(),
                        reason,
                    ]
                })
        })
        .collect();
    match (route_rows.is_empty(), claim_rows.is_empty()) {
        (true, true) => println!("no routes"),
        (false, true) => print_table(&["HOSTNAME", "TLS", "STATE", "POOL", "MEMBERS"], route_rows),
        (true, false) => print_table(&["HOSTNAME", "CONNECTOR", "STATUS", "REASON"], claim_rows),
        (false, false) => {
            print_table(&["HOSTNAME", "TLS", "STATE", "POOL", "MEMBERS"], route_rows);
            println!();
            print_table(&["HOSTNAME", "CONNECTOR", "STATUS", "REASON"], claim_rows);
        }
    }
}

fn print_table(headers: &[&str], rows: Vec<Vec<String>>) {
    let mut widths: Vec<usize> = headers
        .iter()
        .map(|header| header.chars().count())
        .collect();
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let header_row: Vec<String> = headers.iter().map(|header| (*header).to_owned()).collect();
    for row in std::iter::once(&header_row).chain(&rows) {
        let mut line = String::new();
        for (cell, width) in row.iter().zip(&widths) {
            line.push_str(cell);
            line.extend(std::iter::repeat_n(' ', width - cell.chars().count() + 2));
        }
        println!("{}", line.trim_end());
    }
}

async fn subscribe(session: &AdminSession) -> anyhow::Result<(DbId, RouteSubscription)> {
    Ok(match session {
        AdminSession::Admin(admin) => admin.subscribe().await?,
        AdminSession::Watch(watch) => watch.subscribe().await?,
    })
}

async fn watch(session: &AdminSession) -> anyhow::Result<()> {
    let mut mirror: BTreeMap<Hostname, RouteView> = BTreeMap::new();
    let mut current_db: Option<DbId> = None;
    loop {
        let (db_id, mut subscription) = subscribe(session).await?;
        if current_db.as_ref() != Some(&db_id) {
            println!("database {}", db_id.0);
            current_db = Some(db_id);
        }
        let initial = match initial_routes(&mut subscription).await {
            Ok(initial) => initial,
            Err(RecvError::Lagged) => continue,
            Err(err) => return Err(anyhow!("route stream failed: {err}")),
        };
        let removed: Vec<Hostname> = mirror
            .keys()
            .filter(|hostname| !initial.contains_key(*hostname))
            .cloned()
            .collect();
        for hostname in removed {
            mirror.remove(&hostname);
            print_removed(&hostname);
        }
        for (hostname, view) in initial {
            apply_set(&mut mirror, hostname, view);
        }
        loop {
            match subscription.recv().await {
                Ok(Some(HashMapEvent::Set(hostname, view))) => {
                    apply_set(&mut mirror, hostname, view)
                }
                Ok(Some(HashMapEvent::Remove(hostname))) => {
                    if mirror.remove(&hostname).is_some() {
                        print_removed(&hostname);
                    }
                }
                Ok(Some(HashMapEvent::Clear)) => {
                    for hostname in std::mem::take(&mut mirror).into_keys() {
                        print_removed(&hostname);
                    }
                }
                Ok(Some(HashMapEvent::Done) | None) => bail!("server ended the route stream"),
                Ok(Some(HashMapEvent::ShrinkToFit | HashMapEvent::InitialComplete)) => {}
                Err(RecvError::Lagged) => break,
                Err(err) => return Err(anyhow!("route stream failed: {err}")),
            }
        }
    }
}

async fn initial_routes(
    subscription: &mut RouteSubscription,
) -> Result<BTreeMap<Hostname, RouteView>, RecvError> {
    if let Some(initial) = subscription.take_initial() {
        return Ok(initial.into_iter().collect());
    }
    let mut initial = BTreeMap::new();
    while !subscription.is_complete() {
        match subscription.recv().await? {
            Some(HashMapEvent::Set(hostname, view)) => {
                initial.insert(hostname, view);
            }
            Some(HashMapEvent::Remove(hostname)) => {
                initial.remove(&hostname);
            }
            Some(HashMapEvent::Clear) => initial.clear(),
            Some(HashMapEvent::Done) | None => return Err(RecvError::Closed),
            Some(HashMapEvent::ShrinkToFit | HashMapEvent::InitialComplete) => {}
        }
    }
    Ok(initial)
}

fn apply_set(mirror: &mut BTreeMap<Hostname, RouteView>, hostname: Hostname, view: RouteView) {
    let marker = match mirror.get(&hostname) {
        Some(previous) if *previous == view => return,
        Some(_) => '~',
        None => '+',
    };
    println!(
        "{marker} {hostname} tls={} state={} pool={} members={}",
        tls_name(view.tls),
        liveness_text(view.liveness).replace(' ', "-"),
        pool_size(&view),
        members_text(&view),
    );
    mirror.insert(hostname, view);
}

fn print_removed(hostname: &str) {
    println!("- {hostname} withdrawn");
}

fn enrollment_name(enrollment: Enrollment) -> &'static str {
    match enrollment {
        Enrollment::Pending => "pending",
        Enrollment::Approved => "approved",
        Enrollment::Denied => "denied",
        Enrollment::Revoked => "revoked",
    }
}

fn tls_name(mode: TlsMode) -> &'static str {
    match mode {
        TlsMode::Terminate => "terminate",
        TlsMode::Passthrough => "passthrough",
    }
}

fn tls_list(modes: &[TlsMode]) -> String {
    if modes.is_empty() {
        return "none".to_owned();
    }
    modes
        .iter()
        .map(|mode| tls_name(*mode))
        .collect::<Vec<_>>()
        .join(",")
}

fn join_or_dash(items: &[String]) -> String {
    if items.is_empty() {
        "-".to_owned()
    } else {
        items.join(",")
    }
}

fn status_parts(status: &RouteStatus) -> (&'static str, String) {
    match status {
        RouteStatus::Accepted => ("accepted", "-".to_owned()),
        RouteStatus::Pending => ("pending", "awaiting approval".to_owned()),
        RouteStatus::Denied(reason) => ("denied", reason.clone()),
        RouteStatus::Conflict(reason) => ("conflict", reason.clone()),
    }
}

fn liveness_text(liveness: Liveness) -> String {
    match liveness {
        Liveness::Live => "live".to_owned(),
        Liveness::Offline { since_unix } => format!("offline {}", age(since_unix)),
    }
}

fn age(since_unix: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let seconds = now.saturating_sub(since_unix);
    let (days, hours, minutes) = (seconds / 86_400, seconds / 3_600 % 24, seconds / 60 % 60);
    if days > 0 {
        format!("{days}d{hours}h")
    } else if hours > 0 {
        format!("{hours}h{minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m{}s", seconds % 60)
    } else {
        format!("{seconds}s")
    }
}

fn pool_size(view: &RouteView) -> u32 {
    view.members.iter().map(|member| member.sessions).sum()
}

fn members_text(view: &RouteView) -> String {
    if view.members.is_empty() {
        return "-".to_owned();
    }
    view.members
        .iter()
        .map(|member| format!("{}({})", member.connector, member.sessions))
        .collect::<Vec<_>>()
        .join(",")
}
