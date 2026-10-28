use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use iroh::{EndpointId, RelayUrl};
use serde::Deserialize;

const DEFAULT_OFFLINE_EXPIRY_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub key_path: PathBuf,
    pub database: PathBuf,
    pub http_listen: SocketAddr,
    pub tls_listen: SocketAddr,
    #[serde(default = "default_offline_expiry_secs")]
    pub offline_expiry_secs: u64,
    #[serde(default)]
    pub iroh: IrohConfig,
    #[serde(default)]
    pub admin_keys: Vec<AdminKey>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IrohConfig {
    pub bind: Option<SocketAddr>,
    #[serde(default)]
    pub relays: Vec<RelayUrl>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminKey {
    pub id: EndpointId,
    pub role: Role,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Watcher,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        Ok(toml_file_refs::ConfigLoader::new().load(path)?)
    }
}

fn default_offline_expiry_secs() -> u64 {
    DEFAULT_OFFLINE_EXPIRY_SECS
}
