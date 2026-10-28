use std::{
    collections::{BTreeMap, btree_map::Entry},
    path::{Path, PathBuf},
};

use anyhow::{Context, bail, ensure};
use serde::Deserialize;
use toml_file_refs::ConfigLoader;
use tunnelrs_proto::{
    Exposure, Hostname, MAX_HOSTNAME_LEN, MAX_META_BYTES, Meta, ServerAddr, TlsMode,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    key_path: PathBuf,
    server: ServerAddr,
    #[serde(default)]
    expose: Vec<ExposeEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExposeEntry {
    hostname: String,
    backend: String,
    tls: TlsMode,
    #[serde(default)]
    meta: Meta,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub exposure: Exposure,
    pub backend: String,
}

pub type Targets = BTreeMap<Hostname, Target>;

#[derive(Debug, Clone)]
pub struct Settings {
    pub key_path: PathBuf,
    pub server: ServerAddr,
    pub targets: Targets,
}

pub fn load(path: &Path) -> anyhow::Result<Settings> {
    let file: FileConfig = ConfigLoader::new()
        .load(path)
        .with_context(|| format!("loading {}", path.display()))?;
    validate(file, path.parent().unwrap_or(Path::new("")))
}

fn validate(file: FileConfig, base: &Path) -> anyhow::Result<Settings> {
    let mut targets = Targets::new();
    for item in file.expose {
        let hostname = normalize_hostname(&item.hostname);
        ensure!(!hostname.is_empty(), "expose: hostname must not be empty");
        ensure!(
            hostname.len() <= MAX_HOSTNAME_LEN,
            "expose {hostname}: hostname is longer than {MAX_HOSTNAME_LEN} bytes"
        );
        validate_backend(&item.backend).with_context(|| format!("expose {hostname}"))?;
        let meta_bytes = meta_size(&item.meta);
        ensure!(
            meta_bytes <= MAX_META_BYTES,
            "expose {hostname}: meta is {meta_bytes} bytes, the limit is {MAX_META_BYTES}"
        );
        match targets.entry(hostname) {
            Entry::Occupied(existing) => {
                bail!(
                    "expose {}: hostname is listed more than once",
                    existing.key()
                )
            }
            Entry::Vacant(slot) => {
                let exposure = Exposure {
                    hostname: slot.key().clone(),
                    tls: item.tls,
                    meta: item.meta,
                };
                slot.insert(Target {
                    exposure,
                    backend: item.backend,
                });
            }
        }
    }
    Ok(Settings {
        key_path: base.join(file.key_path),
        server: file.server,
        targets,
    })
}

fn validate_backend(backend: &str) -> anyhow::Result<()> {
    let (host, port) = backend
        .rsplit_once(':')
        .with_context(|| format!("backend {backend:?} is not host:port"))?;
    ensure!(!host.is_empty(), "backend {backend:?} has no host");
    port.parse::<u16>()
        .with_context(|| format!("backend {backend:?} has an invalid port"))?;
    Ok(())
}

fn meta_size(meta: &Meta) -> usize {
    meta.iter()
        .map(|(key, value)| key.len() + value.len())
        .sum()
}

pub fn normalize_hostname(hostname: &str) -> Hostname {
    hostname.trim_end_matches('.').to_ascii_lowercase()
}

pub fn announcement(targets: &Targets) -> Vec<Exposure> {
    targets
        .values()
        .map(|target| target.exposure.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(expose: Vec<ExposeEntry>) -> FileConfig {
        FileConfig {
            key_path: PathBuf::from("connector.key"),
            server: ServerAddr {
                id: iroh::SecretKey::generate().public(),
                relays: Vec::new(),
                addrs: Vec::new(),
            },
            expose,
        }
    }

    fn entry(hostname: &str, meta: Meta) -> ExposeEntry {
        ExposeEntry {
            hostname: hostname.to_owned(),
            backend: "backend.default.svc:8080".to_owned(),
            tls: TlsMode::Terminate,
            meta,
        }
    }

    #[test]
    fn hostnames_are_normalized_before_the_uniqueness_check() {
        let settings = validate(
            file(vec![entry("App.Example.com.", Meta::new())]),
            Path::new("/etc/tunnelrs"),
        )
        .unwrap();
        assert_eq!(settings.targets.len(), 1);
        assert_eq!(
            settings.targets["app.example.com"].exposure.hostname,
            "app.example.com"
        );
        assert_eq!(
            settings.key_path,
            PathBuf::from("/etc/tunnelrs/connector.key")
        );

        let duplicate = file(vec![
            entry("app.example.com", Meta::new()),
            entry("APP.example.com.", Meta::new()),
        ]);
        assert!(validate(duplicate, Path::new("/")).is_err());
    }

    #[test]
    fn meta_size_counts_keys_and_values() {
        let at_limit = Meta::from([("k".to_owned(), "v".repeat(MAX_META_BYTES - 1))]);
        assert!(validate(file(vec![entry("a.example.com", at_limit)]), Path::new("/")).is_ok());

        let over_limit = Meta::from([("k".to_owned(), "v".repeat(MAX_META_BYTES))]);
        assert!(
            validate(
                file(vec![entry("a.example.com", over_limit)]),
                Path::new("/")
            )
            .is_err()
        );
    }

    #[test]
    fn backends_need_a_host_and_a_port() {
        let mut missing_port = entry("a.example.com", Meta::new());
        missing_port.backend = "localhost".to_owned();
        assert!(validate(file(vec![missing_port]), Path::new("/")).is_err());

        let mut bad_port = entry("a.example.com", Meta::new());
        bad_port.backend = "localhost:http".to_owned();
        assert!(validate(file(vec![bad_port]), Path::new("/")).is_err());
    }
}
