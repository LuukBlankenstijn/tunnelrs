use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use kube::core::GroupVersionKind;
use serde::Deserialize;
use serde_json::{Map, Number, Value};
use toml_file_refs::ConfigLoader;
use tunnelrs_proto::{Meta, ServerAddr, TlsMode};

use crate::{
    patch::Patch,
    presets::{Policy, Preset},
    templates::Template,
};

const DEFAULT_GRACE_SECS: u64 = 24 * 60 * 60;

pub struct Config {
    pub key_path: PathBuf,
    pub server: ServerAddr,
    pub routing: Routing,
}

pub struct Routing {
    pub namespace: String,
    pub grace_secs: u64,
    pub service: Service,
    pub terminate: Option<Template>,
    pub passthrough: Option<Template>,
    pub presets: BTreeMap<String, Preset>,
    pub policies: Vec<Policy>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub name: String,
    pub http_port: u16,
    pub tls_port: u16,
}

impl Routing {
    pub fn template(&self, mode: TlsMode) -> Option<&Template> {
        match mode {
            TlsMode::Terminate => self.terminate.as_ref(),
            TlsMode::Passthrough => self.passthrough.as_ref(),
        }
    }

    pub fn port(&self, mode: TlsMode) -> u16 {
        match mode {
            TlsMode::Terminate => self.service.http_port,
            TlsMode::Passthrough => self.service.tls_port,
        }
    }

    pub fn kinds(&self) -> Vec<GroupVersionKind> {
        let mut kinds: Vec<GroupVersionKind> = Vec::new();
        for template in [&self.terminate, &self.passthrough].into_iter().flatten() {
            if !kinds.contains(template.gvk()) {
                kinds.push(template.gvk().clone());
            }
        }
        kinds
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    key_path: PathBuf,
    namespace: String,
    #[serde(default = "default_grace_secs")]
    grace_secs: u64,
    server: ServerAddr,
    service: Service,
    modes: RawModes,
    #[serde(default)]
    templates: BTreeMap<String, toml::Table>,
    #[serde(default)]
    presets: BTreeMap<String, RawPreset>,
    #[serde(default)]
    policy: Vec<Policy>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawModes {
    terminate: Option<RawMode>,
    passthrough: Option<RawMode>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMode {
    template: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPreset {
    modes: Vec<TlsMode>,
    #[serde(default, rename = "match")]
    matches: Meta,
    #[serde(default)]
    patch: toml::Table,
}

fn default_grace_secs() -> u64 {
    DEFAULT_GRACE_SECS
}

pub fn load(path: &Path) -> anyhow::Result<Config> {
    let raw: RawConfig = ConfigLoader::new()
        .load(path)
        .with_context(|| format!("loading config {}", path.display()))?;
    raw.compile()
}

impl RawConfig {
    fn compile(self) -> anyhow::Result<Config> {
        if self.namespace.is_empty() {
            bail!("namespace must not be empty");
        }

        let mut templates = BTreeMap::new();
        for (name, table) in self.templates {
            let template = table_to_json(table)
                .and_then(|body| Ok(Template::parse(body)?))
                .with_context(|| format!("template {name}"))?;
            templates.insert(name, template);
        }
        let resolve = |mode: Option<RawMode>, label: &str| {
            mode.map(|mode| {
                templates
                    .get(&mode.template)
                    .cloned()
                    .or_else(|| Template::builtin(&mode.template))
                    .with_context(|| format!("modes.{label}: unknown template {}", mode.template))
            })
            .transpose()
        };
        let terminate = resolve(self.modes.terminate, "terminate")?;
        let passthrough = resolve(self.modes.passthrough, "passthrough")?;
        if terminate.is_none() && passthrough.is_none() {
            bail!("configure at least one of modes.terminate and modes.passthrough");
        }

        let mut presets = BTreeMap::new();
        for (name, raw) in self.presets {
            let preset = raw.compile().with_context(|| format!("preset {name}"))?;
            presets.insert(name, preset);
        }

        for (index, policy) in self.policy.iter().enumerate() {
            if let Some(unknown) = policy
                .allow
                .iter()
                .chain(&policy.force)
                .find(|name| !presets.contains_key(*name))
            {
                bail!("policy[{index}] references unknown preset {unknown}");
            }
        }

        Ok(Config {
            key_path: self.key_path,
            server: self.server,
            routing: Routing {
                namespace: self.namespace,
                grace_secs: self.grace_secs,
                service: self.service,
                terminate,
                passthrough,
                presets,
                policies: self.policy,
            },
        })
    }
}

impl RawPreset {
    fn compile(self) -> anyhow::Result<Preset> {
        if self.modes.is_empty() {
            bail!("modes must list at least one tls mode");
        }
        let sets = self
            .patch
            .into_iter()
            .map(|(path, value)| Ok((path, toml_to_json(value)?)))
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Preset {
            modes: self.modes,
            matches: self.matches,
            patch: Patch::new(sets)?,
        })
    }
}

fn table_to_json(table: toml::Table) -> anyhow::Result<Map<String, Value>> {
    table
        .into_iter()
        .map(|(key, value)| Ok((key, toml_to_json(value)?)))
        .collect()
}

fn toml_to_json(value: toml::Value) -> anyhow::Result<Value> {
    Ok(match value {
        toml::Value::String(text) => Value::String(text),
        toml::Value::Integer(number) => Value::from(number),
        toml::Value::Float(number) => Number::from_f64(number)
            .map(Value::Number)
            .with_context(|| format!("{number} cannot be represented in JSON"))?,
        toml::Value::Boolean(flag) => Value::Bool(flag),
        toml::Value::Datetime(datetime) => Value::String(datetime.to_string()),
        toml::Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(toml_to_json)
                .collect::<anyhow::Result<_>>()?,
        ),
        toml::Value::Table(table) => Value::Object(table_to_json(table)?),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn toml_values_convert_to_json() {
        let table: toml::Table = toml::from_str(
            r#"
            apiVersion = "example.com/v1"
            kind = "Route"
            spec = { port = 8080, weight = 0.5, tags = ["a", "b"], nested = { on = true }, at = 1979-05-27T07:32:00Z }
            "#,
        )
        .unwrap();
        assert_eq!(
            Value::Object(table_to_json(table).unwrap()),
            json!({
                "apiVersion": "example.com/v1",
                "kind": "Route",
                "spec": {
                    "port": 8080,
                    "weight": 0.5,
                    "tags": ["a", "b"],
                    "nested": { "on": true },
                    "at": "1979-05-27T07:32:00Z"
                }
            })
        );
    }
}
