use std::fmt::Write;

use kube::core::{GroupVersion, GroupVersionKind, gvk::ParseGroupVersionError};
use serde_json::{Map, Value, json};

#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("missing string field `{0}`")]
    Missing(&'static str),
    #[error(transparent)]
    ApiVersion(#[from] ParseGroupVersionError),
}

#[derive(Debug, Clone)]
pub struct Template {
    gvk: GroupVersionKind,
    body: Map<String, Value>,
}

pub struct Vars<'a> {
    pub host: &'a str,
    pub service: &'a str,
    pub port: u16,
    pub name: &'a str,
}

impl Vars<'_> {
    fn write(&self, var: &str, out: &mut String) -> bool {
        match var {
            "host" => out.push_str(self.host),
            "service" => out.push_str(self.service),
            "name" => out.push_str(self.name),
            "port" => {
                let _ = write!(out, "{}", self.port);
            }
            _ => return false,
        }
        true
    }
}

impl Template {
    pub fn parse(mut body: Map<String, Value>) -> Result<Self, TemplateError> {
        let api_version = take_string(&mut body, "apiVersion")?;
        let kind = take_string(&mut body, "kind")?;
        let gvk = api_version.parse::<GroupVersion>()?.with_kind(&kind);
        Ok(Self { gvk, body })
    }

    pub fn builtin(name: &str) -> Option<Self> {
        let (gvk, spec) = match name {
            "ingress" => (
                GroupVersionKind::gvk("networking.k8s.io", "v1", "Ingress"),
                json!({
                    "rules": [{
                        "host": "${host}",
                        "http": {
                            "paths": [{
                                "path": "/",
                                "pathType": "Prefix",
                                "backend": {
                                    "service": {
                                        "name": "${service}",
                                        "port": { "number": "${port}" }
                                    }
                                }
                            }]
                        }
                    }]
                }),
            ),
            "traefik-ingressroute" => (
                GroupVersionKind::gvk("traefik.io", "v1alpha1", "IngressRoute"),
                json!({
                    "entryPoints": ["websecure"],
                    "routes": [{
                        "match": "Host(`${host}`)",
                        "kind": "Rule",
                        "services": [{ "name": "${service}", "port": "${port}" }]
                    }]
                }),
            ),
            "traefik-ingressroutetcp" => (
                GroupVersionKind::gvk("traefik.io", "v1alpha1", "IngressRouteTCP"),
                json!({
                    "entryPoints": ["websecure"],
                    "routes": [{
                        "match": "HostSNI(`${host}`)",
                        "services": [{ "name": "${service}", "port": "${port}" }]
                    }],
                    "tls": { "passthrough": true }
                }),
            ),
            "gateway-tlsroute" => (
                GroupVersionKind::gvk("gateway.networking.k8s.io", "v1alpha2", "TLSRoute"),
                json!({
                    "hostnames": ["${host}"],
                    "rules": [{
                        "backendRefs": [{ "name": "${service}", "port": "${port}" }]
                    }]
                }),
            ),
            _ => return None,
        };
        Some(Self {
            gvk,
            body: Map::from_iter([("spec".to_owned(), spec)]),
        })
    }

    pub fn gvk(&self) -> &GroupVersionKind {
        &self.gvk
    }

    pub fn render(&self, vars: &Vars) -> Value {
        let mut object = self.body.clone();
        object
            .values_mut()
            .for_each(|value| substitute(value, vars));
        object.insert("apiVersion".to_owned(), self.gvk.api_version().into());
        object.insert("kind".to_owned(), self.gvk.kind.clone().into());
        Value::Object(object)
    }
}

fn take_string(body: &mut Map<String, Value>, key: &'static str) -> Result<String, TemplateError> {
    match body.remove(key) {
        Some(Value::String(value)) => Ok(value),
        _ => Err(TemplateError::Missing(key)),
    }
}

fn substitute(value: &mut Value, vars: &Vars) {
    if value.as_str() == Some("${port}") {
        *value = Value::from(vars.port);
        return;
    }
    match value {
        Value::String(text) if text.contains("${") => *text = expand(text, vars),
        Value::Array(items) => items.iter_mut().for_each(|item| substitute(item, vars)),
        Value::Object(fields) => fields.values_mut().for_each(|item| substitute(item, vars)),
        _ => {}
    }
}

fn expand(text: &str, vars: &Vars) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let tail = &rest[start + 2..];
        match tail.find('}') {
            Some(end) if vars.write(&tail[..end], &mut out) => rest = &tail[end + 1..],
            _ => {
                out.push_str("${");
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars() -> Vars<'static> {
        Vars {
            host: "app.example.com",
            service: "tunnelrs",
            port: 8443,
            name: "app-example-com-12345678",
        }
    }

    #[test]
    fn substitutes_string_values_only() {
        let body = json!({
            "apiVersion": "example.com/v1",
            "kind": "Route",
            "spec": {
                "${host}": "${name}",
                "port": "${port}",
                "url": "https://${host}:${port}/${unknown}",
                "list": ["${service}", 7, true]
            }
        });
        let Value::Object(body) = body else {
            panic!("template body is an object")
        };
        let rendered = Template::parse(body).unwrap().render(&vars());
        assert_eq!(
            rendered,
            json!({
                "apiVersion": "example.com/v1",
                "kind": "Route",
                "spec": {
                    "${host}": "app-example-com-12345678",
                    "port": 8443,
                    "url": "https://app.example.com:8443/${unknown}",
                    "list": ["tunnelrs", 7, true]
                }
            })
        );
    }

    #[test]
    fn template_requires_api_version_and_kind() {
        let Value::Object(body) = json!({ "kind": "Route" }) else {
            panic!("template body is an object")
        };
        assert!(matches!(
            Template::parse(body),
            Err(TemplateError::Missing("apiVersion"))
        ));
    }
}
