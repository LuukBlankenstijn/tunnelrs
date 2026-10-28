use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::Deserialize;
use tunnelrs_proto::{ConnectorId, Meta, RouteView, TlsMode, host_matches};

use crate::patch::Patch;

#[derive(Debug, Clone)]
pub struct Preset {
    pub modes: Vec<TlsMode>,
    pub matches: Meta,
    pub patch: Patch,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub hosts: Option<String>,
    pub connectors: Option<Vec<ConnectorId>>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub force: Vec<String>,
}

impl Policy {
    fn governs(&self, hostname: &str, route: &RouteView) -> bool {
        self.hosts
            .as_deref()
            .is_none_or(|pattern| host_matches(pattern, hostname))
            && self.connectors.as_ref().is_none_or(|connectors| {
                route
                    .members
                    .iter()
                    .any(|member| connectors.contains(&member.connector))
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    NotAllowed { preset: String },
    UnsupportedMode { preset: String, mode: TlsMode },
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAllowed { preset } => write!(
                f,
                "preset {preset} is not allowed by the policies matching this route"
            ),
            Self::UnsupportedMode { preset, mode } => write!(
                f,
                "preset {preset} does not apply to {} routes",
                mode_name(*mode)
            ),
        }
    }
}

pub fn mode_name(mode: TlsMode) -> &'static str {
    match mode {
        TlsMode::Terminate => "terminate",
        TlsMode::Passthrough => "passthrough",
    }
}

#[derive(Debug, Default)]
pub struct Selection<'a> {
    pub apply: Vec<(&'a str, &'a Preset)>,
    pub rejected: Vec<Rejection>,
}

pub fn select<'a>(
    presets: &'a BTreeMap<String, Preset>,
    policies: &[Policy],
    hostname: &str,
    route: &RouteView,
) -> Selection<'a> {
    let mut governed = false;
    let mut allowed = BTreeSet::new();
    let mut forced = BTreeSet::new();
    for policy in policies
        .iter()
        .filter(|policy| policy.governs(hostname, route))
    {
        governed = true;
        allowed.extend(policy.allow.iter().map(String::as_str));
        forced.extend(policy.force.iter().map(String::as_str));
    }

    let mut selection = Selection::default();
    for (name, preset) in presets {
        let is_forced = forced.contains(name.as_str());
        let matched = !preset.matches.is_empty()
            && preset
                .matches
                .iter()
                .all(|(key, value)| route.meta.get(key) == Some(value));
        if !is_forced && !matched {
            continue;
        }
        if !is_forced && governed && !allowed.contains(name.as_str()) {
            selection.rejected.push(Rejection::NotAllowed {
                preset: name.clone(),
            });
        } else if !preset.modes.contains(&route.tls) {
            selection.rejected.push(Rejection::UnsupportedMode {
                preset: name.clone(),
                mode: route.tls,
            });
        } else {
            selection.apply.push((name.as_str(), preset));
        }
    }
    selection
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;
    use tunnelrs_proto::{Liveness, PoolMember};

    use super::*;

    fn connector(seed: u8) -> ConnectorId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn preset(modes: &[TlsMode], matches: &[(&str, &str)]) -> Preset {
        Preset {
            modes: modes.to_vec(),
            matches: matches
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
            patch: Patch::default(),
        }
    }

    fn route(tls: TlsMode, meta: &[(&str, &str)], members: &[ConnectorId]) -> RouteView {
        RouteView {
            tls,
            meta: meta
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
            liveness: Liveness::Live,
            members: members
                .iter()
                .map(|&connector| PoolMember {
                    connector,
                    sessions: 1,
                })
                .collect(),
        }
    }

    fn presets() -> BTreeMap<String, Preset> {
        BTreeMap::from([
            (
                "auth".to_owned(),
                preset(&[TlsMode::Terminate], &[("k8s/auth", "authentik")]),
            ),
            (
                "public".to_owned(),
                preset(
                    &[TlsMode::Terminate, TlsMode::Passthrough],
                    &[("k8s/exposure", "public")],
                ),
            ),
            ("headers".to_owned(), preset(&[TlsMode::Terminate], &[])),
        ])
    }

    fn applied<'a>(selection: &Selection<'a>) -> Vec<&'a str> {
        selection.apply.iter().map(|(name, _)| *name).collect()
    }

    #[test]
    fn meta_selects_presets_when_no_policy_governs() {
        let presets = presets();
        let route = route(
            TlsMode::Terminate,
            &[("k8s/auth", "authentik"), ("k8s/exposure", "public")],
            &[],
        );
        let selection = select(&presets, &[], "app.example.com", &route);
        assert_eq!(applied(&selection), ["auth", "public"]);
        assert!(selection.rejected.is_empty());

        let other = route_with_meta(&[("k8s/auth", "oauth2-proxy")]);
        let selection = select(&presets, &[], "app.example.com", &other);
        assert!(applied(&selection).is_empty());
        assert!(selection.rejected.is_empty());
    }

    fn route_with_meta(meta: &[(&str, &str)]) -> RouteView {
        route(TlsMode::Terminate, meta, &[])
    }

    #[test]
    fn governing_policy_rejects_presets_it_does_not_allow() {
        let presets = presets();
        let policies = [Policy {
            hosts: Some("*.internal.example.com".to_owned()),
            allow: vec!["auth".to_owned()],
            ..Policy::default()
        }];
        let route = route_with_meta(&[("k8s/auth", "authentik"), ("k8s/exposure", "public")]);

        let selection = select(&presets, &policies, "wiki.internal.example.com", &route);
        assert_eq!(applied(&selection), ["auth"]);
        assert_eq!(
            selection.rejected,
            [Rejection::NotAllowed {
                preset: "public".to_owned()
            }]
        );

        let selection = select(&presets, &policies, "wiki.example.com", &route);
        assert_eq!(applied(&selection), ["auth", "public"]);
        assert!(selection.rejected.is_empty());
    }

    #[test]
    fn forced_presets_apply_without_meta_but_respect_modes() {
        let presets = presets();
        let policies = [Policy {
            hosts: Some("*.internal.example.com".to_owned()),
            force: vec!["auth".to_owned(), "headers".to_owned()],
            ..Policy::default()
        }];

        let terminate = route_with_meta(&[]);
        let selection = select(&presets, &policies, "wiki.internal.example.com", &terminate);
        assert_eq!(applied(&selection), ["auth", "headers"]);
        assert!(selection.rejected.is_empty());

        let passthrough = route(TlsMode::Passthrough, &[("k8s/exposure", "public")], &[]);
        let selection = select(
            &presets,
            &policies,
            "wiki.internal.example.com",
            &passthrough,
        );
        assert!(applied(&selection).is_empty());
        assert_eq!(
            selection.rejected,
            [
                Rejection::UnsupportedMode {
                    preset: "auth".to_owned(),
                    mode: TlsMode::Passthrough
                },
                Rejection::UnsupportedMode {
                    preset: "headers".to_owned(),
                    mode: TlsMode::Passthrough
                },
                Rejection::NotAllowed {
                    preset: "public".to_owned()
                },
            ]
        );
    }

    #[test]
    fn connector_policies_govern_routes_served_by_listed_connectors() {
        let presets = presets();
        let trusted = connector(1);
        let policies = [Policy {
            connectors: Some(vec![trusted]),
            force: vec!["headers".to_owned()],
            ..Policy::default()
        }];

        let served = route(TlsMode::Terminate, &[], &[connector(2), trusted]);
        let selection = select(&presets, &policies, "app.example.com", &served);
        assert_eq!(applied(&selection), ["headers"]);

        let elsewhere = route(TlsMode::Terminate, &[], &[connector(2)]);
        let selection = select(&presets, &policies, "app.example.com", &elsewhere);
        assert!(applied(&selection).is_empty());
    }
}
