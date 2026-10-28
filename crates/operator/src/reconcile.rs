use std::{
    collections::{BTreeMap, HashMap},
    fmt,
};

use kube::core::GroupVersionKind;
use serde_json::{Map, Value};
use tunnelrs_proto::{DbId, Hostname, Liveness, RouteView};

use crate::{
    config::Routing,
    patch::PatchError,
    presets::{Rejection, mode_name, select},
    templates::Vars,
};

pub const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
pub const MANAGER: &str = "tunnelrs-operator";
pub const HOSTNAME_ANNOTATION: &str = "tunnelrs.dev/hostname";
pub const DB_ID_ANNOTATION: &str = "tunnelrs.dev/db-id";
pub const LAST_LIVE_ANNOTATION: &str = "tunnelrs.dev/last-live";

const MAX_NAME_LEN: usize = 63;
const HASH_SUFFIX_LEN: usize = 9;
const MAX_LAST_LIVE_REFRESH_SECS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectKey {
    pub gvk: GroupVersionKind,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct Desired {
    pub key: ObjectKey,
    pub hostname: Hostname,
    pub object: Value,
    pub rejected: Vec<Rejection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Managed {
    pub key: ObjectKey,
    pub hostname: Option<Hostname>,
    pub db_id: Option<String>,
    pub last_live: Option<u64>,
}

impl Managed {
    pub fn from_annotations(key: ObjectKey, annotations: &BTreeMap<String, String>) -> Self {
        Self {
            key,
            hostname: annotations.get(HOSTNAME_ANNOTATION).cloned(),
            db_id: annotations.get(DB_ID_ANNOTATION).cloned(),
            last_live: annotations
                .get(LAST_LIVE_ANNOTATION)
                .and_then(|value| value.parse().ok()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteReason {
    Withdrawn,
    GraceExpired,
    Superseded,
}

impl fmt::Display for DeleteReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Withdrawn => "route withdrawn",
            Self::GraceExpired => "route offline past the grace period",
            Self::Superseded => "route now uses a different object",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    Keep,
    Delete(DeleteReason),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    #[error("no template is configured for {0} routes")]
    NoTemplate(&'static str),
    #[error("preset {preset}: {source}")]
    Preset { preset: String, source: PatchError },
    #[error("`{0}` in the rendered object is not a table")]
    NotAnObject(&'static str),
}

#[derive(Debug, Default)]
pub struct Plan {
    pub apply: Vec<Desired>,
    pub delete: Vec<(Managed, DeleteReason)>,
    pub failures: Vec<(Hostname, BuildError)>,
}

pub fn object_name(hostname: &str) -> String {
    let hash = fnv1a32(hostname.bytes().map(|byte| byte.to_ascii_lowercase()));
    let sanitized: String = hostname
        .chars()
        .map(|c| match c.to_ascii_lowercase() {
            c @ ('a'..='z' | '0'..='9') => c,
            _ => '-',
        })
        .collect();
    let prefix = sanitized.trim_start_matches('-');
    let prefix = prefix[..prefix.len().min(MAX_NAME_LEN - HASH_SUFFIX_LEN)].trim_end_matches('-');
    if prefix.is_empty() {
        format!("{hash:08x}")
    } else {
        format!("{prefix}-{hash:08x}")
    }
}

fn fnv1a32(bytes: impl IntoIterator<Item = u8>) -> u32 {
    bytes.into_iter().fold(0x811c_9dc5, |hash, byte| {
        (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193)
    })
}

fn expired(last_live: u64, now: u64, grace_secs: u64) -> bool {
    now.saturating_sub(last_live) > grace_secs
}

fn route_last_live(
    liveness: Liveness,
    recorded: Option<u64>,
    now: u64,
    grace_secs: u64,
) -> Option<u64> {
    match liveness {
        Liveness::Live => {
            let refresh = (grace_secs / 2).min(MAX_LAST_LIVE_REFRESH_SECS);
            Some(match recorded {
                Some(recorded) if recorded <= now && now - recorded < refresh => recorded,
                _ => now,
            })
        }
        Liveness::Offline { since_unix } => {
            let last_live = recorded.map_or(since_unix, |recorded| recorded.max(since_unix));
            (!expired(last_live, now, grace_secs)).then_some(last_live)
        }
    }
}

pub fn fate(
    object: &Managed,
    route: Option<&RouteView>,
    db_id: &DbId,
    superseded: bool,
    now: u64,
    grace_secs: u64,
) -> Fate {
    if superseded {
        return Fate::Delete(DeleteReason::Superseded);
    }
    let recorded = object.last_live.unwrap_or(0);
    let unless_expired = |last_live| {
        if expired(last_live, now, grace_secs) {
            Fate::Delete(DeleteReason::GraceExpired)
        } else {
            Fate::Keep
        }
    };
    match route.map(|route| route.liveness) {
        Some(Liveness::Live) => Fate::Keep,
        Some(Liveness::Offline { since_unix }) => unless_expired(recorded.max(since_unix)),
        None if object.db_id.as_deref() == Some(db_id.0.as_str()) => {
            Fate::Delete(DeleteReason::Withdrawn)
        }
        None => unless_expired(recorded),
    }
}

pub fn build(
    routing: &Routing,
    db_id: &DbId,
    hostname: &str,
    route: &RouteView,
    last_live: u64,
) -> Result<Desired, BuildError> {
    let template = routing
        .template(route.tls)
        .ok_or(BuildError::NoTemplate(mode_name(route.tls)))?;
    let name = object_name(hostname);
    let vars = Vars {
        host: hostname,
        service: &routing.service.name,
        port: routing.port(route.tls),
        name: &name,
    };
    let mut object = template.render(&vars);
    let selection = select(&routing.presets, &routing.policies, hostname, route);
    for (preset, definition) in &selection.apply {
        definition
            .patch
            .apply(&mut object)
            .map_err(|source| BuildError::Preset {
                preset: (*preset).to_owned(),
                source,
            })?;
    }

    let root = table(&mut object, "object")?;
    root.insert("apiVersion".to_owned(), template.gvk().api_version().into());
    root.insert("kind".to_owned(), template.gvk().kind.clone().into());
    let metadata = child(root, "metadata", "metadata")?;
    metadata.insert("name".to_owned(), name.clone().into());
    metadata.insert("namespace".to_owned(), routing.namespace.clone().into());
    child(metadata, "labels", "metadata.labels")?
        .insert(MANAGED_BY_LABEL.to_owned(), MANAGER.into());
    let annotations = child(metadata, "annotations", "metadata.annotations")?;
    annotations.insert(HOSTNAME_ANNOTATION.to_owned(), hostname.into());
    annotations.insert(DB_ID_ANNOTATION.to_owned(), db_id.0.clone().into());
    annotations.insert(
        LAST_LIVE_ANNOTATION.to_owned(),
        last_live.to_string().into(),
    );

    Ok(Desired {
        key: ObjectKey {
            gvk: template.gvk().clone(),
            name,
        },
        hostname: hostname.to_owned(),
        object,
        rejected: selection.rejected,
    })
}

fn table<'a>(
    value: &'a mut Value,
    path: &'static str,
) -> Result<&'a mut Map<String, Value>, BuildError> {
    if value.is_null() {
        *value = Value::Object(Map::new());
    }
    value.as_object_mut().ok_or(BuildError::NotAnObject(path))
}

fn child<'a>(
    fields: &'a mut Map<String, Value>,
    key: &str,
    path: &'static str,
) -> Result<&'a mut Map<String, Value>, BuildError> {
    table(fields.entry(key).or_insert(Value::Null), path)
}

pub fn plan(
    routing: &Routing,
    db_id: &DbId,
    routes: &HashMap<Hostname, RouteView>,
    existing: &[Managed],
    now: u64,
) -> Plan {
    let mut recorded: HashMap<&str, u64> = HashMap::new();
    for object in existing {
        if let (Some(hostname), Some(last_live)) = (object.hostname.as_deref(), object.last_live) {
            let entry = recorded.entry(hostname).or_insert(last_live);
            *entry = (*entry).max(last_live);
        }
    }

    let mut plan = Plan::default();
    for (hostname, route) in routes {
        let last_seen = recorded.get(hostname.as_str()).copied();
        let Some(last_live) = route_last_live(route.liveness, last_seen, now, routing.grace_secs)
        else {
            continue;
        };
        match build(routing, db_id, hostname, route, last_live) {
            Ok(desired) => plan.apply.push(desired),
            Err(err) => plan.failures.push((hostname.clone(), err)),
        }
    }
    plan.apply.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    plan.failures.sort_by(|a, b| a.0.cmp(&b.0));

    plan.delete = {
        let wanted: HashMap<&str, &ObjectKey> = plan
            .apply
            .iter()
            .map(|desired| (desired.hostname.as_str(), &desired.key))
            .collect();
        existing
            .iter()
            .filter_map(|object| {
                let hostname = object.hostname.as_deref();
                let route = hostname.and_then(|hostname| routes.get(hostname));
                let superseded = hostname
                    .and_then(|hostname| wanted.get(hostname))
                    .is_some_and(|key| **key != object.key);
                match fate(object, route, db_id, superseded, now, routing.grace_secs) {
                    Fate::Keep => None,
                    Fate::Delete(reason) => Some((object.clone(), reason)),
                }
            })
            .collect()
    };
    plan
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use iroh::SecretKey;
    use serde_json::json;
    use tunnelrs_proto::{Meta, PoolMember, TlsMode};

    use super::*;
    use crate::{config::Service, patch::Patch, presets::Preset, templates::Template};

    const NOW: u64 = 1_000_000;
    const GRACE: u64 = 86_400;

    fn routing() -> Routing {
        let Value::Object(sets) =
            json!({ "spec.routes[*].middlewares": [{ "name": "authentik" }] })
        else {
            panic!("patch sets are an object")
        };
        Routing {
            namespace: "edge".to_owned(),
            grace_secs: GRACE,
            service: Service {
                name: "tunnelrs".to_owned(),
                http_port: 8080,
                tls_port: 8443,
            },
            terminate: Template::builtin("traefik-ingressroute"),
            passthrough: Template::builtin("traefik-ingressroutetcp"),
            presets: BTreeMap::from([(
                "auth".to_owned(),
                Preset {
                    modes: vec![TlsMode::Terminate],
                    matches: Meta::from([("k8s/auth".to_owned(), "authentik".to_owned())]),
                    patch: Patch::new(sets).unwrap(),
                },
            )]),
            policies: Vec::new(),
        }
    }

    fn db(id: &str) -> DbId {
        DbId(id.to_owned())
    }

    fn view(tls: TlsMode, liveness: Liveness) -> RouteView {
        RouteView {
            tls,
            meta: Meta::new(),
            liveness,
            members: vec![PoolMember {
                connector: SecretKey::from_bytes(&[7; 32]).public(),
                sessions: u32::from(liveness == Liveness::Live),
            }],
        }
    }

    fn managed(kind: &str, hostname: &str, db_id: &str, last_live: u64) -> Managed {
        Managed {
            key: ObjectKey {
                gvk: GroupVersionKind::gvk("traefik.io", "v1alpha1", kind),
                name: object_name(hostname),
            },
            hostname: Some(hostname.to_owned()),
            db_id: Some(db_id.to_owned()),
            last_live: Some(last_live),
        }
    }

    fn object(last_live: u64, db_id: &str) -> Managed {
        managed("IngressRoute", "app.example.com", db_id, last_live)
    }

    #[test]
    fn live_routes_keep_their_objects_regardless_of_age() {
        let route = view(TlsMode::Terminate, Liveness::Live);
        assert_eq!(
            fate(&object(0, "a"), Some(&route), &db("a"), false, NOW, GRACE),
            Fate::Keep
        );
    }

    #[test]
    fn offline_routes_expire_after_the_grace_period() {
        let offline = |since_unix| view(TlsMode::Terminate, Liveness::Offline { since_unix });
        let stale = object(NOW - GRACE - 1, "a");
        assert_eq!(
            fate(
                &stale,
                Some(&offline(NOW - GRACE - 1)),
                &db("a"),
                false,
                NOW,
                GRACE
            ),
            Fate::Delete(DeleteReason::GraceExpired)
        );
        assert_eq!(
            fate(
                &stale,
                Some(&offline(NOW - GRACE)),
                &db("a"),
                false,
                NOW,
                GRACE
            ),
            Fate::Keep
        );
        assert_eq!(
            fate(
                &object(NOW - 10, "a"),
                Some(&offline(0)),
                &db("a"),
                false,
                NOW,
                GRACE
            ),
            Fate::Keep
        );
    }

    #[test]
    fn absent_routes_are_withdrawn_only_under_the_same_database() {
        let fresh = object(NOW - 10, "a");
        assert_eq!(
            fate(&fresh, None, &db("a"), false, NOW, GRACE),
            Fate::Delete(DeleteReason::Withdrawn)
        );
        assert_eq!(fate(&fresh, None, &db("b"), false, NOW, GRACE), Fate::Keep);
        assert_eq!(
            fate(
                &object(NOW - GRACE - 1, "a"),
                None,
                &db("b"),
                false,
                NOW,
                GRACE
            ),
            Fate::Delete(DeleteReason::GraceExpired)
        );
        let unannotated = Managed {
            db_id: None,
            last_live: None,
            ..fresh
        };
        assert_eq!(
            fate(&unannotated, None, &db("b"), false, NOW, GRACE),
            Fate::Delete(DeleteReason::GraceExpired)
        );
    }

    #[test]
    fn superseded_objects_are_deleted_even_when_live() {
        let route = view(TlsMode::Passthrough, Liveness::Live);
        assert_eq!(
            fate(&object(NOW, "a"), Some(&route), &db("a"), true, NOW, GRACE),
            Fate::Delete(DeleteReason::Superseded)
        );
    }

    #[test]
    fn empty_route_map_after_a_server_reset_deletes_nothing() {
        let existing = [
            managed("IngressRoute", "a.example.com", "old", NOW - 60),
            managed("IngressRouteTCP", "b.example.com", "old", NOW - GRACE),
        ];
        let plan = plan(&routing(), &db("new"), &HashMap::new(), &existing, NOW);
        assert!(plan.apply.is_empty());
        assert!(plan.delete.is_empty());
    }

    #[test]
    fn empty_route_map_under_the_same_database_withdraws_everything() {
        let existing = [
            managed("IngressRoute", "a.example.com", "same", NOW - 60),
            managed("IngressRouteTCP", "b.example.com", "same", NOW),
        ];
        let plan = plan(&routing(), &db("same"), &HashMap::new(), &existing, NOW);
        assert_eq!(
            plan.delete,
            [
                (existing[0].clone(), DeleteReason::Withdrawn),
                (existing[1].clone(), DeleteReason::Withdrawn),
            ]
        );
    }

    #[test]
    fn mode_change_replaces_the_object_kind() {
        let existing = [managed("IngressRoute", "app.example.com", "a", NOW - 60)];
        let routes = HashMap::from([(
            "app.example.com".to_owned(),
            view(TlsMode::Passthrough, Liveness::Live),
        )]);
        let plan = plan(&routing(), &db("a"), &routes, &existing, NOW);
        assert_eq!(plan.apply.len(), 1);
        assert_eq!(plan.apply[0].key.gvk.kind, "IngressRouteTCP");
        assert_eq!(
            plan.delete,
            [(existing[0].clone(), DeleteReason::Superseded)]
        );
    }

    #[test]
    fn expired_offline_routes_are_not_reapplied() {
        let existing = [managed(
            "IngressRoute",
            "app.example.com",
            "a",
            NOW - GRACE - 5,
        )];
        let routes = HashMap::from([(
            "app.example.com".to_owned(),
            view(
                TlsMode::Terminate,
                Liveness::Offline {
                    since_unix: NOW - GRACE - 5,
                },
            ),
        )]);
        let plan = plan(&routing(), &db("a"), &routes, &existing, NOW);
        assert!(plan.apply.is_empty());
        assert_eq!(
            plan.delete,
            [(existing[0].clone(), DeleteReason::GraceExpired)]
        );
    }

    #[test]
    fn desired_object_carries_identity_annotations_and_presets() {
        let mut route = view(TlsMode::Terminate, Liveness::Live);
        route
            .meta
            .insert("k8s/auth".to_owned(), "authentik".to_owned());
        let desired = build(&routing(), &db("a"), "App.Example.com", &route, NOW).unwrap();
        let name = object_name("App.Example.com");
        assert_eq!(desired.key.name, name);
        assert_eq!(
            desired.object,
            json!({
                "apiVersion": "traefik.io/v1alpha1",
                "kind": "IngressRoute",
                "metadata": {
                    "name": name,
                    "namespace": "edge",
                    "labels": { MANAGED_BY_LABEL: MANAGER },
                    "annotations": {
                        HOSTNAME_ANNOTATION: "App.Example.com",
                        DB_ID_ANNOTATION: "a",
                        LAST_LIVE_ANNOTATION: NOW.to_string()
                    }
                },
                "spec": {
                    "entryPoints": ["websecure"],
                    "routes": [{
                        "match": "Host(`App.Example.com`)",
                        "kind": "Rule",
                        "services": [{ "name": "tunnelrs", "port": 8080 }],
                        "middlewares": [{ "name": "authentik" }]
                    }]
                }
            })
        );
    }

    #[test]
    fn live_routes_refresh_last_live_only_when_stale() {
        assert_eq!(
            route_last_live(Liveness::Live, Some(NOW - 10), NOW, GRACE),
            Some(NOW - 10)
        );
        assert_eq!(
            route_last_live(Liveness::Live, Some(NOW - 600), NOW, GRACE),
            Some(NOW)
        );
        assert_eq!(route_last_live(Liveness::Live, None, NOW, GRACE), Some(NOW));
    }

    #[test]
    fn object_names_are_sanitized_bounded_and_hashed() {
        assert_eq!(fnv1a32(*b"foobar"), 0xbf9c_f968);
        assert_eq!(
            object_name("App.Example.com"),
            format!("app-example-com-{:08x}", fnv1a32(*b"app.example.com"))
        );
        let long = format!("{}.example.com", "a".repeat(80));
        let name = object_name(&long);
        assert_eq!(name.len(), MAX_NAME_LEN);
        assert!(name.starts_with("aaaa"));
        assert_ne!(
            object_name(&long),
            object_name(&format!("{}.example.org", "a".repeat(80)))
        );
    }
}
