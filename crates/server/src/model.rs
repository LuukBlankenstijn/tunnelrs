use std::collections::{BTreeMap, BTreeSet};

use tunnelrs_proto::{
    ApiError, ConnectorId, Enrollment, Exposure, Hostname, MAX_HOSTNAME_LEN, MAX_META_BYTES, Meta,
    RouteStatus, TlsMode, host_matches,
};

const MAX_LABEL_LEN: usize = 63;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub patterns: Vec<String>,
    pub tls_modes: Option<Vec<TlsMode>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announced {
    pub tls: TlsMode,
    pub meta: Meta,
}

#[derive(Debug, Clone)]
pub struct ConnectorRecord {
    pub enrollment: Enrollment,
    pub grant: Option<Grant>,
    pub announcement: BTreeMap<Hostname, Announced>,
    pub rejected: BTreeMap<Hostname, String>,
    pub statuses: BTreeMap<Hostname, RouteStatus>,
}

impl ConnectorRecord {
    pub fn new(enrollment: Enrollment) -> Self {
        Self {
            enrollment,
            grant: None,
            announcement: BTreeMap::new(),
            rejected: BTreeMap::new(),
            statuses: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RouteRecord {
    pub tls: TlsMode,
    pub meta: Meta,
    pub members: BTreeSet<ConnectorId>,
    pub offline_since: Option<u64>,
}

impl RouteRecord {
    pub fn is_live(&self, live: &BTreeSet<ConnectorId>) -> bool {
        self.members.iter().any(|member| live.contains(member))
    }
}

#[derive(Debug, Clone, Default)]
pub struct Model {
    pub connectors: BTreeMap<ConnectorId, ConnectorRecord>,
    pub routes: BTreeMap<Hostname, RouteRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Change {
    Kept,
    Freed,
    Redefined,
}

impl Model {
    pub fn restore(&mut self) {
        let stored = std::mem::take(&mut self.routes);
        for (host, mut route) in stored {
            route.members = self
                .connectors
                .iter()
                .filter(|(_, record)| {
                    record.announcement.get(&host).is_some_and(|announced| {
                        announced.tls == route.tls
                            && announced.meta == route.meta
                            && eligibility(record, &host, announced).is_ok()
                    })
                })
                .map(|(id, _)| *id)
                .collect();
            if !route.members.is_empty() {
                self.routes.insert(host, route);
            }
        }
        let ids: Vec<ConnectorId> = self.connectors.keys().copied().collect();
        let live = BTreeSet::new();
        for id in ids {
            self.evaluate(id, &live);
        }
    }

    pub fn announce(
        &mut self,
        id: ConnectorId,
        exposures: Vec<Exposure>,
        live: &BTreeSet<ConnectorId>,
    ) -> Result<(), ApiError> {
        let mut announcement = BTreeMap::new();
        let mut rejected = BTreeMap::new();
        for exposure in exposures {
            let host = normalize_hostname(&exposure.hostname);
            if announcement.contains_key(&host) || rejected.contains_key(&host) {
                return Err(ApiError::Invalid(format!(
                    "hostname {host} is announced more than once"
                )));
            }
            match validate_exposure(&host, &exposure.meta) {
                Ok(()) => {
                    announcement.insert(
                        host,
                        Announced {
                            tls: exposure.tls,
                            meta: exposure.meta,
                        },
                    );
                }
                Err(reason) => {
                    rejected.insert(host, reason);
                }
            }
        }
        let record = self
            .connectors
            .entry(id)
            .or_insert_with(|| ConnectorRecord::new(Enrollment::Pending));
        record.announcement = announcement;
        record.rejected = rejected;
        self.evaluate(id, live);
        Ok(())
    }

    pub fn approve(
        &mut self,
        id: ConnectorId,
        hosts: Option<Vec<String>>,
        tls_modes: Option<Vec<TlsMode>>,
        live: &BTreeSet<ConnectorId>,
    ) -> Result<(), ApiError> {
        let record = self
            .connectors
            .get_mut(&id)
            .ok_or_else(|| unknown_connector(id))?;
        let patterns = match hosts {
            Some(hosts) => parse_patterns(&hosts)?,
            None if record.announcement.is_empty() => {
                return Err(ApiError::Invalid(format!(
                    "connector {id} has not announced any valid hostnames; pass hosts explicitly"
                )));
            }
            None => record.announcement.keys().cloned().collect(),
        };
        let tls_modes = match tls_modes {
            Some(modes) if modes.is_empty() => {
                return Err(ApiError::Invalid(
                    "tls_modes must name at least one mode".to_owned(),
                ));
            }
            Some(modes) => Some(
                modes
                    .into_iter()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            ),
            None => None,
        };
        record.grant = Some(Grant {
            patterns,
            tls_modes,
        });
        record.enrollment = Enrollment::Approved;
        self.evaluate(id, live);
        Ok(())
    }

    pub fn deny(&mut self, id: ConnectorId, live: &BTreeSet<ConnectorId>) -> Result<(), ApiError> {
        let record = self
            .connectors
            .get_mut(&id)
            .ok_or_else(|| unknown_connector(id))?;
        record.enrollment = Enrollment::Denied;
        self.evaluate(id, live);
        Ok(())
    }

    pub fn revoke(
        &mut self,
        id: ConnectorId,
        live: &BTreeSet<ConnectorId>,
    ) -> Result<(), ApiError> {
        let record = self
            .connectors
            .get_mut(&id)
            .ok_or_else(|| unknown_connector(id))?;
        record.enrollment = Enrollment::Revoked;
        record.grant = None;
        record.announcement.clear();
        record.rejected.clear();
        self.evaluate(id, live);
        Ok(())
    }

    pub fn withdraw(&mut self, host: &str, live: &BTreeSet<ConnectorId>) {
        let Some(route) = self.routes.remove(host) else {
            return;
        };
        for member in &route.members {
            if let Some(record) = self.connectors.get_mut(member) {
                record.announcement.remove(host);
                record.statuses.remove(host);
            }
        }
        self.offer(host, live);
    }

    pub fn settle(&mut self, live: &BTreeSet<ConnectorId>, now: u64) {
        for route in self.routes.values_mut() {
            if route.is_live(live) {
                route.offline_since = None;
            } else if route.offline_since.is_none() {
                route.offline_since = Some(now);
            }
        }
    }

    pub fn expired(
        &self,
        live: &BTreeSet<ConnectorId>,
        now: u64,
        expiry_secs: u64,
    ) -> Vec<Hostname> {
        self.routes
            .iter()
            .filter(|(_, route)| {
                !route.is_live(live)
                    && route
                        .offline_since
                        .is_some_and(|since| now.saturating_sub(since) >= expiry_secs)
            })
            .map(|(host, _)| host.clone())
            .collect()
    }

    fn evaluate(&mut self, id: ConnectorId, live: &BTreeSet<ConnectorId>) {
        let Some(record) = self.connectors.get(&id) else {
            return;
        };
        let mut hosts: BTreeSet<Hostname> = record.announcement.keys().cloned().collect();
        hosts.extend(
            self.routes
                .iter()
                .filter(|(_, route)| route.members.contains(&id))
                .map(|(host, _)| host.clone()),
        );
        let mut statuses: BTreeMap<Hostname, RouteStatus> = record
            .rejected
            .iter()
            .map(|(host, reason)| (host.clone(), RouteStatus::Denied(reason.clone())))
            .collect();
        let mut reoffer = Vec::new();
        for host in hosts {
            let (status, change) = self.claim(id, &host);
            if let Some(status) = status {
                statuses.insert(host.clone(), status);
            }
            if change != Change::Kept {
                reoffer.push(host);
            }
        }
        if let Some(record) = self.connectors.get_mut(&id) {
            record.statuses = statuses;
        }
        for host in reoffer {
            self.offer(&host, live);
        }
    }

    fn claim(&mut self, id: ConnectorId, host: &str) -> (Option<RouteStatus>, Change) {
        let Some(record) = self.connectors.get(&id) else {
            return (None, Change::Kept);
        };
        let wanted = record
            .announcement
            .get(host)
            .map(|announced| (announced.clone(), eligibility(record, host, announced)));
        if let Some(route) = self.routes.get_mut(host) {
            route.members.remove(&id);
        }
        match wanted {
            Some((announced, Ok(()))) => match self.routes.get_mut(host) {
                Some(route) if route.tls == announced.tls && route.meta == announced.meta => {
                    route.members.insert(id);
                    (Some(RouteStatus::Accepted), Change::Kept)
                }
                Some(route) if route.members.is_empty() => {
                    route.tls = announced.tls;
                    route.meta = announced.meta;
                    route.members.insert(id);
                    (Some(RouteStatus::Accepted), Change::Redefined)
                }
                Some(route) => (
                    Some(RouteStatus::Conflict(conflict_reason(
                        host, route, &announced,
                    ))),
                    Change::Kept,
                ),
                None => {
                    self.routes.insert(
                        host.to_owned(),
                        RouteRecord {
                            tls: announced.tls,
                            meta: announced.meta,
                            members: BTreeSet::from([id]),
                            offline_since: None,
                        },
                    );
                    (Some(RouteStatus::Accepted), Change::Kept)
                }
            },
            Some((_, Err(status))) => (Some(status), self.release(host)),
            None => (None, self.release(host)),
        }
    }

    fn release(&mut self, host: &str) -> Change {
        if self
            .routes
            .get(host)
            .is_some_and(|route| route.members.is_empty())
        {
            self.routes.remove(host);
            Change::Freed
        } else {
            Change::Kept
        }
    }

    fn offer(&mut self, host: &str, live: &BTreeSet<ConnectorId>) {
        let members = self
            .routes
            .get(host)
            .map(|route| route.members.clone())
            .unwrap_or_default();
        let mut candidates: Vec<ConnectorId> = self
            .connectors
            .iter()
            .filter(|(id, record)| {
                record.enrollment == Enrollment::Approved
                    && record.announcement.contains_key(host)
                    && !members.contains(*id)
            })
            .map(|(id, _)| *id)
            .collect();
        candidates.sort_by_key(|id| (!live.contains(id), *id));
        for id in candidates {
            let (status, _) = self.claim(id, host);
            if let (Some(status), Some(record)) = (status, self.connectors.get_mut(&id)) {
                record.statuses.insert(host.to_owned(), status);
            }
        }
    }
}

pub fn normalize_hostname(name: &str) -> Hostname {
    name.trim_end_matches('.').to_ascii_lowercase()
}

pub fn tls_name(tls: TlsMode) -> &'static str {
    match tls {
        TlsMode::Terminate => "terminate",
        TlsMode::Passthrough => "passthrough",
    }
}

fn eligibility(
    record: &ConnectorRecord,
    host: &str,
    announced: &Announced,
) -> Result<(), RouteStatus> {
    match record.enrollment {
        Enrollment::Pending => Err(RouteStatus::Pending),
        Enrollment::Denied => Err(RouteStatus::Denied("connector is denied".to_owned())),
        Enrollment::Revoked => Err(RouteStatus::Denied("connector is revoked".to_owned())),
        Enrollment::Approved => {
            let Some(grant) = &record.grant else {
                return Err(RouteStatus::Denied("connector has no grant".to_owned()));
            };
            if !grant
                .patterns
                .iter()
                .any(|pattern| host_matches(pattern, host))
            {
                return Err(RouteStatus::Denied(format!(
                    "{host} is not covered by the connector's grant"
                )));
            }
            if grant
                .tls_modes
                .as_ref()
                .is_some_and(|modes| !modes.contains(&announced.tls))
            {
                return Err(RouteStatus::Denied(format!(
                    "tls mode {} is not granted",
                    tls_name(announced.tls)
                )));
            }
            Ok(())
        }
    }
}

fn conflict_reason(host: &str, route: &RouteRecord, announced: &Announced) -> String {
    if route.tls != announced.tls {
        format!(
            "{host} is held by a pool with tls mode {}",
            tls_name(route.tls)
        )
    } else {
        format!("{host} is held by a pool with different meta")
    }
}

fn unknown_connector(id: ConnectorId) -> ApiError {
    ApiError::NotFound(format!("connector {id}"))
}

fn validate_exposure(host: &str, meta: &Meta) -> Result<(), String> {
    validate_hostname(host)?;
    match serde_json::to_vec(meta) {
        Ok(bytes) if bytes.len() <= MAX_META_BYTES => Ok(()),
        Ok(bytes) => Err(format!(
            "meta is {} bytes, the limit is {MAX_META_BYTES}",
            bytes.len()
        )),
        Err(err) => Err(format!("meta cannot be serialized: {err}")),
    }
}

fn validate_hostname(host: &str) -> Result<(), String> {
    validate_name(host, validate_label)
}

fn validate_pattern(pattern: &str) -> Result<(), String> {
    validate_name(pattern, |label| match label {
        "*" => Ok(()),
        label => validate_label(label),
    })
}

fn validate_name(name: &str, label: impl Fn(&str) -> Result<(), String>) -> Result<(), String> {
    if name.is_empty() {
        return Err("hostname is empty".to_owned());
    }
    if name.len() > MAX_HOSTNAME_LEN {
        return Err(format!("hostname is longer than {MAX_HOSTNAME_LEN} bytes"));
    }
    name.split('.').try_for_each(label)
}

fn validate_label(label: &str) -> Result<(), String> {
    if label.is_empty() || label.len() > MAX_LABEL_LEN {
        return Err(format!(
            "label {label:?} must be 1 to {MAX_LABEL_LEN} characters"
        ));
    }
    if !label
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(format!("label {label:?} may only contain a-z, 0-9 and '-'"));
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(format!("label {label:?} must not start or end with '-'"));
    }
    Ok(())
}

fn parse_patterns(hosts: &[String]) -> Result<Vec<String>, ApiError> {
    if hosts.is_empty() {
        return Err(ApiError::Invalid(
            "hosts must name at least one pattern".to_owned(),
        ));
    }
    let patterns = hosts
        .iter()
        .map(|host| {
            let pattern = normalize_hostname(host);
            validate_pattern(&pattern)
                .map(|()| pattern)
                .map_err(|reason| {
                    ApiError::Invalid(format!("invalid host pattern {host:?}: {reason}"))
                })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    Ok(patterns.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;

    use super::*;

    fn connector() -> ConnectorId {
        SecretKey::generate().public()
    }

    fn exposure(hostname: &str, tls: TlsMode, meta: &[(&str, &str)]) -> Exposure {
        Exposure {
            hostname: hostname.to_owned(),
            tls,
            meta: meta
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
        }
    }

    fn status(model: &Model, id: ConnectorId, host: &str) -> Option<RouteStatus> {
        model.connectors[&id].statuses.get(host).cloned()
    }

    fn approved(
        model: &mut Model,
        id: ConnectorId,
        exposures: Vec<Exposure>,
        live: &BTreeSet<ConnectorId>,
    ) {
        model.announce(id, exposures, live).unwrap();
        model.approve(id, None, None, live).unwrap();
    }

    #[test]
    fn approve_without_hosts_grants_exactly_the_announced_hostnames() {
        let mut model = Model::default();
        let id = connector();
        let live = BTreeSet::from([id]);
        model
            .announce(
                id,
                vec![
                    exposure("App.Example.com.", TlsMode::Terminate, &[]),
                    exposure("bad host", TlsMode::Terminate, &[]),
                ],
                &live,
            )
            .unwrap();
        assert_eq!(
            status(&model, id, "app.example.com"),
            Some(RouteStatus::Pending)
        );
        assert!(model.routes.is_empty());

        model.approve(id, None, None, &live).unwrap();

        let grant = model.connectors[&id].grant.clone().unwrap();
        assert_eq!(grant.patterns, vec!["app.example.com".to_owned()]);
        assert_eq!(
            status(&model, id, "app.example.com"),
            Some(RouteStatus::Accepted)
        );
        assert!(matches!(
            status(&model, id, "bad host"),
            Some(RouteStatus::Denied(_))
        ));
        assert!(model.routes["app.example.com"].members.contains(&id));
    }

    #[test]
    fn duplicate_hostnames_reject_the_whole_announcement() {
        let mut model = Model::default();
        let id = connector();
        let live = BTreeSet::from([id]);
        let result = model.announce(
            id,
            vec![
                exposure("a.example.com", TlsMode::Terminate, &[]),
                exposure("A.example.com.", TlsMode::Passthrough, &[]),
            ],
            &live,
        );
        assert!(matches!(result, Err(ApiError::Invalid(_))));
        assert!(!model.connectors.contains_key(&id));
    }

    #[test]
    fn grant_patterns_and_tls_modes_restrict_claims() {
        let mut model = Model::default();
        let id = connector();
        let live = BTreeSet::from([id]);
        model
            .announce(
                id,
                vec![
                    exposure("a.foo.example.com", TlsMode::Terminate, &[]),
                    exposure("a.b.foo.example.com", TlsMode::Terminate, &[]),
                    exposure("c.foo.example.com", TlsMode::Passthrough, &[]),
                ],
                &live,
            )
            .unwrap();
        model
            .approve(
                id,
                Some(vec!["*.foo.example.com".to_owned()]),
                Some(vec![TlsMode::Terminate]),
                &live,
            )
            .unwrap();
        assert_eq!(
            status(&model, id, "a.foo.example.com"),
            Some(RouteStatus::Accepted)
        );
        assert!(matches!(
            status(&model, id, "a.b.foo.example.com"),
            Some(RouteStatus::Denied(_))
        ));
        assert!(matches!(
            status(&model, id, "c.foo.example.com"),
            Some(RouteStatus::Denied(_))
        ));
        assert_eq!(
            model.routes.keys().collect::<Vec<_>>(),
            vec!["a.foo.example.com"]
        );
    }

    #[test]
    fn offline_pool_keeps_its_hostname_against_different_meta() {
        let mut model = Model::default();
        let first = connector();
        let second = connector();
        approved(
            &mut model,
            first,
            vec![exposure(
                "app.example.com",
                TlsMode::Terminate,
                &[("k8s/auth", "a")],
            )],
            &BTreeSet::new(),
        );
        let live = BTreeSet::from([second]);
        approved(
            &mut model,
            second,
            vec![exposure(
                "app.example.com",
                TlsMode::Terminate,
                &[("k8s/auth", "b")],
            )],
            &live,
        );
        assert!(matches!(
            status(&model, second, "app.example.com"),
            Some(RouteStatus::Conflict(_))
        ));
        assert_eq!(
            model.routes["app.example.com"].members,
            BTreeSet::from([first])
        );
        assert_eq!(model.routes["app.example.com"].meta["k8s/auth"], "a");
    }

    #[test]
    fn matching_claimants_share_a_pool() {
        let mut model = Model::default();
        let first = connector();
        let second = connector();
        let live = BTreeSet::from([first, second]);
        let exposures = vec![exposure(
            "app.example.com",
            TlsMode::Passthrough,
            &[("k", "v")],
        )];
        approved(&mut model, first, exposures.clone(), &live);
        approved(&mut model, second, exposures, &live);
        assert_eq!(
            model.routes["app.example.com"].members,
            BTreeSet::from([first, second])
        );
    }

    #[test]
    fn withdrawing_a_route_hands_the_hostname_to_a_conflicting_claimant() {
        let mut model = Model::default();
        let first = connector();
        let second = connector();
        approved(
            &mut model,
            first,
            vec![exposure("app.example.com", TlsMode::Terminate, &[])],
            &BTreeSet::new(),
        );
        let live = BTreeSet::from([second]);
        approved(
            &mut model,
            second,
            vec![exposure("app.example.com", TlsMode::Passthrough, &[])],
            &live,
        );

        model.withdraw("app.example.com", &live);

        assert!(model.connectors[&first].announcement.is_empty());
        assert_eq!(
            status(&model, second, "app.example.com"),
            Some(RouteStatus::Accepted)
        );
        let route = &model.routes["app.example.com"];
        assert_eq!(route.members, BTreeSet::from([second]));
        assert_eq!(route.tls, TlsMode::Passthrough);
    }

    #[test]
    fn reannouncing_without_a_hostname_withdraws_it() {
        let mut model = Model::default();
        let id = connector();
        let live = BTreeSet::from([id]);
        approved(
            &mut model,
            id,
            vec![
                exposure("a.example.com", TlsMode::Terminate, &[]),
                exposure("b.example.com", TlsMode::Terminate, &[]),
            ],
            &live,
        );
        model
            .announce(
                id,
                vec![exposure("a.example.com", TlsMode::Terminate, &[])],
                &live,
            )
            .unwrap();
        assert_eq!(
            model.routes.keys().collect::<Vec<_>>(),
            vec!["a.example.com"]
        );
        assert_eq!(status(&model, id, "b.example.com"), None);
    }

    #[test]
    fn sole_member_can_change_its_route_meta() {
        let mut model = Model::default();
        let id = connector();
        let live = BTreeSet::from([id]);
        approved(
            &mut model,
            id,
            vec![exposure("a.example.com", TlsMode::Terminate, &[("k", "1")])],
            &live,
        );
        model
            .announce(
                id,
                vec![exposure("a.example.com", TlsMode::Terminate, &[("k", "2")])],
                &live,
            )
            .unwrap();
        assert_eq!(
            status(&model, id, "a.example.com"),
            Some(RouteStatus::Accepted)
        );
        assert_eq!(model.routes["a.example.com"].meta["k"], "2");
    }

    #[test]
    fn revoke_withdraws_routes_and_forgets_the_announcement() {
        let mut model = Model::default();
        let id = connector();
        let live = BTreeSet::from([id]);
        approved(
            &mut model,
            id,
            vec![exposure("a.example.com", TlsMode::Terminate, &[])],
            &live,
        );
        model.revoke(id, &live).unwrap();
        let record = &model.connectors[&id];
        assert_eq!(record.enrollment, Enrollment::Revoked);
        assert!(record.grant.is_none());
        assert!(record.announcement.is_empty());
        assert!(model.routes.is_empty());
    }

    #[test]
    fn restore_keeps_the_stored_pool_ahead_of_conflicting_claimants() {
        let mut model = Model::default();
        let owner = connector();
        let rival = connector();
        approved(
            &mut model,
            owner,
            vec![exposure(
                "app.example.com",
                TlsMode::Terminate,
                &[("k", "owner")],
            )],
            &BTreeSet::new(),
        );
        approved(
            &mut model,
            rival,
            vec![exposure(
                "app.example.com",
                TlsMode::Terminate,
                &[("k", "rival")],
            )],
            &BTreeSet::new(),
        );
        let mut stored = model.clone();
        for record in stored.connectors.values_mut() {
            record.statuses.clear();
        }
        for route in stored.routes.values_mut() {
            route.members.clear();
        }

        stored.restore();

        assert_eq!(
            stored.routes["app.example.com"].members,
            BTreeSet::from([owner])
        );
        assert!(matches!(
            status(&stored, rival, "app.example.com"),
            Some(RouteStatus::Conflict(_))
        ));
    }

    #[test]
    fn settle_and_expiry_track_offline_time() {
        let mut model = Model::default();
        let id = connector();
        let live = BTreeSet::from([id]);
        approved(
            &mut model,
            id,
            vec![exposure("a.example.com", TlsMode::Terminate, &[])],
            &live,
        );
        model.settle(&live, 100);
        assert_eq!(model.routes["a.example.com"].offline_since, None);

        let offline = BTreeSet::new();
        model.settle(&offline, 200);
        model.settle(&offline, 300);
        assert_eq!(model.routes["a.example.com"].offline_since, Some(200));
        assert!(model.expired(&offline, 299, 100).is_empty());
        assert_eq!(
            model.expired(&offline, 300, 100),
            vec!["a.example.com".to_owned()]
        );
        assert!(model.expired(&live, 300, 100).is_empty());
    }
}
