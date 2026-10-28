use std::{
    collections::{HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use k8s_openapi::api::core::v1::ObjectReference;
use kube::{
    Client, Resource,
    api::{Api, DeleteParams, DynamicObject, ListParams, Patch, PatchParams},
    core::GroupVersionKind,
    discovery::{self, ApiResource, Scope},
    runtime::events::{Event, EventType, Recorder, Reporter},
};
use serde_json::Value;
use tracing::{info, warn};
use tunnelrs_proto::{DbId, Hostname, RouteView};

use crate::{
    config::Routing,
    presets::Rejection,
    reconcile::{
        self, BuildError, DeleteReason, Desired, MANAGED_BY_LABEL, MANAGER, Managed, ObjectKey,
    },
};

struct Kind {
    resource: ApiResource,
    namespaced: bool,
}

impl Kind {
    fn api(&self, client: &Client, namespace: &str) -> Api<DynamicObject> {
        if self.namespaced {
            Api::namespaced_with(client.clone(), namespace, &self.resource)
        } else {
            Api::all_with(client.clone(), &self.resource)
        }
    }
}

pub struct Cluster {
    client: Client,
    recorder: Recorder,
    kinds: HashMap<GroupVersionKind, Kind>,
    reported: HashMap<ObjectKey, Vec<Rejection>>,
    failures: HashMap<Hostname, String>,
}

impl Cluster {
    pub fn new(client: Client) -> Self {
        let recorder = Recorder::new(client.clone(), Reporter::from(MANAGER));
        Self {
            client,
            recorder,
            kinds: HashMap::new(),
            reported: HashMap::new(),
            failures: HashMap::new(),
        }
    }

    pub async fn reconcile(
        &mut self,
        routing: &Routing,
        db_id: &DbId,
        routes: &HashMap<Hostname, RouteView>,
    ) -> anyhow::Result<()> {
        let gvks = routing.kinds();
        self.resolve(&gvks).await?;
        let existing = self.list(&gvks, &routing.namespace).await?;
        let plan = reconcile::plan(routing, db_id, routes, &existing, unix_now());
        self.report_failures(&plan.failures);

        let current: HashSet<ObjectKey> = plan
            .apply
            .iter()
            .map(|desired| desired.key.clone())
            .collect();
        for desired in plan.apply {
            self.apply(&routing.namespace, desired).await;
        }
        for (object, reason) in &plan.delete {
            self.delete(&routing.namespace, object, *reason).await;
        }
        self.reported.retain(|key, _| current.contains(key));
        Ok(())
    }

    async fn resolve(&mut self, gvks: &[GroupVersionKind]) -> anyhow::Result<()> {
        for gvk in gvks {
            if self.kinds.contains_key(gvk) {
                continue;
            }
            let (resource, capabilities) = discovery::pinned_kind(&self.client, gvk)
                .await
                .with_context(|| format!("discovering {} {}", gvk.api_version(), gvk.kind))?;
            self.kinds.insert(
                gvk.clone(),
                Kind {
                    resource,
                    namespaced: capabilities.scope == Scope::Namespaced,
                },
            );
        }
        Ok(())
    }

    async fn list(
        &self,
        gvks: &[GroupVersionKind],
        namespace: &str,
    ) -> anyhow::Result<Vec<Managed>> {
        let params = ListParams::default().labels(&format!("{MANAGED_BY_LABEL}={MANAGER}"));
        let mut managed = Vec::new();
        for gvk in gvks {
            let objects = self.kinds[gvk]
                .api(&self.client, namespace)
                .list(&params)
                .await
                .with_context(|| format!("listing {} {}", gvk.api_version(), gvk.kind))?;
            for object in objects.items {
                let Some(name) = object.metadata.name else {
                    continue;
                };
                let key = ObjectKey {
                    gvk: gvk.clone(),
                    name,
                };
                managed.push(Managed::from_annotations(
                    key,
                    object
                        .metadata
                        .annotations
                        .as_ref()
                        .unwrap_or(&Default::default()),
                ));
            }
        }
        Ok(managed)
    }

    async fn apply(&mut self, namespace: &str, desired: Desired) {
        let Desired {
            key,
            hostname,
            mut object,
            rejected,
        } = desired;
        let kind = &self.kinds[&key.gvk];
        if !kind.namespaced
            && let Some(metadata) = object.get_mut("metadata").and_then(Value::as_object_mut)
        {
            metadata.remove("namespace");
        }
        let params = PatchParams::apply(MANAGER).force();
        let applied = match kind
            .api(&self.client, namespace)
            .patch(&key.name, &params, &Patch::Apply(&object))
            .await
        {
            Ok(applied) => applied,
            Err(err) => {
                warn!(%hostname, kind = %key.gvk.kind, name = %key.name, error = %err, "applying routing object failed");
                return;
            }
        };
        if self.reported.get(&key) == Some(&rejected) {
            return;
        }
        let reference = applied.object_ref(&kind.resource);
        for rejection in &rejected {
            warn!(%hostname, kind = %key.gvk.kind, name = %key.name, "{rejection}");
            self.publish(&reference, rejection.to_string()).await;
        }
        self.reported.insert(key, rejected);
    }

    async fn publish(&self, reference: &ObjectReference, note: String) {
        let event = Event {
            type_: EventType::Warning,
            reason: "PresetRejected".to_owned(),
            note: Some(note),
            action: "ApplyPresets".to_owned(),
            secondary: None,
        };
        if let Err(err) = self.recorder.publish(&event, reference).await {
            warn!(error = %err, "publishing event failed");
        }
    }

    async fn delete(&self, namespace: &str, object: &Managed, reason: DeleteReason) {
        let key = &object.key;
        let hostname = object.hostname.as_deref().unwrap_or_default();
        match self.kinds[&key.gvk]
            .api(&self.client, namespace)
            .delete(&key.name, &DeleteParams::default())
            .await
        {
            Ok(_) => {
                info!(hostname, kind = %key.gvk.kind, name = %key.name, %reason, "deleted routing object")
            }
            Err(kube::Error::Api(status)) if status.is_not_found() => {}
            Err(err) => {
                warn!(hostname, kind = %key.gvk.kind, name = %key.name, error = %err, "deleting routing object failed");
            }
        }
    }

    fn report_failures(&mut self, failures: &[(Hostname, BuildError)]) {
        let current: HashMap<Hostname, String> = failures
            .iter()
            .map(|(hostname, err)| (hostname.clone(), err.to_string()))
            .collect();
        for (hostname, message) in &current {
            if self.failures.get(hostname) != Some(message) {
                warn!(%hostname, "cannot build routing object: {message}");
            }
        }
        self.failures = current;
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
