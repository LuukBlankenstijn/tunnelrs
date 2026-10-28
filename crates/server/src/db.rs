use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    str::FromStr,
    time::Duration,
};

use anyhow::Context;
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode},
};
use tunnelrs_proto::{ConnectorId, DbId, Enrollment, Hostname, TlsMode};

use crate::model::{Announced, ConnectorRecord, Grant, Model, RouteRecord, tls_name};

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error("invalid json in {column}: {source}")]
    Json {
        column: &'static str,
        source: serde_json::Error,
    },
    #[error("invalid value {value:?} in {column}")]
    Corrupt { column: &'static str, value: String },
}

pub struct Db {
    pool: SqlitePool,
}

impl Db {
    pub async fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating database directory {}", parent.display()))?;
        }
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(BUSY_TIMEOUT);
        let pool = SqlitePool::connect_with(options)
            .await
            .with_context(|| format!("opening database {}", path.display()))?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .context("running database migrations")?;
        Ok(Self { pool })
    }

    pub async fn db_id(&self) -> Result<DbId, DbError> {
        let id = sqlx::query_scalar!(r#"SELECT db_id AS "db_id!" FROM meta WHERE id = 0"#)
            .fetch_one(&self.pool)
            .await?;
        Ok(DbId(id))
    }

    pub async fn load(&self) -> Result<Model, DbError> {
        let mut model = Model::default();

        let connectors =
            sqlx::query!(r#"SELECT id AS "id!", enrollment AS "enrollment!" FROM connectors"#)
                .fetch_all(&self.pool)
                .await?;
        for row in connectors {
            model.connectors.insert(
                parse_id(&row.id)?,
                ConnectorRecord::new(parse_enrollment(&row.enrollment)?),
            );
        }

        let grants = sqlx::query!(
            r#"SELECT connector_id AS "connector_id!", patterns AS "patterns!", tls_modes AS "tls_modes?" FROM grants"#
        )
        .fetch_all(&self.pool)
        .await?;
        for row in grants {
            let grant = Grant {
                patterns: parse_json("grants.patterns", &row.patterns)?,
                tls_modes: row
                    .tls_modes
                    .as_deref()
                    .map(|modes| parse_json("grants.tls_modes", modes))
                    .transpose()?,
            };
            if let Some(record) = model.connectors.get_mut(&parse_id(&row.connector_id)?) {
                record.grant = Some(grant);
            }
        }

        let announcements = sqlx::query!(
            r#"SELECT connector_id AS "connector_id!", hostname AS "hostname!", tls AS "tls!", meta AS "meta!" FROM announcements"#
        )
        .fetch_all(&self.pool)
        .await?;
        for row in announcements {
            let announced = Announced {
                tls: parse_tls("announcements.tls", &row.tls)?,
                meta: parse_json("announcements.meta", &row.meta)?,
            };
            if let Some(record) = model.connectors.get_mut(&parse_id(&row.connector_id)?) {
                record.announcement.insert(row.hostname, announced);
            }
        }

        let routes = sqlx::query!(
            r#"SELECT hostname AS "hostname!", tls AS "tls!", meta AS "meta!", offline_since AS "offline_since?" FROM routes"#
        )
        .fetch_all(&self.pool)
        .await?;
        for row in routes {
            model.routes.insert(
                row.hostname,
                RouteRecord {
                    tls: parse_tls("routes.tls", &row.tls)?,
                    meta: parse_json("routes.meta", &row.meta)?,
                    members: BTreeSet::new(),
                    offline_since: row
                        .offline_since
                        .map(|since| u64::try_from(since).unwrap_or_default()),
                },
            );
        }

        Ok(model)
    }

    pub async fn persist(&self, old: &Model, new: &Model, now: u64) -> Result<(), DbError> {
        let changes = Changes::between(old, new);
        if changes.is_empty() {
            return Ok(());
        }
        let updated_at = i64::try_from(now).unwrap_or(i64::MAX);
        let mut tx = self.pool.begin().await?;

        for (id, enrollment) in &changes.enrollments {
            let id = id.to_string();
            let enrollment = enrollment_name(*enrollment);
            sqlx::query!(
                "INSERT INTO connectors (id, enrollment, updated_at) VALUES (?, ?, ?) ON CONFLICT (id) DO UPDATE SET enrollment = excluded.enrollment, updated_at = excluded.updated_at",
                id,
                enrollment,
                updated_at
            )
            .execute(&mut *tx)
            .await?;
        }

        for (id, grant) in &changes.grants {
            let id = id.to_string();
            match grant {
                Some(grant) => {
                    let patterns = to_json("grants.patterns", &grant.patterns)?;
                    let tls_modes = grant
                        .tls_modes
                        .as_ref()
                        .map(|modes| to_json("grants.tls_modes", modes))
                        .transpose()?;
                    sqlx::query!(
                        "INSERT INTO grants (connector_id, patterns, tls_modes) VALUES (?, ?, ?) ON CONFLICT (connector_id) DO UPDATE SET patterns = excluded.patterns, tls_modes = excluded.tls_modes",
                        id,
                        patterns,
                        tls_modes
                    )
                    .execute(&mut *tx)
                    .await?;
                }
                None => {
                    sqlx::query!("DELETE FROM grants WHERE connector_id = ?", id)
                        .execute(&mut *tx)
                        .await?;
                }
            }
        }

        for (id, announcement) in &changes.announcements {
            let id = id.to_string();
            sqlx::query!("DELETE FROM announcements WHERE connector_id = ?", id)
                .execute(&mut *tx)
                .await?;
            for (hostname, announced) in announcement.iter() {
                let tls = tls_name(announced.tls);
                let meta = to_json("announcements.meta", &announced.meta)?;
                sqlx::query!(
                    "INSERT INTO announcements (connector_id, hostname, tls, meta) VALUES (?, ?, ?, ?)",
                    id,
                    hostname,
                    tls,
                    meta
                )
                .execute(&mut *tx)
                .await?;
            }
        }

        for (hostname, route) in &changes.routes {
            let hostname = hostname.as_str();
            match route {
                Some(route) => {
                    let tls = tls_name(route.tls);
                    let meta = to_json("routes.meta", &route.meta)?;
                    let offline_since = route
                        .offline_since
                        .map(|since| i64::try_from(since).unwrap_or(i64::MAX));
                    sqlx::query!(
                        "INSERT INTO routes (hostname, tls, meta, offline_since) VALUES (?, ?, ?, ?) ON CONFLICT (hostname) DO UPDATE SET tls = excluded.tls, meta = excluded.meta, offline_since = excluded.offline_since",
                        hostname,
                        tls,
                        meta,
                        offline_since
                    )
                    .execute(&mut *tx)
                    .await?;
                }
                None => {
                    sqlx::query!("DELETE FROM routes WHERE hostname = ?", hostname)
                        .execute(&mut *tx)
                        .await?;
                }
            }
        }

        tx.commit().await?;
        Ok(())
    }
}

#[derive(Default)]
struct Changes<'a> {
    enrollments: Vec<(ConnectorId, Enrollment)>,
    grants: Vec<(ConnectorId, Option<&'a Grant>)>,
    announcements: Vec<(ConnectorId, &'a BTreeMap<Hostname, Announced>)>,
    routes: Vec<(&'a Hostname, Option<&'a RouteRecord>)>,
}

impl<'a> Changes<'a> {
    fn between(old: &'a Model, new: &'a Model) -> Self {
        let mut changes = Self::default();
        for (id, record) in &new.connectors {
            let before = old.connectors.get(id);
            if before.is_none_or(|before| before.enrollment != record.enrollment) {
                changes.enrollments.push((*id, record.enrollment));
            }
            if before.and_then(|before| before.grant.as_ref()) != record.grant.as_ref() {
                changes.grants.push((*id, record.grant.as_ref()));
            }
            if before.map_or(!record.announcement.is_empty(), |before| {
                before.announcement != record.announcement
            }) {
                changes.announcements.push((*id, &record.announcement));
            }
        }
        for (hostname, route) in &new.routes {
            if old.routes.get(hostname).is_none_or(|before| {
                before.tls != route.tls
                    || before.meta != route.meta
                    || before.offline_since != route.offline_since
            }) {
                changes.routes.push((hostname, Some(route)));
            }
        }
        for hostname in old.routes.keys() {
            if !new.routes.contains_key(hostname) {
                changes.routes.push((hostname, None));
            }
        }
        changes
    }

    fn is_empty(&self) -> bool {
        self.enrollments.is_empty()
            && self.grants.is_empty()
            && self.announcements.is_empty()
            && self.routes.is_empty()
    }
}

fn enrollment_name(enrollment: Enrollment) -> &'static str {
    match enrollment {
        Enrollment::Pending => "pending",
        Enrollment::Approved => "approved",
        Enrollment::Denied => "denied",
        Enrollment::Revoked => "revoked",
    }
}

fn parse_enrollment(value: &str) -> Result<Enrollment, DbError> {
    match value {
        "pending" => Ok(Enrollment::Pending),
        "approved" => Ok(Enrollment::Approved),
        "denied" => Ok(Enrollment::Denied),
        "revoked" => Ok(Enrollment::Revoked),
        other => Err(DbError::Corrupt {
            column: "connectors.enrollment",
            value: other.to_owned(),
        }),
    }
}

fn parse_tls(column: &'static str, value: &str) -> Result<TlsMode, DbError> {
    match value {
        "terminate" => Ok(TlsMode::Terminate),
        "passthrough" => Ok(TlsMode::Passthrough),
        other => Err(DbError::Corrupt {
            column,
            value: other.to_owned(),
        }),
    }
}

fn parse_id(value: &str) -> Result<ConnectorId, DbError> {
    ConnectorId::from_str(value).map_err(|_| DbError::Corrupt {
        column: "connector id",
        value: value.to_owned(),
    })
}

fn parse_json<T: serde::de::DeserializeOwned>(
    column: &'static str,
    value: &str,
) -> Result<T, DbError> {
    serde_json::from_str(value).map_err(|source| DbError::Json { column, source })
}

fn to_json<T: serde::Serialize>(column: &'static str, value: &T) -> Result<String, DbError> {
    serde_json::to_string(value).map_err(|source| DbError::Json { column, source })
}
