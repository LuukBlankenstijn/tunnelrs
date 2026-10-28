use std::{
    convert::Infallible,
    sync::{Arc, PoisonError},
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::{
    HeaderMap, Request, Response, StatusCode, Uri, Version,
    body::Incoming,
    client::conn::http1::SendRequest,
    header::{
        CONNECTION, CONTENT_TYPE, COOKIE, HOST, HeaderName, HeaderValue, TE, TRAILER,
        TRANSFER_ENCODING, UPGRADE,
    },
    http::uri::{Authority, PathAndQuery},
    service::service_fn,
    upgrade::OnUpgrade,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use tokio::net::TcpListener;
use tunnelrs_proto::TlsMode;

use crate::routing::{self, ForwardTable, Lookup, Pool, SessionHandle};

type ResponseBody = UnsyncBoxBody<Bytes, hyper::Error>;

const MAX_IDLE_PER_HOSTNAME: usize = 32;
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

pub async fn serve(listener: TcpListener, table: Arc<ForwardTable>) -> anyhow::Result<()> {
    let builder = Arc::new(auto::Builder::new(TokioExecutor::new()));
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                tracing::warn!(%err, "http listener accept failed");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        if let Err(err) = tcp.set_nodelay(true) {
            tracing::debug!(%peer, %err, "setting TCP_NODELAY failed");
        }
        let table = table.clone();
        let builder = builder.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| handle(table.clone(), req));
            if let Err(err) = builder
                .serve_connection_with_upgrades(TokioIo::new(tcp), service)
                .await
            {
                tracing::debug!(%peer, %err, "http connection ended with error");
            }
        });
    }
}

async fn handle(
    table: Arc<ForwardTable>,
    mut req: Request<Incoming>,
) -> Result<Response<ResponseBody>, Infallible> {
    let Some(hostname) = request_hostname(&req) else {
        return Ok(status_response(StatusCode::BAD_REQUEST));
    };
    let pool = match routing::lookup(&table, &hostname, TlsMode::Terminate) {
        Lookup::Live(pool) => pool,
        Lookup::NoLiveConnector => return Ok(status_response(StatusCode::SERVICE_UNAVAILABLE)),
        Lookup::Unknown => return Ok(status_response(StatusCode::NOT_FOUND)),
    };
    let downstream_upgrade = is_upgrade(req.headers()).then(|| hyper::upgrade::on(&mut req));
    let req = upstream_request(req, downstream_upgrade.is_some());
    Ok(forward(&pool, &hostname, req, downstream_upgrade).await)
}

fn request_hostname(req: &Request<Incoming>) -> Option<String> {
    let authority = match req.uri().authority() {
        Some(authority) => authority.clone(),
        None => req
            .headers()
            .get(HOST)?
            .to_str()
            .ok()?
            .parse::<Authority>()
            .ok()?,
    };
    let hostname = authority.host().trim_end_matches('.');
    (!hostname.is_empty()).then(|| hostname.to_ascii_lowercase())
}

fn is_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key(UPGRADE)
        && connection_tokens(headers).any(|token| token.eq_ignore_ascii_case("upgrade"))
}

fn connection_tokens(headers: &HeaderMap) -> impl Iterator<Item = &str> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

fn upstream_request(req: Request<Incoming>, upgrade: bool) -> Request<Incoming> {
    let (mut parts, body) = req.into_parts();
    if let Some(authority) = parts.uri.authority() {
        let host = match authority.port_u16() {
            Some(port) => format!("{}:{port}", authority.host()),
            None => authority.host().to_owned(),
        };
        if let Ok(host) = HeaderValue::try_from(host) {
            parts.headers.insert(HOST, host);
        }
    }
    let path = parts
        .uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));
    parts.uri = Uri::from(path);
    if parts.version == Version::HTTP_2 {
        merge_cookies(&mut parts.headers);
    }
    parts.version = Version::HTTP_11;
    strip_hop_by_hop(&mut parts.headers, upgrade);
    Request::from_parts(parts, body)
}

fn merge_cookies(headers: &mut HeaderMap) {
    let merged = {
        let cookies: Vec<&[u8]> = headers
            .get_all(COOKIE)
            .iter()
            .map(HeaderValue::as_bytes)
            .collect();
        if cookies.len() < 2 {
            return;
        }
        cookies.join(&b"; "[..])
    };
    if let Ok(merged) = HeaderValue::from_bytes(&merged) {
        headers.insert(COOKIE, merged);
    }
}

fn strip_hop_by_hop(headers: &mut HeaderMap, upgrade: bool) {
    let listed: Vec<HeaderName> = connection_tokens(headers)
        .filter_map(|token| HeaderName::from_bytes(token.as_bytes()).ok())
        .collect();
    for name in listed {
        if !(upgrade && name == UPGRADE) {
            headers.remove(name);
        }
    }
    for name in [CONNECTION, TE, TRAILER, TRANSFER_ENCODING] {
        headers.remove(name);
    }
    for name in ["keep-alive", "proxy-connection"] {
        headers.remove(name);
    }
    if upgrade {
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    } else {
        headers.remove(UPGRADE);
    }
}

async fn forward(
    pool: &Pool,
    hostname: &str,
    mut req: Request<Incoming>,
    downstream_upgrade: Option<OnUpgrade>,
) -> Response<ResponseBody> {
    for session in pool.round_robin() {
        loop {
            let (mut sender, reused) = match take_idle(session, hostname) {
                Some(sender) => (sender, true),
                None => match connect(session, hostname).await {
                    Ok(sender) => (sender, false),
                    Err(err) => {
                        tracing::warn!(
                            session = session.id,
                            connector = %session.connector,
                            hostname,
                            "opening http data stream failed: {err:#}"
                        );
                        break;
                    }
                },
            };
            match sender.try_send_request(req).await {
                Ok(resp) => return respond(session, hostname, sender, resp, downstream_upgrade),
                Err(mut err) => {
                    let Some(unsent) = err.take_message() else {
                        tracing::warn!(
                            session = session.id,
                            hostname,
                            err = %err.error(),
                            "forwarding http request failed"
                        );
                        return status_response(StatusCode::BAD_GATEWAY);
                    };
                    tracing::debug!(
                        session = session.id,
                        hostname,
                        err = %err.error(),
                        reused,
                        "upstream connection closed before request was sent"
                    );
                    req = unsent;
                    if !reused {
                        break;
                    }
                }
            }
        }
    }
    status_response(StatusCode::BAD_GATEWAY)
}

async fn connect(session: &SessionHandle, hostname: &str) -> anyhow::Result<SendRequest<Incoming>> {
    let (send, recv) = session.open_data_stream(hostname).await?;
    let (sender, conn) =
        hyper::client::conn::http1::handshake(TokioIo::new(tokio::io::join(recv, send))).await?;
    let session_id = session.id;
    tokio::spawn(async move {
        if let Err(err) = conn.with_upgrades().await {
            tracing::debug!(session = session_id, %err, "upstream http connection failed");
        }
    });
    Ok(sender)
}

fn respond(
    session: &SessionHandle,
    hostname: &str,
    sender: SendRequest<Incoming>,
    mut resp: Response<Incoming>,
    downstream_upgrade: Option<OnUpgrade>,
) -> Response<ResponseBody> {
    let switching = resp.status() == StatusCode::SWITCHING_PROTOCOLS;
    match (switching, downstream_upgrade) {
        (true, Some(downstream)) => {
            let upstream = hyper::upgrade::on(&mut resp);
            tokio::spawn(tunnel(downstream, upstream));
        }
        (true, None) => {
            tracing::warn!(
                session = session.id,
                hostname,
                "backend switched protocols without an upgrade request"
            );
            return status_response(StatusCode::BAD_GATEWAY);
        }
        (false, Some(_)) => {}
        (false, None) => release(session, hostname, sender),
    }
    strip_hop_by_hop(resp.headers_mut(), switching);
    resp.map(BodyExt::boxed_unsync)
}

async fn tunnel(downstream: OnUpgrade, upstream: OnUpgrade) {
    let (downstream, upstream) = match tokio::try_join!(downstream, upstream) {
        Ok(upgraded) => upgraded,
        Err(err) => {
            tracing::debug!(%err, "http upgrade failed");
            return;
        }
    };
    let mut downstream = TokioIo::new(downstream);
    let mut upstream = TokioIo::new(upstream);
    if let Err(err) = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await {
        tracing::debug!(%err, "upgraded connection ended with error");
    }
}

fn take_idle(session: &SessionHandle, hostname: &str) -> Option<SendRequest<Incoming>> {
    let mut idle = session
        .idle_http
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let senders = idle.get_mut(hostname)?;
    senders.retain(|sender| !sender.is_closed());
    let sender = senders
        .iter()
        .position(|sender| sender.is_ready())
        .map(|index| senders.swap_remove(index));
    if senders.is_empty() {
        idle.remove(hostname);
    }
    sender
}

fn release(session: &SessionHandle, hostname: &str, sender: SendRequest<Incoming>) {
    if sender.is_closed() {
        return;
    }
    let mut idle = session
        .idle_http
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let senders = idle.entry(hostname.to_owned()).or_default();
    if senders.len() >= MAX_IDLE_PER_HOSTNAME {
        senders.retain(|sender| !sender.is_closed());
    }
    if senders.len() < MAX_IDLE_PER_HOSTNAME {
        senders.push(sender);
    }
}

fn status_response(status: StatusCode) -> Response<ResponseBody> {
    let body: ResponseBody = Full::new(Bytes::from(format!("{status}\n")))
        .map_err(|never| match never {})
        .boxed_unsync();
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}
