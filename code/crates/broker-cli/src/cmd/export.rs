//! `broker audit export`: decisions from the verified chain as OCSF events,
//! printed as NDJSON or delivered to a SIEM (Splunk HEC-style `hec`, or an
//! OTLP/HTTP `otlp` logs endpoint). Every event is validated before it
//! leaves; one invalid event stops the export. Delivery uses verified TLS;
//! plain HTTP is accepted only for a loopback sink (tests, local collectors).

use super::{EXIT_BROKER, ctl};
use audit::SqliteRecorder;
use bytes::Bytes;
use creds::secrets::{OsSecrets, SecretReader};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use netguard::resolver::PolicyResolver;

pub struct Args {
    pub format: String,
    pub to: Option<String>,
    pub token: Option<String>,
    pub from_seq: i64,
}

pub fn export(a: Args) -> i32 {
    match run(a) {
        Ok(n) => {
            eprintln!("broker: exported {n} events");
            0
        }
        Err(e) => {
            eprintln!("broker: {e:#}");
            EXIT_BROKER
        }
    }
}

fn run(a: Args) -> anyhow::Result<usize> {
    let dirs = ctl::dirs()?;
    let db = dirs.audit_db();
    let n = SqliteRecorder::verify_path(&db).map_err(|e| anyhow::anyhow!("audit chain does not verify: {e}"))?;
    let rec = SqliteRecorder::open_read_only(&db)?;
    // Only the prefix that verified; rows appended since are left for the next export.
    let rows = rec.range(a.from_seq, i64::try_from(n).unwrap_or(i64::MAX))?;
    let mut events = Vec::new();
    for s in &rows {
        if let Some(v) = audit::ocsf::to_ocsf(s) {
            audit::ocsf::validate(&v).map_err(|e| anyhow::anyhow!("event {} does not validate: {e}", s.seq))?;
            events.push(v);
        }
    }
    let body = match a.format.as_str() {
        "ocsf" | "hec" => events
            .iter()
            .map(|e| {
                if a.format == "hec" {
                    let secs = e["time"].as_i64().unwrap_or(0) as f64 / 1000.0;
                    serde_json::json!({ "time": secs, "source": "broker", "sourcetype": format!("ocsf:{}", e["class_uid"]), "event": e }).to_string()
                } else {
                    e.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        "otlp" => audit::otlp::logs_request(&events).to_string(),
        f => anyhow::bail!("unknown format {f:?} (ocsf, hec, otlp)"),
    };
    let Some(to) = a.to else {
        println!("{body}");
        return Ok(events.len());
    };
    let auth = match (&a.token, a.format.as_str()) {
        (Some(r), fmt) => {
            let sref = policy::SecretRef::parse(r).map_err(|e| anyhow::anyhow!(e))?;
            let home = brokerd::dirs::passwd_home()?;
            let s = OsSecrets { config_dir: dirs.config_dir.clone(), home }.read(&sref)?;
            let tok = String::from_utf8(s.expose().to_vec()).map_err(|_| anyhow::anyhow!("token is not UTF-8"))?;
            Some(if fmt == "hec" { format!("Splunk {tok}") } else { format!("Bearer {tok}") })
        }
        (None, _) => None,
    };
    let user = brokerd::session_util::load_user_policy(&dirs)?;
    let mut roots = Vec::new();
    for r in &user.tls.extra_roots {
        roots.extend(
            tls::trust_bundle::load_pem_certs(&dirs.config_dir.join(r))
                .or_else(|_| tls::trust_bundle::load_pem_certs(std::path::Path::new(r)))?,
        );
    }
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let status = rt.block_on(post(&to, auth, body, &roots))?;
    if !(200..300).contains(&status) {
        anyhow::bail!("sink answered HTTP {status}");
    }
    Ok(events.len())
}

async fn post(
    url: &str,
    auth: Option<String>,
    body: String,
    roots: &[rustls_pki_types::CertificateDer<'static>],
) -> anyhow::Result<u16> {
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        anyhow::bail!("sink URL must be https:// (or http:// on loopback)");
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (h, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>()?),
        None => (authority, if https { 443 } else { 80 }),
    };
    let host = netguard::canon_host(h.as_bytes()).map_err(|e| anyhow::anyhow!("sink host: {e}"))?;
    let addrs = netguard::resolver::SystemResolver::new()
        .resolve(&host)
        .await
        .map_err(|r| anyhow::anyhow!("resolving the sink: {r:?}"))?;
    if !https && !addrs.iter().all(|a| a.is_loopback()) {
        anyhow::bail!("plain HTTP is only allowed for a loopback sink; use https://");
    }
    let tcp = brokerd::upstream::connect_addrs(&addrs, port)
        .await
        .ok_or_else(|| anyhow::anyhow!("cannot connect to the sink"))?;
    let req = {
        let mut b = hyper::Request::builder()
            .method("POST")
            .uri(path)
            .header("host", authority)
            .header("content-type", "application/json");
        if let Some(a) = auth {
            b = b.header("authorization", a);
        }
        b.body(Full::new(Bytes::from(body)))?
    };
    let status = if https {
        let cfg = tls::upstream::client_config(roots)?;
        let stream = brokerd::upstream::tls_connect(&cfg, &host, tcp)
            .await
            .map_err(|r| anyhow::anyhow!("TLS to the sink: {r:?}"))?;
        let (mut s, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(conn);
        let resp = s.send_request(req).await?;
        let st = resp.status().as_u16();
        let _ = resp.into_body().collect().await;
        st
    } else {
        let (mut s, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
        tokio::spawn(conn);
        let resp = s.send_request(req).await?;
        let st = resp.status().as_u16();
        let _ = resp.into_body().collect().await;
        st
    };
    Ok(status)
}
