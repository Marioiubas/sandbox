//! `brokerd`: normally started by `broker run`; runs in the foreground.

use brokerd::dirs::BrokerDirs;
use brokerd::server::Server;
use brokerd::session::Daemon;
use std::sync::Arc;
use std::time::Duration;

fn usage() -> ! {
    eprintln!(
        "usage: brokerd [--idle-exit-secs N]\n\nThe per-user broker daemon. It is started on demand by `broker run`."
    );
    std::process::exit(2)
}

fn main() {
    let mut idle = std::env::var("BROKER_DAEMON_IDLE_SECS").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(900);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--idle-exit-secs" => idle = args.next().and_then(|v| v.parse().ok()).unwrap_or_else(|| usage()),
            "--version" => {
                println!("brokerd {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            _ => usage(),
        }
    }
    if let Err(e) = run(Duration::from_secs(idle)) {
        eprintln!("brokerd: {e:#}");
        std::process::exit(1);
    }
}

fn run(idle: Duration) -> anyhow::Result<()> {
    let dirs = BrokerDirs::from_env()?;
    dirs.ensure()?;
    // I9: without a verifiable audit chain the daemon does not start.
    let recorder = Arc::new(audit::SqliteRecorder::open(&dirs.audit_db())?);
    let shim = launcher::default_shim_path()?;
    let backend: Arc<dyn launcher::SandboxBackend> = Arc::from(launcher::host_backend());
    let resolver = Arc::new(netguard::resolver::SystemResolver::new());
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async move {
        let daemon = Arc::new(Daemon::new(dirs, recorder, backend, resolver, shim));
        let server = Server::new(daemon, idle);
        let listener = server.bind()?;
        server.run(listener).await
    })
}
