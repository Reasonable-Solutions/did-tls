use clap::Parser;
use hyper::body::to_bytes;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, StatusCode};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::sleep;
use url::Url;

use did_web_rpk_tls::{
    build_did_from_host, peer_from_did, peer_from_did_url, send_request, BoxError, BootstrapConfig,
    Dialer, Node, Peer,
};

#[derive(Parser, Debug)]
#[command(name = "mtls-did", about = "did:web + Ed25519 mTLS (HTTP/2) ping-pong demo")]
struct Args {
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = 8443)]
    port: u16,
    #[arg(long)]
    did: Option<String>,
    #[arg(long)]
    did_host: Option<String>,
    #[arg(long)]
    did_port: Option<u16>,
    #[arg(long)]
    peer_did: Option<String>,
    #[arg(long)]
    peer_url: Option<String>,
    #[arg(long)]
    peer_did_url: Option<String>,
    #[arg(long)]
    peer_addr: Option<String>,
    #[arg(long)]
    peer_host: Option<String>,
    #[arg(long, default_value_t = 30)]
    bootstrap_retries: usize,
    #[arg(long, default_value_t = 1)]
    bootstrap_delay_secs: u64,
    #[arg(long, default_value_t = 5)]
    ping_interval_secs: u64,
}

#[derive(Clone)]
struct AppState {
    did_json: Arc<String>,
}

struct PeerConfig {
    peer: Peer,
    connect_addr: Option<SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let args = Args::parse();

    let did = match (args.did_host.as_deref(), args.did.clone()) {
        (Some(host), _) => {
            if args.did.is_some() {
                eprintln!("note: --did-host overrides --did");
            }
            build_did_from_host(host, args.did_port)
        }
        (None, Some(did)) => did,
        (None, None) => return Err("missing --did or --did-host".into()),
    };

    let node = Node::new(did)?;
    eprintln!(
        "local publicKeyMultibase: {}",
        node.local_public_key_multibase()?
    );

    let listener = node.listen()?;
    let state = Arc::new(AppState {
        did_json: listener.did_json.clone(),
    });

    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
    println!("listening on https://{}", addr);
    println!("serving did.json for {}", listener.did);

    let server_state = state.clone();
    let server_task = tokio::spawn(async move {
        if let Err(err) = run_server(addr, listener.acceptor, server_state).await {
            eprintln!("server error: {}", err);
        }
    });

    if let Some(peer_config) = build_peer_config(&args)? {
        let bootstrap = BootstrapConfig {
            retries: args.bootstrap_retries,
            delay: Duration::from_secs(args.bootstrap_delay_secs),
        };
        let dialer = match peer_config.connect_addr {
            Some(addr) => {
                node.dial_with_peer_addr_config(peer_config.peer, addr, bootstrap)
                    .await?
            }
            None => node
                .dial_with_peer_config(peer_config.peer, bootstrap)
                .await?,
        };
        eprintln!("loaded {} peer public key(s)", dialer.peer_keys.len());
        for (idx, key) in dialer.peer_keys.iter().enumerate() {
            eprintln!(
                "peer key {} spki_len={} spki_suffix={}",
                idx + 1,
                key.len(),
                short_hex(key)
            );
        }

        let interval = Duration::from_secs(args.ping_interval_secs);
        tokio::spawn(async move {
            if let Err(err) = ping_loop(dialer, interval).await {
                eprintln!("ping loop error: {}", err);
            }
        });
    }

    server_task.await.map_err(|e| -> BoxError { e.into() })?;
    Ok(())
}

async fn run_server(
    addr: SocketAddr,
    acceptor: tokio_rustls::TlsAcceptor,
    state: Arc<AppState>,
) -> Result<(), BoxError> {
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let state = state.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let service = service_fn(move |req| handle(req, state.clone()));
                    if let Err(err) = Http::new()
                        .http2_only(true)
                        .serve_connection(tls_stream, service)
                        .await
                    {
                        eprintln!("connection error: {}", err);
                    }
                }
                Err(err) => eprintln!("tls error: {}", err),
            }
        });
    }
}

async fn handle(req: Request<Body>, state: Arc<AppState>) -> Result<Response<Body>, hyper::Error> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/.well-known/did.json") => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/did+json")
            .body(Body::from(state.did_json.as_str().to_owned()))
            .unwrap(),
        (&Method::POST, "/ping") => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(Body::from("pong"))
            .unwrap(),
        (&Method::POST, "/pong") => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(Body::from("ping"))
            .unwrap(),
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("not found"))
            .unwrap(),
    };
    Ok(response)
}

async fn ping_loop(dialer: Dialer, interval: Duration) -> Result<(), BoxError> {
    loop {
        let url = dialer.peer.base_url.join("ping")?;
        let body = Body::from("ping");
        let response = send_request(
            &url,
            dialer.client_config.clone(),
            Method::POST,
            Some(body),
            dialer.connect_addr,
            Some(dialer.peer.server_name.clone()),
        )
        .await?;
        let bytes = to_bytes(response.into_body()).await?;
        println!("ping -> {}", String::from_utf8_lossy(bytes.as_ref()));
        sleep(interval).await;
    }
}

fn build_peer_config(args: &Args) -> Result<Option<PeerConfig>, BoxError> {
    if args.peer_did.is_none()
        && args.peer_url.is_none()
        && args.peer_did_url.is_none()
        && args.peer_addr.is_none()
        && args.peer_host.is_none()
    {
        return Ok(None);
    }

    let connect_addr = match args.peer_addr.as_deref() {
        Some(addr) => Some(addr.parse()?),
        None => None,
    };

    let url_override = match args.peer_url.as_deref() {
        Some(peer_url) => Some(Url::parse(peer_url)?),
        None => None,
    };

    let mut peer = if let Some(peer_did) = args.peer_did.as_deref() {
        peer_from_did(peer_did)?
    } else if let Some(peer_did_url) = args.peer_did_url.as_deref() {
        peer_from_did_url(&Url::parse(peer_did_url)?)?
    } else if let Some(peer_url) = url_override.as_ref() {
        let did_url = did_url_from_base_url(peer_url)?;
        peer_from_did_url(&did_url)?
    } else {
        let peer_host = args
            .peer_host
            .as_deref()
            .ok_or("missing --peer-host for derived peer")?;
        let addr: SocketAddr =
            connect_addr.ok_or("missing --peer-addr for derived peer url")?;
        let did = build_did_from_host(peer_host, Some(addr.port()));
        peer_from_did(&did)?
    };

    if let Some(url) = url_override {
        peer.base_url = url;
    }

    Ok(Some(PeerConfig { peer, connect_addr }))
}

fn did_url_from_base_url(base_url: &Url) -> Result<Url, BoxError> {
    let mut url = base_url.clone();
    let path = url.path().trim_end_matches('/');
    if path.is_empty() {
        url.set_path("/.well-known/did.json");
    } else {
        url.set_path(&format!("{}/did.json", path));
    }
    Ok(url)
}

fn short_hex(bytes: &[u8]) -> String {
    const SUFFIX_LEN: usize = 8;
    bytes
        .iter()
        .rev()
        .take(SUFFIX_LEN)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}
