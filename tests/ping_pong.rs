#![cfg(feature = "http")]

use bytes::Bytes;
use did_web_rpk_tls::{send_request, Node, Result};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http2::Builder as Http2Builder;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn ping_pong_over_rpk_mtls() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping ping_pong_over_rpk_mtls: {}", err);
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let addr = listener.local_addr()?;

    let did = format!("did:web:localhost%3A{}", addr.port());
    let server_node = Node::new(did.clone())?;
    let acceptor = server_node.listen()?.acceptor;
    let did_json = server_node.did_json.clone();

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                res = listener.accept() => {
                    let (stream, _) = match res {
                        Ok(pair) => pair,
                        Err(err) => {
                            eprintln!("listener error: {}", err);
                            break;
                        }
                    };
                    let acceptor = acceptor.clone();
                    let did_json = did_json.clone();
                    tokio::spawn(async move {
                        match acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                let service = service_fn(move |req| handle(req, did_json.clone()));
                                if let Err(err) = Http2Builder::new(TokioExecutor::new())
                                    .serve_connection(TokioIo::new(tls_stream), service)
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
        }
    });

    let client_node = Node::new("did:web:client.example".to_string())?;
    let dialer = timeout(
        Duration::from_secs(5),
        client_node.dial_with_addr_config(
            &did,
            addr,
            did_web_rpk_tls::BootstrapConfig {
                retries: 5,
                delay: Duration::from_millis(100),
            },
        ),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "dial timeout"))??;

    let url = dialer.peer.base_url.join("ping")?;
    let response = timeout(
        Duration::from_secs(5),
        send_request(
            &url,
            dialer.client_config.clone(),
            Method::POST,
            Some(Full::new(Bytes::from("ping"))),
            dialer.connect_addr,
            Some(dialer.peer.server_name.clone()),
        ),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "request timeout"))??;
    let body = response.into_body().collect().await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?
        .to_bytes();
    assert_eq!(body.as_ref(), b"pong");

    let _ = shutdown_tx.send(());
    let _ = timeout(Duration::from_secs(5), server_task).await;

    Ok(())
}

async fn handle(
    req: Request<hyper::body::Incoming>,
    did_json: Arc<String>,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/.well-known/did.json") => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/did+json")
            .body(Full::new(Bytes::from(did_json.as_str().to_owned())))
            .unwrap(),
        (&Method::POST, "/ping") => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(Full::new(Bytes::from("pong")))
            .unwrap(),
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("not found")))
            .unwrap(),
    };
    Ok(response)
}

#[tokio::test]
async fn reject_unknown_peer_keys() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping reject_unknown_peer_keys: {}", err);
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    let addr = listener.local_addr()?;

    let server_did = format!("did:web:localhost%3A{}", addr.port());
    let server_node = Node::new(server_did.clone())?;
    let acceptor = server_node.listen()?.acceptor;
    let did_json = server_node.did_json.clone();

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                res = listener.accept() => {
                    let (stream, _) = match res {
                        Ok(pair) => pair,
                        Err(err) => {
                            eprintln!("listener error: {}", err);
                            break;
                        }
                    };
                    let acceptor = acceptor.clone();
                    let did_json = did_json.clone();
                    tokio::spawn(async move {
                        match acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                let service = service_fn(move |req| handle(req, did_json.clone()));
                                let _ = Http2Builder::new(TokioExecutor::new())
                                    .serve_connection(TokioIo::new(tls_stream), service)
                                    .await;
                            }
                            Err(err) => eprintln!("tls error: {}", err),
                        }
                    });
                }
            }
        }
    });

    let client_node = Node::new("did:web:client.example".to_string())?;
    let bogus_did = format!("did:web:localhost%3A{}", addr.port() + 1);
    let bogus_peer = did_web_rpk_tls::peer_from_did(&bogus_did)?;
    let bogus_keys = vec![vec![0u8; 44]];

    let dialer = client_node.dial_with_keys_addr(bogus_peer, addr, bogus_keys)?;
    let url = dialer.peer.base_url.join("ping")?;

    let result = timeout(
        Duration::from_secs(5),
        send_request(
            &url,
            dialer.client_config.clone(),
            Method::POST,
            Some(Full::new(Bytes::from("ping"))),
            dialer.connect_addr,
            Some(dialer.peer.server_name.clone()),
        ),
    )
    .await;

    let _ = shutdown_tx.send(());
    let _ = timeout(Duration::from_secs(5), server_task).await;

    match result {
        Ok(Ok(_)) => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "expected handshake to fail for unknown peer key",
        )
        .into()),
        Ok(Err(err)) => {
            if let did_web_rpk_tls::Error::TlsPeerRejected(_) = err {
                Ok(())
            } else {
                Err(err)
            }
        }
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "handshake timeout",
        )
        .into()),
    }
}
