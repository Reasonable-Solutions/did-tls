#![cfg(feature = "http")]

use did_web_rpk_tls::{send_request, Node, Result};
use hyper::body::to_bytes;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, StatusCode};
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::test]
async fn ping_pong_over_rpk_mtls() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
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
        }
    });

    let client_node = Node::new("did:web:client.example".to_string())?;
    let dialer = client_node.dial(&did).await?;

    let url = dialer.peer.base_url.join("ping")?;
    let response = send_request(
        &url,
        dialer.client_config.clone(),
        Method::POST,
        Some(Body::from("ping")),
        dialer.connect_addr,
        Some(dialer.peer.server_name.clone()),
    )
    .await?;
    let bytes = to_bytes(response.into_body()).await?;
    assert_eq!(bytes.as_ref(), b"pong");

    let _ = shutdown_tx.send(());
    let _ = server_task.await;

    Ok(())
}

async fn handle(req: Request<Body>, did_json: Arc<String>) -> Result<Response<Body>> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/.well-known/did.json") => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/did+json")
            .body(Body::from(did_json.as_str().to_owned()))
            .unwrap(),
        (&Method::POST, "/ping") => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(Body::from("pong"))
            .unwrap(),
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("not found"))
            .unwrap(),
    };
    Ok(response)
}
