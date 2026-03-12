# did-web-rpk-tls crate specification

## 1. Purpose
Provide a small Rust crate that offers a simple API for mTLS using RFC 7250 raw public keys (RPK) and did:web for out-of-band trust. The crate should make it easy to build services that:
- publish a did:web document (did.json)
- verify peer identities by resolving did:web documents
- use rustls raw public key support for TLS 1.3 mutual authentication

This crate is intended for service-to-service use in controlled environments (e.g., Kubernetes), where DNS is authoritative and did:web is a natural trust anchor.

## 2. Non-goals
- No X.509 CA support or certificate chain validation.
- No SPIFFE or SPIRE integration (can be added by downstream users).
- No browser or WebPKI compatibility.
- No automatic workload attestation.
- No requirement to support non-did:web methods.

## 3. Key concepts
- **Identity**: a did:web string (e.g., `did:web:service.ns.svc.cluster.local`).
- **RPK**: raw SubjectPublicKeyInfo (SPKI) DER as defined by RFC 7250.
- **DID document**: JSON document served at `/.well-known/did.json` or `/<path>/did.json` per did:web spec.
- **TOFU**: Trust-on-first-use is acceptable by default, with optional pinning and cache refresh controls.

## 4. Public API (crate surface)

### 4.1 Primary types

```
pub struct Node {
    pub did: String,
    pub did_json: Arc<String>,
}

pub struct Listener {
    pub acceptor: tokio_rustls::TlsAcceptor,
    pub did: String,
    pub did_json: Arc<String>,
}

pub struct Dialer {
    pub client_config: Arc<rustls::ClientConfig>,
    pub peer: Peer,
    pub connect_addr: Option<SocketAddr>,
    pub peer_keys: Vec<Vec<u8>>,
}

pub struct Peer {
    pub did: String,
    pub base_url: url::Url,
    pub did_url: url::Url,
    pub server_name: rustls::pki_types::ServerName<'static>,
}
```

### 4.2 Constructors

```
impl Node {
    pub fn new(did: impl Into<String>) -> Result<Self, BoxError>;
    pub fn new_with_trusted_keys(did: impl Into<String>, trusted_keys: HashMap<String, Vec<Vec<u8>>>)
        -> Result<Self, BoxError>;
    pub fn local_public_key_multibase(&self) -> Result<String, BoxError>;
    pub fn set_trusted_keys(&self, peer_did: impl Into<String>, keys: Vec<Vec<u8>>);
    pub fn add_trusted_key(&self, peer_did: impl Into<String>, key: Vec<u8>);
    pub fn listen(&self) -> Result<Listener, BoxError>;
    pub fn dial_with_resolver(&self, peer_did: &str, resolver: &dyn DidResolver)
        -> Result<Dialer, BoxError>;
    pub fn dial_with_resolver_addr(&self, peer_did: &str, connect_addr: Option<SocketAddr>, resolver: &dyn DidResolver)
        -> Result<Dialer, BoxError>;
    pub async fn dial(&self, peer_did: &str)
        -> Result<Dialer, BoxError>;
    pub async fn dial_with_config(&self, peer_did: &str, config: BootstrapConfig)
        -> Result<Dialer, BoxError>;
    pub async fn dial_with_addr(&self, peer_did: &str, connect_addr: SocketAddr)
        -> Result<Dialer, BoxError>;
    pub async fn dial_with_addr_config(&self, peer_did: &str, connect_addr: SocketAddr, config: BootstrapConfig)
        -> Result<Dialer, BoxError>;
    pub async fn dial_with_peer(&self, peer: Peer)
        -> Result<Dialer, BoxError>;
    pub async fn dial_with_peer_config(&self, peer: Peer, config: BootstrapConfig)
        -> Result<Dialer, BoxError>;
    pub async fn dial_with_peer_addr(&self, peer: Peer, connect_addr: SocketAddr)
        -> Result<Dialer, BoxError>;
    pub async fn dial_with_peer_addr_config(&self, peer: Peer, connect_addr: SocketAddr, config: BootstrapConfig)
        -> Result<Dialer, BoxError>;
    pub fn dial_with_keys(&self, peer: Peer, peer_keys: Vec<Vec<u8>>)
        -> Result<Dialer, BoxError>;
    pub fn dial_with_keys_addr(&self, peer: Peer, connect_addr: SocketAddr, peer_keys: Vec<Vec<u8>>)
        -> Result<Dialer, BoxError>;
    pub fn trusted_keys(&self) -> Arc<RwLock<HashMap<String, Vec<Vec<u8>>>>>;
}
```

### 4.3 Helper functions

```
pub fn build_did_from_host(host: &str, port: Option<u16>) -> String;

pub fn peer_from_did(did: &str) -> Result<Peer, BoxError>;

pub fn peer_from_did_url(did_url: &Url) -> Result<Peer, BoxError>;

pub fn did_web_to_urls(did: &str) -> Result<(Url, Url), BoxError>;

pub fn did_web_from_url(url: &Url) -> Result<String, BoxError>;

pub fn server_name_from_host(host: &str) -> Result<ServerName<'static>, BoxError>;
```

### 4.4 HTTP helper

```
pub async fn send_request(
    url: &Url,
    client_config: Arc<ClientConfig>,
    method: Method,
    body: Option<Body>,
    connect_addr: Option<SocketAddr>,
    server_name: Option<ServerName<'static>>,
) -> Result<Response<Body>, BoxError>;

pub struct BootstrapConfig {
    pub retries: usize,
    pub delay: Duration,
}

pub async fn fetch_peer_keys_with_config(
    url: &Url,
    client_config: Arc<ClientConfig>,
    connect_addr: Option<SocketAddr>,
    server_name: ServerName<'static>,
    config: BootstrapConfig,
    expected_did: &str,
) -> Result<Vec<Vec<u8>>, BoxError>;
```

### 4.5 Features

- `default = ["http"]`
- `http`: enables DID resolution helpers and `Node::dial*` methods that perform
  HTTP fetches for `did.json`. Without this feature, callers should use
  `dial_with_keys*` and supply a trusted key set out of band.

### 4.6 Resolver trait

```
pub trait DidResolver: Send + Sync {
    fn resolve(&self, did: &str) -> Result<Vec<Vec<u8>>, BoxError>;
}

pub struct StaticResolver { /* map of did -> keys */ }
```

## 5. Behavior and flows

### 5.1 Listen flow
- `Node::listen()` returns a `Listener` that wraps a rustls `ServerConfig` configured for:
  - TLS 1.3 only
  - RFC 7250 raw public keys
  - ALPN = `h2` only
- The listener must accept client authentication and require raw public keys.
- The caller is responsible for wiring the acceptor into hyper/axum or any other server stack.

### 5.2 Dial flow
- `Node::dial()` resolves a peer from a did:web string.
- It fetches the peer did.json using a bootstrap client config that accepts any peer key (TOFU).
- The resolved peer SPKI keys are cached in the node's trust store.
- A client config is built with a verifier that accepts only the cached keys.
- A `Dialer` is returned with the configured client config and peer metadata.

### 5.3 DID resolution
- did:web resolution rules:
  - `did:web:example.com` => `https://example.com/.well-known/did.json`
  - `did:web:example.com:user:svc` => `https://example.com/user/svc/did.json`
  - `%3A` is decoded into `:` for the host segment only, following did:web encoding rules.
- Only HTTPS URLs are supported for did:web resolution.

### 5.4 DID document parsing
- The resolver looks for `verificationMethod[].publicKeyMultibase`.
- Only Ed25519 keys are accepted.
- The multibase string is decoded into a 32-byte Ed25519 key, then wrapped into SPKI DER for rustls.
- The DID document `id` must match the expected DID.
- If `verificationMethod[].controller` is present and does not match the expected DID, that entry is ignored.
- If no valid keys exist, resolution fails.

### 5.5 Trust model
- Default trust is TOFU:
  - First successful did.json fetch pins the key(s).
  - Subsequent handshakes require key match.
- Pinned trust is supported:
  - The caller can pre-populate `trusted_keys` or use `dial_with_keys` to skip TOFU.
  - The trust store is a shared `RwLock<HashMap<String, Vec<Vec<u8>>>>` keyed by peer DID.
  - Client-side verification only accepts keys for the expected peer DID.

## 6. Rustls integration

### 6.1 Verifiers
Implement custom verifiers:
- `PubkeyVerifier` implements both `ClientCertVerifier` and `ServerCertVerifier`.
- It accepts keys only if they match the pinned SPKI DER.
- It requires raw public keys (`requires_raw_public_keys() -> true`).

### 6.2 Resolvers
- Use `AlwaysResolvesClientRawPublicKeys` and `AlwaysResolvesServerRawPublicKeys`.
- Use `CertifiedKey` to present SPKI DER as the certificate chain.

### 6.3 ALPN
- ALPN is set to `h2` only.
- No ALPN identity binding (explicitly out of scope).

## 7. Configurable parameters
- `BootstrapConfig` (retries/delay) for did.json fetch retries.
- Optional `connect_addr` for direct IP/port while keeping did:web host as identity.
- Future: a cache TTL or background refresh policy for peer keys.

## 8. Error behavior
- All public APIs return `BoxError` for easy integration.
- Error messages should be stable and human-readable (useful in logs).
- Verification failures should identify the SPKI length and a short suffix to assist debugging.

## 9. Example usage

### 9.1 Server
```
let node = Node::new("did:web:service.ns.svc.cluster.local")?;
let listener = node.listen()?;

let addr: SocketAddr = "0.0.0.0:8443".parse()?;
let tls_acceptor = listener.acceptor.clone();

// Wire into hyper or axum
```

### 9.2 Client
```
let node = Node::new("did:web:client.ns.svc.cluster.local")?;
let dialer = node.dial("did:web:service.ns.svc.cluster.local").await?;

let response = send_request(
    &dialer.peer.base_url.join("ping")?,
    dialer.client_config.clone(),
    Method::POST,
    Some(Body::from("ping")),
    dialer.connect_addr,
    Some(dialer.peer.server_name.clone()),
).await?;
```

## 10. Security considerations
- did.json is public and non-secret. Only private keys must remain secret.
- TOFU is acceptable for controlled environments; for higher assurance, implement a preconfigured trust bundle.
- If DNS is compromised, identity guarantees are compromised (same as all DNS-based identity).
- Key rotation is handled by updating did.json; clients must refresh or restart to pick up new keys.

## 11. Testing plan
- Unit tests:
  - did:web parsing and URL conversion
  - multibase encode/decode
  - SPKI conversion from raw Ed25519 key
- Integration tests:
  - two-process ping-pong (server + client) with RPK mTLS
  - TOFU cache behavior with key pinning
  - did.json fetch retries

## 12. Versioning and packaging
- Crate name suggestion: `did-web-rpk-tls` or `did-rpk-tls`.
- License: MIT.
- Examples:
  - `examples/ping_pong.rs` demonstrating two nodes.
- README with quickstart and security model.

## 13. Implementation notes
- Use `ed25519-dalek` for key generation and SPKI encoding.
- Use `bs58` + multicodec prefix `[0xed, 0x01]` for multibase encoding.
- Use `percent-encoding` for did:web decoding in host and path segments.
- Keep all APIs async-friendly; avoid blocking in rustls verifiers by using cached keys.
