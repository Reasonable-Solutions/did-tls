use bs58;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hyper::body::to_bytes;
use hyper::{Body, Method, Request, Response, StatusCode};
use rand_core::OsRng;
use rustls::client::AlwaysResolvesClientRawPublicKeys;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
};
use rustls::{
    ClientConfig, DistinguishedName, DigitallySignedStruct, Error, ServerConfig, SignatureScheme,
};
use rustls::crypto::aws_lc_rs::sign::any_supported_type;
use rustls::sign::CertifiedKey;
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use url::Url;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

const BOOTSTRAP_RETRIES: usize = 30;
const BOOTSTRAP_DELAY_SECS: u64 = 1;

const ED25519_PUBKEY_MULTICODEC: [u8; 2] = [0xed, 0x01];
const DID_WEB_PREFIX: &str = "did:web:";
const ALPN_H2: &[u8] = b"h2";

#[derive(Clone, Copy, Debug)]
pub struct BootstrapConfig {
    pub retries: usize,
    pub delay: Duration,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            retries: BOOTSTRAP_RETRIES,
            delay: Duration::from_secs(BOOTSTRAP_DELAY_SECS),
        }
    }
}

#[derive(Clone)]
pub struct Listener {
    pub acceptor: TlsAcceptor,
    pub did: String,
    pub did_json: Arc<String>,
}

#[derive(Clone)]
pub struct Dialer {
    pub client_config: Arc<ClientConfig>,
    pub peer: Peer,
    pub connect_addr: Option<SocketAddr>,
    pub peer_keys: Vec<Vec<u8>>,
}

#[derive(Clone)]
pub struct Peer {
    pub did: String,
    pub base_url: Url,
    pub did_url: Url,
    pub server_name: ServerName<'static>,
}

#[derive(Clone)]
pub struct Identity {
    pub certified_key: Arc<CertifiedKey>,
    pub public_key: Vec<u8>,
}

pub struct Node {
    pub did: String,
    pub did_json: Arc<String>,
    identity: Identity,
    trusted_keys: Arc<RwLock<Vec<Vec<u8>>>>,
}

impl Node {
    pub fn new(did: impl Into<String>) -> Result<Self, BoxError> {
        Self::new_with_trusted_keys(did, Vec::new())
    }

    pub fn new_with_trusted_keys(
        did: impl Into<String>,
        trusted_keys: Vec<Vec<u8>>,
    ) -> Result<Self, BoxError> {
        let did = did.into();
        let identity = generate_identity()?;
        let did_json = Arc::new(build_did_json(&did, &identity.public_key)?);
        Ok(Self {
            did,
            did_json,
            identity,
            trusted_keys: Arc::new(RwLock::new(trusted_keys)),
        })
    }

    pub fn local_public_key_multibase(&self) -> Result<String, BoxError> {
        encode_multibase_ed25519(&self.identity.public_key)
    }

    pub fn set_trusted_keys(&self, keys: Vec<Vec<u8>>) {
        let mut guard = self.trusted_keys.write().unwrap();
        *guard = keys;
    }

    pub fn add_trusted_key(&self, key: Vec<u8>) {
        let mut guard = self.trusted_keys.write().unwrap();
        guard.push(key);
    }

    pub fn listen(&self) -> Result<Listener, BoxError> {
        let verifier = Arc::new(PubkeyVerifier::new(self.trusted_keys.clone(), true));
        let config = build_server_config(
            self.identity.certified_key.clone(),
            verifier,
            vec![ALPN_H2.to_vec()],
        )?;
        Ok(Listener {
            acceptor: TlsAcceptor::from(Arc::new(config)),
            did: self.did.clone(),
            did_json: self.did_json.clone(),
        })
    }

    pub async fn dial(&self, peer_did: &str) -> Result<Dialer, BoxError> {
        self.dial_with_config(peer_did, BootstrapConfig::default())
            .await
    }

    pub async fn dial_with_config(
        &self,
        peer_did: &str,
        config: BootstrapConfig,
    ) -> Result<Dialer, BoxError> {
        let peer = peer_from_did(peer_did)?;
        self.dial_with_peer_config(peer, config).await
    }

    pub async fn dial_with_addr(
        &self,
        peer_did: &str,
        connect_addr: SocketAddr,
    ) -> Result<Dialer, BoxError> {
        self.dial_with_addr_config(peer_did, connect_addr, BootstrapConfig::default())
            .await
    }

    pub async fn dial_with_addr_config(
        &self,
        peer_did: &str,
        connect_addr: SocketAddr,
        config: BootstrapConfig,
    ) -> Result<Dialer, BoxError> {
        let peer = peer_from_did(peer_did)?;
        self.dial_with_peer_addr_config(peer, connect_addr, config)
            .await
    }

    pub async fn dial_with_peer(&self, peer: Peer) -> Result<Dialer, BoxError> {
        self.dial_with_peer_config(peer, BootstrapConfig::default())
            .await
    }

    pub async fn dial_with_peer_config(
        &self,
        peer: Peer,
        config: BootstrapConfig,
    ) -> Result<Dialer, BoxError> {
        self.dial_with_peer_addr_config_inner(peer, None, config).await
    }

    pub async fn dial_with_peer_addr(
        &self,
        peer: Peer,
        connect_addr: SocketAddr,
    ) -> Result<Dialer, BoxError> {
        self.dial_with_peer_addr_config(peer, Some(connect_addr), BootstrapConfig::default())
            .await
    }

    pub async fn dial_with_peer_addr_config(
        &self,
        peer: Peer,
        connect_addr: SocketAddr,
        config: BootstrapConfig,
    ) -> Result<Dialer, BoxError> {
        self.dial_with_peer_addr_config_inner(peer, Some(connect_addr), config)
            .await
    }

    async fn dial_with_peer_addr_config_inner(
        &self,
        peer: Peer,
        connect_addr: Option<SocketAddr>,
        config: BootstrapConfig,
    ) -> Result<Dialer, BoxError> {
        let bootstrap_config = build_client_config(
            self.identity.certified_key.clone(),
            Arc::new(NoVerifier),
            vec![ALPN_H2.to_vec()],
        )?;
        let keys = fetch_peer_keys_with_config(
            &peer.did_url,
            Arc::new(bootstrap_config),
            connect_addr,
            peer.server_name.clone(),
            config,
        )
        .await?;
        {
            let mut guard = self.trusted_keys.write().unwrap();
            *guard = keys.clone();
        }
        let verifier = Arc::new(PubkeyVerifier::new(self.trusted_keys.clone(), false));
        let client_config = build_client_config(
            self.identity.certified_key.clone(),
            verifier,
            vec![ALPN_H2.to_vec()],
        )?;
        Ok(Dialer {
            client_config: Arc::new(client_config),
            peer,
            connect_addr,
            peer_keys: keys,
        })
    }

    pub fn dial_with_keys(
        &self,
        peer: Peer,
        peer_keys: Vec<Vec<u8>>,
    ) -> Result<Dialer, BoxError> {
        self.dial_with_keys_addr_inner(peer, None, peer_keys)
    }

    pub fn dial_with_keys_addr(
        &self,
        peer: Peer,
        connect_addr: SocketAddr,
        peer_keys: Vec<Vec<u8>>,
    ) -> Result<Dialer, BoxError> {
        self.dial_with_keys_addr_inner(peer, Some(connect_addr), peer_keys)
    }

    fn dial_with_keys_addr_inner(
        &self,
        peer: Peer,
        connect_addr: Option<SocketAddr>,
        peer_keys: Vec<Vec<u8>>,
    ) -> Result<Dialer, BoxError> {
        {
            let mut guard = self.trusted_keys.write().unwrap();
            *guard = peer_keys.clone();
        }
        let verifier = Arc::new(PubkeyVerifier::new(self.trusted_keys.clone(), false));
        let client_config = build_client_config(
            self.identity.certified_key.clone(),
            verifier,
            vec![ALPN_H2.to_vec()],
        )?;
        Ok(Dialer {
            client_config: Arc::new(client_config),
            peer,
            connect_addr,
            peer_keys,
        })
    }

    pub fn trusted_keys(&self) -> Arc<RwLock<Vec<Vec<u8>>>> {
        self.trusted_keys.clone()
    }
}

#[derive(Debug)]
pub struct PubkeyVerifier {
    allowed_keys: Arc<RwLock<Vec<Vec<u8>>>>,
    allow_if_empty: bool,
}

impl PubkeyVerifier {
    pub fn new(allowed_keys: Arc<RwLock<Vec<Vec<u8>>>>, allow_if_empty: bool) -> Self {
        Self {
            allowed_keys,
            allow_if_empty,
        }
    }

    fn check_key(&self, end_entity: &CertificateDer<'_>) -> Result<(), Error> {
        let key = end_entity.as_ref();
        let allowed = self.allowed_keys.read().unwrap();
        if allowed.is_empty() && self.allow_if_empty {
            eprintln!(
                "rpk verify: allow (empty trust store) spki_len={} spki_suffix={}",
                key.len(),
                short_hex(key)
            );
            return Ok(());
        }
        if allowed.iter().any(|k| k.as_slice() == key) {
            eprintln!(
                "rpk verify: allow spki_len={} spki_suffix={}",
                key.len(),
                short_hex(key)
            );
            Ok(())
        } else {
            eprintln!(
                "rpk verify: deny spki_len={} spki_suffix={} trusted={}",
                key.len(),
                short_hex(key),
                allowed.len()
            );
            Err(Error::General(format!(
                "untrusted public key spki_len={} spki_suffix={} trusted={}",
                key.len(),
                short_hex(key),
                allowed.len()
            )))
        }
    }
}

impl ClientCertVerifier for PubkeyVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        self.check_key(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

impl ServerCertVerifier for PubkeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        self.check_key(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

#[derive(Debug)]
pub struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

pub fn build_did_from_host(host: &str, port: Option<u16>) -> String {
    match port {
        Some(port) => format!("did:web:{}%3A{}", host, port),
        None => format!("did:web:{}", host),
    }
}

pub fn peer_from_did(did: &str) -> Result<Peer, BoxError> {
    let (base_url, did_url) = did_web_to_urls(did)?;
    let server_name = server_name_from_url(&base_url)?;
    Ok(Peer {
        did: did.to_string(),
        base_url,
        did_url,
        server_name,
    })
}

pub fn peer_from_did_url(did_url: &Url) -> Result<Peer, BoxError> {
    let did = did_web_from_url(did_url)?;
    peer_from_did(&did)
}

pub fn did_web_from_url(url: &Url) -> Result<String, BoxError> {
    if url.scheme() != "https" {
        return Err("did:web URL must be https".into());
    }
    let host = url.host_str().ok_or("missing host")?;
    let host_id = match url.port() {
        Some(port) => format!("{}%3A{}", host, port),
        None => host.to_string(),
    };
    let path = url.path();
    if path == "/.well-known/did.json" {
        return Ok(format!("{}{}", DID_WEB_PREFIX, host_id));
    }
    if let Some(prefix) = path.strip_suffix("/did.json") {
        let segments = prefix
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        if segments.is_empty() {
            return Ok(format!("{}{}", DID_WEB_PREFIX, host_id));
        }
        let method_id = segments.join(":");
        return Ok(format!("{}{}:{}", DID_WEB_PREFIX, host_id, method_id));
    }
    Err("did:web URL must end with /.well-known/did.json or /did.json".into())
}

pub fn did_web_to_urls(did: &str) -> Result<(Url, Url), BoxError> {
    if !did.starts_with(DID_WEB_PREFIX) {
        return Err("unsupported DID (expected did:web)".into());
    }
    let method_id = &did[DID_WEB_PREFIX.len()..];
    let segments = method_id
        .split(':')
        .map(|segment| {
            percent_encoding::percent_decode_str(segment)
                .decode_utf8()
                .map(|value| value.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if segments.is_empty() {
        return Err("did:web missing host".into());
    }
    let host = &segments[0];
    let path_segments = &segments[1..];

    let base_path = if path_segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}/", path_segments.join("/"))
    };
    let did_path = if path_segments.is_empty() {
        "/.well-known/did.json".to_string()
    } else {
        format!("/{}/did.json", path_segments.join("/"))
    };

    let base_url = Url::parse(&format!("https://{}{}", host, base_path))?;
    let did_url = Url::parse(&format!("https://{}{}", host, did_path))?;
    Ok((base_url, did_url))
}

pub fn server_name_from_url(url: &Url) -> Result<ServerName<'static>, BoxError> {
    let host = url.host_str().ok_or("missing host")?;
    server_name_from_host(host)
}

pub fn server_name_from_host(host: &str) -> Result<ServerName<'static>, BoxError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        Ok(ServerName::IpAddress(ip.into()))
    } else {
        Ok(ServerName::try_from(host.to_string()).map_err(|_| "invalid server name")?)
    }
}

pub fn build_server_config(
    certified_key: Arc<CertifiedKey>,
    verifier: Arc<dyn ClientCertVerifier>,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<ServerConfig, BoxError> {
    let resolver = Arc::new(AlwaysResolvesServerRawPublicKeys::new(certified_key));
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(resolver);
    config.alpn_protocols = alpn_protocols;
    Ok(config)
}

pub fn build_client_config(
    certified_key: Arc<CertifiedKey>,
    verifier: Arc<dyn ServerCertVerifier>,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<ClientConfig, BoxError> {
    let resolver = Arc::new(AlwaysResolvesClientRawPublicKeys::new(certified_key));
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(resolver);
    config.alpn_protocols = alpn_protocols;
    Ok(config)
}

pub async fn send_request(
    url: &Url,
    client_config: Arc<ClientConfig>,
    method: Method,
    body: Option<Body>,
    connect_addr: Option<SocketAddr>,
    server_name: Option<ServerName<'static>>,
) -> Result<Response<Body>, BoxError> {
    let host = url.host_str().ok_or("missing host")?;
    let port = url.port_or_known_default().ok_or("missing port")?;
    let addr = match connect_addr {
        Some(addr) => addr,
        None => format!("{}:{}", host, port).parse()?,
    };

    let server_name = match server_name {
        Some(server_name) => server_name,
        None => server_name_from_host(host)?,
    };

    let tcp = TcpStream::connect(addr).await?;
    let connector = TlsConnector::from(client_config);
    let tls_stream = connector.connect(server_name, tcp).await?;

    let (mut sender, connection) = hyper::client::conn::Builder::new()
        .http2_only(true)
        .handshake(tls_stream)
        .await?;

    tokio::spawn(async move {
        if let Err(err) = connection.await {
            eprintln!("client connection error: {}", err);
        }
    });

    let request = Request::builder()
        .method(method)
        .uri(url.as_str())
        .body(body.unwrap_or_else(Body::empty))?;

    let response = sender.send_request(request).await?;
    Ok(response)
}

pub async fn fetch_peer_keys(
    url: &Url,
    client_config: Arc<ClientConfig>,
    connect_addr: Option<SocketAddr>,
    server_name: ServerName<'static>,
) -> Result<Vec<Vec<u8>>, BoxError> {
    fetch_peer_keys_with_config(
        url,
        client_config,
        connect_addr,
        server_name,
        BootstrapConfig::default(),
    )
    .await
}

pub async fn fetch_peer_keys_with_config(
    url: &Url,
    client_config: Arc<ClientConfig>,
    connect_addr: Option<SocketAddr>,
    server_name: ServerName<'static>,
    config: BootstrapConfig,
) -> Result<Vec<Vec<u8>>, BoxError> {
    let mut last_err: Option<BoxError> = None;

    for attempt in 1..=config.retries {
        eprintln!(
            "fetching peer did (attempt {}/{}) {}",
            attempt, config.retries, url
        );
        match send_request(
            url,
            client_config.clone(),
            Method::GET,
            None,
            connect_addr,
            Some(server_name.clone()),
        )
        .await
        {
            Ok(response) => {
                if response.status() == StatusCode::OK {
                    let bytes = to_bytes(response.into_body()).await?;
                    let doc: serde_json::Value = serde_json::from_slice(bytes.as_ref())?;
                    return extract_keys_from_did(&doc);
                }
                last_err = Some(format!("did.json fetch failed: {}", response.status()).into());
            }
            Err(err) => last_err = Some(err),
        }

        if attempt < config.retries {
            eprintln!(
                "peer did fetch failed (attempt {}/{}); retrying in {}s",
                attempt,
                config.retries,
                config.delay.as_secs()
            );
            sleep(config.delay).await;
        }
    }

    Err(last_err.unwrap_or_else(|| "did.json fetch failed".into()))
}

fn extract_keys_from_did(doc: &serde_json::Value) -> Result<Vec<Vec<u8>>, BoxError> {
    let methods = doc
        .get("verificationMethod")
        .and_then(|v| v.as_array())
        .ok_or("did.json missing verificationMethod")?;

    let mut keys = Vec::new();
    for method in methods {
        let multibase = match method.get("publicKeyMultibase").and_then(|v| v.as_str()) {
            Some(value) => value,
            None => continue,
        };
        let raw = decode_multibase_ed25519(multibase)?;
        let spki = spki_from_raw_pubkey(&raw)?;
        keys.push(spki);
    }

    if keys.is_empty() {
        return Err("no Ed25519 publicKeyMultibase keys found in did.json".into());
    }
    Ok(keys)
}

fn generate_identity() -> Result<Identity, BoxError> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_bytes().to_vec();

    let spki = verifying_key.to_public_key_der()?.as_bytes().to_vec();
    let cert_chain = vec![CertificateDer::from(spki)];

    let pkcs8 = signing_key.to_pkcs8_der()?;
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        pkcs8.as_bytes().to_vec(),
    ));
    let signing_key = any_supported_type(&private_key)?;

    let certified_key = Arc::new(CertifiedKey::new(cert_chain, signing_key));

    Ok(Identity {
        certified_key,
        public_key,
    })
}

fn build_did_json(did: &str, public_key: &[u8]) -> Result<String, BoxError> {
    let public_key_multibase = encode_multibase_ed25519(public_key)?;
    let doc = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": did,
        "verificationMethod": [{
            "id": format!("{}#key-1", did),
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyMultibase": public_key_multibase
        }],
        "authentication": [format!("{}#key-1", did)],
        "assertionMethod": [format!("{}#key-1", did)],
    });
    Ok(serde_json::to_string_pretty(&doc)?)
}

fn spki_from_raw_pubkey(raw: &[u8]) -> Result<Vec<u8>, BoxError> {
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| "invalid Ed25519 public key length")?;
    let verifying_key = VerifyingKey::from_bytes(&raw)?;
    Ok(verifying_key.to_public_key_der()?.as_bytes().to_vec())
}

fn encode_multibase_ed25519(public_key: &[u8]) -> Result<String, BoxError> {
    if public_key.len() != 32 {
        return Err("invalid Ed25519 public key length".into());
    }
    let mut bytes = Vec::with_capacity(ED25519_PUBKEY_MULTICODEC.len() + public_key.len());
    bytes.extend_from_slice(&ED25519_PUBKEY_MULTICODEC);
    bytes.extend_from_slice(public_key);
    Ok(format!("z{}", bs58::encode(bytes).into_string()))
}

fn decode_multibase_ed25519(value: &str) -> Result<Vec<u8>, BoxError> {
    let encoded = value.strip_prefix('z').ok_or("unsupported multibase prefix")?;
    let bytes = bs58::decode(encoded).into_vec()?;
    if bytes.len() != ED25519_PUBKEY_MULTICODEC.len() + 32 {
        return Err("invalid multibase Ed25519 key length".into());
    }
    if bytes[..ED25519_PUBKEY_MULTICODEC.len()] != ED25519_PUBKEY_MULTICODEC {
        return Err("unexpected multicodec prefix".into());
    }
    Ok(bytes[ED25519_PUBKEY_MULTICODEC.len()..].to_vec())
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
