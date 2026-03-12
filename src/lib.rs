use bs58;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
#[cfg(feature = "http")]
use hyper::body::to_bytes;
#[cfg(feature = "http")]
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
    ClientConfig, DistinguishedName, DigitallySignedStruct, Error as RustlsError, ServerConfig,
    SignatureScheme,
};
use rustls::crypto::aws_lc_rs::sign::any_supported_type;
use rustls::sign::CertifiedKey;
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;
#[cfg(feature = "http")]
use tokio::net::TcpStream;
#[cfg(feature = "http")]
use tokio::time::sleep;
use tokio_rustls::TlsAcceptor;
#[cfg(feature = "http")]
use tokio_rustls::TlsConnector;
use url::Url;

#[derive(Debug)]
pub enum Error {
    InvalidDid(String),
    DidDocument(String),
    Resolution(String),
    Key(String),
    Transport(String),
    Io(std::io::Error),
    Url(url::ParseError),
    Json(serde_json::Error),
    Base58(bs58::decode::Error),
    Utf8(std::str::Utf8Error),
    AddrParse(std::net::AddrParseError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidDid(msg) => write!(f, "invalid did: {}", msg),
            Error::DidDocument(msg) => write!(f, "did document error: {}", msg),
            Error::Resolution(msg) => write!(f, "did resolution error: {}", msg),
            Error::Key(msg) => write!(f, "key error: {}", msg),
            Error::Transport(msg) => write!(f, "transport error: {}", msg),
            Error::Io(err) => write!(f, "io error: {}", err),
            Error::Url(err) => write!(f, "url error: {}", err),
            Error::Json(err) => write!(f, "json error: {}", err),
            Error::Base58(err) => write!(f, "base58 error: {}", err),
            Error::Utf8(err) => write!(f, "utf8 error: {}", err),
            Error::AddrParse(err) => write!(f, "addr parse error: {}", err),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<url::ParseError> for Error {
    fn from(err: url::ParseError) -> Self {
        Error::Url(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Json(err)
    }
}

impl From<bs58::decode::Error> for Error {
    fn from(err: bs58::decode::Error) -> Self {
        Error::Base58(err)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Self {
        Error::Utf8(err)
    }
}

impl From<std::net::AddrParseError> for Error {
    fn from(err: std::net::AddrParseError) -> Self {
        Error::AddrParse(err)
    }
}

#[cfg(feature = "http")]
impl From<hyper::Error> for Error {
    fn from(err: hyper::Error) -> Self {
        Error::Transport(err.to_string())
    }
}

#[cfg(feature = "http")]
impl From<hyper::http::Error> for Error {
    fn from(err: hyper::http::Error) -> Self {
        Error::Transport(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
type RustlsResult<T> = std::result::Result<T, RustlsError>;

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

pub trait DidResolver: Send + Sync {
    fn resolve(&self, did: &str) -> Result<Vec<Vec<u8>>>;
}

pub struct StaticResolver {
    keys: HashMap<String, Vec<Vec<u8>>>,
}

impl StaticResolver {
    pub fn new(keys: HashMap<String, Vec<Vec<u8>>>) -> Self {
        Self { keys }
    }
}

impl DidResolver for StaticResolver {
    fn resolve(&self, did: &str) -> Result<Vec<Vec<u8>>> {
        self.keys
            .get(did)
            .cloned()
            .ok_or_else(|| Error::Resolution(format!("no trusted keys for {}", did)))
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
    trusted_keys: Arc<RwLock<HashMap<String, Vec<Vec<u8>>>>>,
}

impl Node {
    pub fn new(did: impl Into<String>) -> Result<Self> {
        Self::new_with_trusted_keys(did, HashMap::new())
    }

    pub fn new_with_trusted_keys(
        did: impl Into<String>,
        trusted_keys: HashMap<String, Vec<Vec<u8>>>,
    ) -> Result<Self> {
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

    pub fn local_public_key_multibase(&self) -> Result<String> {
        encode_multibase_ed25519(&self.identity.public_key)
    }

    pub fn set_trusted_keys(&self, peer_did: impl Into<String>, keys: Vec<Vec<u8>>) {
        let mut guard = self.trusted_keys.write().unwrap();
        guard.insert(peer_did.into(), keys);
    }

    pub fn add_trusted_key(&self, peer_did: impl Into<String>, key: Vec<u8>) {
        let mut guard = self.trusted_keys.write().unwrap();
        guard.entry(peer_did.into()).or_default().push(key);
    }

    pub fn listen(&self) -> Result<Listener> {
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

    #[cfg(feature = "http")]
    pub fn dial_with_resolver(
        &self,
        peer_did: &str,
        resolver: &dyn DidResolver,
    ) -> Result<Dialer> {
        self.dial_with_resolver_addr(peer_did, None, resolver)
    }

    pub fn dial_with_resolver_addr(
        &self,
        peer_did: &str,
        connect_addr: Option<SocketAddr>,
        resolver: &dyn DidResolver,
    ) -> Result<Dialer> {
        let peer = peer_from_did(peer_did)?;
        let keys = resolver.resolve(peer_did)?;
        self.dial_with_peer_keys_addr(peer, connect_addr, keys)
    }

    #[cfg(feature = "http")]
    pub async fn dial(&self, peer_did: &str) -> Result<Dialer> {
        self.dial_with_config(peer_did, BootstrapConfig::default())
            .await
    }

    #[cfg(feature = "http")]
    pub async fn dial_with_config(
        &self,
        peer_did: &str,
        config: BootstrapConfig,
    ) -> Result<Dialer> {
        let peer = peer_from_did(peer_did)?;
        self.dial_with_peer_config(peer, config).await
    }

    #[cfg(feature = "http")]
    pub async fn dial_with_addr(
        &self,
        peer_did: &str,
        connect_addr: SocketAddr,
    ) -> Result<Dialer> {
        self.dial_with_addr_config(peer_did, connect_addr, BootstrapConfig::default())
            .await
    }

    #[cfg(feature = "http")]
    pub async fn dial_with_addr_config(
        &self,
        peer_did: &str,
        connect_addr: SocketAddr,
        config: BootstrapConfig,
    ) -> Result<Dialer> {
        let peer = peer_from_did(peer_did)?;
        self.dial_with_peer_addr_config(peer, connect_addr, config)
            .await
    }

    #[cfg(feature = "http")]
    pub async fn dial_with_peer(&self, peer: Peer) -> Result<Dialer> {
        self.dial_with_peer_config(peer, BootstrapConfig::default())
            .await
    }

    #[cfg(feature = "http")]
    pub async fn dial_with_peer_config(
        &self,
        peer: Peer,
        config: BootstrapConfig,
    ) -> Result<Dialer> {
        self.dial_with_peer_addr_config_inner(peer, None, config).await
    }

    #[cfg(feature = "http")]
    pub async fn dial_with_peer_addr(
        &self,
        peer: Peer,
        connect_addr: SocketAddr,
    ) -> Result<Dialer> {
        self.dial_with_peer_addr_config(peer, connect_addr, BootstrapConfig::default())
            .await
    }

    #[cfg(feature = "http")]
    pub async fn dial_with_peer_addr_config(
        &self,
        peer: Peer,
        connect_addr: SocketAddr,
        config: BootstrapConfig,
    ) -> Result<Dialer> {
        self.dial_with_peer_addr_config_inner(peer, Some(connect_addr), config)
            .await
    }

    #[cfg(feature = "http")]
    async fn dial_with_peer_addr_config_inner(
        &self,
        peer: Peer,
        connect_addr: Option<SocketAddr>,
        config: BootstrapConfig,
    ) -> Result<Dialer> {
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
            &peer.did,
        )
        .await?;
        self.dial_with_peer_keys_addr(peer, connect_addr, keys)
    }

    pub fn dial_with_keys(
        &self,
        peer: Peer,
        peer_keys: Vec<Vec<u8>>,
    ) -> Result<Dialer> {
        self.dial_with_peer_keys_addr(peer, None, peer_keys)
    }

    pub fn dial_with_keys_addr(
        &self,
        peer: Peer,
        connect_addr: SocketAddr,
        peer_keys: Vec<Vec<u8>>,
    ) -> Result<Dialer> {
        self.dial_with_peer_keys_addr(peer, Some(connect_addr), peer_keys)
    }

    fn dial_with_peer_keys_addr(
        &self,
        peer: Peer,
        connect_addr: Option<SocketAddr>,
        peer_keys: Vec<Vec<u8>>,
    ) -> Result<Dialer> {
        {
            let mut guard = self.trusted_keys.write().unwrap();
            guard.insert(peer.did.clone(), peer_keys.clone());
        }
        let verifier = Arc::new(PeerVerifier::new(self.trusted_keys.clone(), peer.did.clone()));
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

    pub fn trusted_keys(&self) -> Arc<RwLock<HashMap<String, Vec<Vec<u8>>>>> {
        self.trusted_keys.clone()
    }
}

#[derive(Debug)]
pub struct PubkeyVerifier {
    allowed_keys: Arc<RwLock<HashMap<String, Vec<Vec<u8>>>>>,
    allow_if_empty: bool,
}

impl PubkeyVerifier {
    pub fn new(allowed_keys: Arc<RwLock<HashMap<String, Vec<Vec<u8>>>>>, allow_if_empty: bool) -> Self {
        Self {
            allowed_keys,
            allow_if_empty,
        }
    }

    fn check_key(&self, end_entity: &CertificateDer<'_>) -> RustlsResult<()> {
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
        if allowed
            .values()
            .any(|keys| keys.iter().any(|k| k.as_slice() == key))
        {
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
                allowed.values().map(|keys| keys.len()).sum::<usize>()
            );
            Err(RustlsError::General(format!(
                "untrusted public key spki_len={} spki_suffix={} trusted={}",
                key.len(),
                short_hex(key),
                allowed.values().map(|keys| keys.len()).sum::<usize>()
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
    ) -> RustlsResult<ClientCertVerified> {
        self.check_key(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> RustlsResult<HandshakeSignatureValid> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> RustlsResult<HandshakeSignatureValid> {
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
    ) -> RustlsResult<ServerCertVerified> {
        self.check_key(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> RustlsResult<HandshakeSignatureValid> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> RustlsResult<HandshakeSignatureValid> {
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
struct PeerVerifier {
    allowed_keys: Arc<RwLock<HashMap<String, Vec<Vec<u8>>>>>,
    peer_did: String,
}

impl PeerVerifier {
    fn new(
        allowed_keys: Arc<RwLock<HashMap<String, Vec<Vec<u8>>>>>,
        peer_did: String,
    ) -> Self {
        Self {
            allowed_keys,
            peer_did,
        }
    }

    fn check_key(&self, end_entity: &CertificateDer<'_>) -> RustlsResult<()> {
        let key = end_entity.as_ref();
        let allowed = self.allowed_keys.read().unwrap();
        let keys = allowed
            .get(&self.peer_did)
            .ok_or_else(|| RustlsError::General(format!("no trusted keys for {}", self.peer_did)))?;
        if keys.iter().any(|k| k.as_slice() == key) {
            eprintln!(
                "rpk verify: allow peer={} spki_len={} spki_suffix={}",
                self.peer_did,
                key.len(),
                short_hex(key)
            );
            Ok(())
        } else {
            eprintln!(
                "rpk verify: deny peer={} spki_len={} spki_suffix={} trusted={}",
                self.peer_did,
                key.len(),
                short_hex(key),
                keys.len()
            );
            Err(RustlsError::General(format!(
                "untrusted public key for {} spki_len={} spki_suffix={} trusted={}",
                self.peer_did,
                key.len(),
                short_hex(key),
                keys.len()
            )))
        }
    }
}

impl ServerCertVerifier for PeerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> RustlsResult<ServerCertVerified> {
        self.check_key(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> RustlsResult<HandshakeSignatureValid> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> RustlsResult<HandshakeSignatureValid> {
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
    ) -> RustlsResult<ServerCertVerified> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> RustlsResult<HandshakeSignatureValid> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> RustlsResult<HandshakeSignatureValid> {
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

pub fn peer_from_did(did: &str) -> Result<Peer> {
    let (base_url, did_url) = did_web_to_urls(did)?;
    let server_name = server_name_from_url(&base_url)?;
    Ok(Peer {
        did: did.to_string(),
        base_url,
        did_url,
        server_name,
    })
}

pub fn peer_from_did_url(did_url: &Url) -> Result<Peer> {
    let did = did_web_from_url(did_url)?;
    peer_from_did(&did)
}

pub fn did_web_from_url(url: &Url) -> Result<String> {
    if url.scheme() != "https" {
        return Err(Error::InvalidDid("did:web URL must be https".to_string()));
    }
    let host = url
        .host_str()
        .ok_or_else(|| Error::InvalidDid("missing host".to_string()))?;
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
    Err(Error::InvalidDid(
        "did:web URL must end with /.well-known/did.json or /did.json".to_string(),
    ))
}

pub fn did_web_to_urls(did: &str) -> Result<(Url, Url)> {
    if !did.starts_with(DID_WEB_PREFIX) {
        return Err(Error::InvalidDid(
            "unsupported DID (expected did:web)".to_string(),
        ));
    }
    let method_id = &did[DID_WEB_PREFIX.len()..];
    let segments = method_id
        .split(':')
        .map(|segment| {
            percent_encoding::percent_decode_str(segment)
                .decode_utf8()
                .map(|value| value.to_string())
                .map_err(Error::from)
        })
        .collect::<Result<Vec<_>>>()?;
    if segments.is_empty() {
        return Err(Error::InvalidDid("did:web missing host".to_string()));
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

pub fn server_name_from_url(url: &Url) -> Result<ServerName<'static>> {
    let host = url
        .host_str()
        .ok_or_else(|| Error::Resolution("missing host".to_string()))?;
    server_name_from_host(host)
}

pub fn server_name_from_host(host: &str) -> Result<ServerName<'static>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        Ok(ServerName::IpAddress(ip.into()))
    } else {
        Ok(ServerName::try_from(host.to_string())
            .map_err(|_| Error::Resolution("invalid server name".to_string()))?)
    }
}

pub fn build_server_config(
    certified_key: Arc<CertifiedKey>,
    verifier: Arc<dyn ClientCertVerifier>,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<ServerConfig> {
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
) -> Result<ClientConfig> {
    let resolver = Arc::new(AlwaysResolvesClientRawPublicKeys::new(certified_key));
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(resolver);
    config.alpn_protocols = alpn_protocols;
    Ok(config)
}

#[cfg(feature = "http")]
pub async fn send_request(
    url: &Url,
    client_config: Arc<ClientConfig>,
    method: Method,
    body: Option<Body>,
    connect_addr: Option<SocketAddr>,
    server_name: Option<ServerName<'static>>,
) -> Result<Response<Body>> {
    let host = url
        .host_str()
        .ok_or_else(|| Error::Resolution("missing host".to_string()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| Error::Resolution("missing port".to_string()))?;
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

#[cfg(feature = "http")]
pub async fn fetch_peer_keys(
    url: &Url,
    client_config: Arc<ClientConfig>,
    connect_addr: Option<SocketAddr>,
    server_name: ServerName<'static>,
    expected_did: &str,
) -> Result<Vec<Vec<u8>>> {
    fetch_peer_keys_with_config(
        url,
        client_config,
        connect_addr,
        server_name,
        BootstrapConfig::default(),
        expected_did,
    )
    .await
}

#[cfg(feature = "http")]
pub async fn fetch_peer_keys_with_config(
    url: &Url,
    client_config: Arc<ClientConfig>,
    connect_addr: Option<SocketAddr>,
    server_name: ServerName<'static>,
    config: BootstrapConfig,
    expected_did: &str,
) -> Result<Vec<Vec<u8>>> {
    let mut last_err: Option<Error> = None;

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
                    return extract_keys_from_did(&doc, expected_did);
                }
                last_err = Some(Error::Resolution(format!(
                    "did.json fetch failed: {}",
                    response.status()
                )));
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

    Err(last_err.unwrap_or_else(|| {
        Error::Resolution("did.json fetch failed".to_string())
    }))
}

fn extract_keys_from_did(doc: &serde_json::Value, expected_did: &str) -> Result<Vec<Vec<u8>>> {
    let doc_id = doc
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::DidDocument("did.json missing id".to_string()))?;
    if doc_id != expected_did {
        return Err(Error::DidDocument(format!(
            "did.json id mismatch (expected {} got {})",
            expected_did, doc_id
        )));
    }

    let methods = doc
        .get("verificationMethod")
        .and_then(|v| v.as_array())
        .ok_or_else(|| Error::DidDocument("did.json missing verificationMethod".to_string()))?;

    let mut keys = Vec::new();
    for method in methods {
        if let Some(controller) = method.get("controller").and_then(|v| v.as_str()) {
            if controller != expected_did {
                continue;
            }
        }
        let multibase = match method.get("publicKeyMultibase").and_then(|v| v.as_str()) {
            Some(value) => value,
            None => continue,
        };
        let raw = decode_multibase_ed25519(multibase)?;
        let spki = spki_from_raw_pubkey(&raw)?;
        keys.push(spki);
    }

    if keys.is_empty() {
        return Err(Error::DidDocument(
            "no Ed25519 publicKeyMultibase keys found in did.json".to_string(),
        ));
    }
    Ok(keys)
}

fn generate_identity() -> Result<Identity> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_bytes().to_vec();

    let spki = verifying_key
        .to_public_key_der()
        .map_err(|e| Error::Key(e.to_string()))?
        .as_bytes()
        .to_vec();
    let cert_chain = vec![CertificateDer::from(spki)];

    let pkcs8 = signing_key
        .to_pkcs8_der()
        .map_err(|e| Error::Key(e.to_string()))?;
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        pkcs8.as_bytes().to_vec(),
    ));
    let signing_key =
        any_supported_type(&private_key).map_err(|e| Error::Key(e.to_string()))?;

    let certified_key = Arc::new(CertifiedKey::new(cert_chain, signing_key));

    Ok(Identity {
        certified_key,
        public_key,
    })
}

fn build_did_json(did: &str, public_key: &[u8]) -> Result<String> {
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

fn spki_from_raw_pubkey(raw: &[u8]) -> Result<Vec<u8>> {
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| Error::Key("invalid Ed25519 public key length".to_string()))?;
    let verifying_key =
        VerifyingKey::from_bytes(&raw).map_err(|e| Error::Key(e.to_string()))?;
    Ok(verifying_key
        .to_public_key_der()
        .map_err(|e| Error::Key(e.to_string()))?
        .as_bytes()
        .to_vec())
}

fn encode_multibase_ed25519(public_key: &[u8]) -> Result<String> {
    if public_key.len() != 32 {
        return Err(Error::Key("invalid Ed25519 public key length".to_string()));
    }
    let mut bytes = Vec::with_capacity(ED25519_PUBKEY_MULTICODEC.len() + public_key.len());
    bytes.extend_from_slice(&ED25519_PUBKEY_MULTICODEC);
    bytes.extend_from_slice(public_key);
    Ok(format!("z{}", bs58::encode(bytes).into_string()))
}

fn decode_multibase_ed25519(value: &str) -> Result<Vec<u8>> {
    let encoded = value
        .strip_prefix('z')
        .ok_or_else(|| Error::Key("unsupported multibase prefix".to_string()))?;
    let bytes = bs58::decode(encoded).into_vec()?;
    if bytes.len() != ED25519_PUBKEY_MULTICODEC.len() + 32 {
        return Err(Error::Key(
            "invalid multibase Ed25519 key length".to_string(),
        ));
    }
    if bytes[..ED25519_PUBKEY_MULTICODEC.len()] != ED25519_PUBKEY_MULTICODEC {
        return Err(Error::Key("unexpected multicodec prefix".to_string()));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};
    use rustls::pki_types::CertificateDer;

    #[test]
    fn did_web_to_urls_with_port() {
        let (base, did) = did_web_to_urls("did:web:localhost%3A8443").unwrap();
        assert_eq!(base.as_str(), "https://localhost:8443/");
        assert_eq!(did.as_str(), "https://localhost:8443/.well-known/did.json");
    }

    #[test]
    fn did_web_to_urls_with_path() {
        let (base, did) = did_web_to_urls("did:web:example.com:user:svc").unwrap();
        assert_eq!(base.as_str(), "https://example.com/user/svc/");
        assert_eq!(did.as_str(), "https://example.com/user/svc/did.json");
    }

    #[test]
    fn did_web_from_url_round_trip() {
        let did = did_web_from_url(&Url::parse("https://example.com/.well-known/did.json").unwrap())
            .unwrap();
        assert_eq!(did, "did:web:example.com");

        let did = did_web_from_url(&Url::parse("https://example.com/user/svc/did.json").unwrap())
            .unwrap();
        assert_eq!(did, "did:web:example.com:user:svc");
    }

    #[test]
    fn multibase_round_trip() {
        let key = vec![7u8; 32];
        let encoded = encode_multibase_ed25519(&key).unwrap();
        let decoded = decode_multibase_ed25519(&encoded).unwrap();
        assert_eq!(decoded, key);
    }

    #[test]
    fn extract_keys_requires_matching_id() {
        let identity = generate_identity().unwrap();
        let did = "did:web:example.com";
        let doc = build_did_json(did, &identity.public_key).unwrap();
        let value: serde_json::Value = serde_json::from_str(&doc).unwrap();
        let err = extract_keys_from_did(&value, "did:web:other.example.com").unwrap_err();
        assert!(err.to_string().contains("id mismatch"));
    }

    #[test]
    fn extract_keys_returns_spki() {
        let identity = generate_identity().unwrap();
        let did = "did:web:example.com";
        let doc = build_did_json(did, &identity.public_key).unwrap();
        let value: serde_json::Value = serde_json::from_str(&doc).unwrap();
        let keys = extract_keys_from_did(&value, did).unwrap();
        assert_eq!(keys.len(), 1);
        let expected_spki = spki_from_raw_pubkey(&identity.public_key).unwrap();
        assert_eq!(keys[0], expected_spki);
    }

    #[test]
    fn peer_verifier_rejects_other_peer_keys() {
        let identity_a = generate_identity().unwrap();
        let identity_b = generate_identity().unwrap();

        let did_a = "did:web:a.example";
        let did_b = "did:web:b.example";

        let key_a = spki_from_raw_pubkey(&identity_a.public_key).unwrap();
        let key_b = spki_from_raw_pubkey(&identity_b.public_key).unwrap();

        let mut map = HashMap::new();
        map.insert(did_a.to_string(), vec![key_a.clone()]);
        map.insert(did_b.to_string(), vec![key_b.clone()]);

        let verifier = PeerVerifier::new(Arc::new(RwLock::new(map)), did_a.to_string());
        let cert = CertificateDer::from(key_b);
        assert!(verifier.check_key(&cert).is_err());
    }
}
