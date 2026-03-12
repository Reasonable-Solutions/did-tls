# mtls-did-web

Proof-of-concept: DID Web + RFC7250 raw public keys (RPK) for mutual TLS over HTTP/2.

This demo uses:
- `did:web` to publish an Ed25519 public key.
- RFC7250 raw public keys (SPKI DER) for TLS 1.3 mutual authentication.
- TOFU (trust-on-first-use) to bootstrap the peer key from its DID document.

## How it works (high level)

1) Each node generates a fresh Ed25519 keypair at startup.
2) It serves a DID document at `/.well-known/did.json` with:
   - `type: Ed25519VerificationKey2020`
   - `publicKeyMultibase: z...` (multibase-encoded multicodec Ed25519 key)
3) The first time a node starts, it fetches the peer's DID doc and extracts the
   `publicKeyMultibase` value.
4) That raw Ed25519 key is wrapped into SPKI DER (as required by RFC7250) and
   stored as a trusted key.
5) All subsequent TLS handshakes require the peer's RPK to match the stored SPKI.

There are no X.509 certificates. The TLS handshake uses raw public keys only.

## Library API

The core logic lives in `src/lib.rs` and exposes two primitives:
- `Node::listen()` -> `Listener` (server-side TLS acceptor + DID doc)
- `Node::dial(peer_did, connect_addr)` -> `Dialer` (client config + peer metadata)

## Run

Open two terminals:

Terminal A:

```
cargo run -- --host 127.0.0.1 --port 8443 \
  --did did:web:localhost%3A8443 \
  --peer-did did:web:localhost%3A9443 \
  --peer-addr 127.0.0.1:9443
```

Terminal B:

```
cargo run -- --host 127.0.0.1 --port 9443 \
  --did did:web:localhost%3A9443 \
  --peer-did did:web:localhost%3A8443 \
  --peer-addr 127.0.0.1:8443
```

You should see logs for:
- `local publicKeyMultibase` (the node's key)
- DID fetch retries during bootstrap
- RPK verification allow/deny decisions
- `ping -> pong` messages

## Local DNS identity (no /etc/hosts)

To simulate in-cluster DNS names on localhost, split the identity host from the
connect address:

Terminal A:

```
cargo run -- --host 127.0.0.1 --port 8443 \
  --did-host service-a.ns.svc.cluster.local \
  --peer-host service-b.ns.svc.cluster.local \
  --peer-addr 127.0.0.1:9443
```

Terminal B:

```
cargo run -- --host 127.0.0.1 --port 9443 \
  --did-host service-b.ns.svc.cluster.local \
  --peer-host service-a.ns.svc.cluster.local \
  --peer-addr 127.0.0.1:8443
```

This keeps the DID and TLS SNI tied to the DNS identity, while still connecting
to localhost.

## Notes

- `/.well-known/did.json` is served over RPK mTLS, so normal `curl` will not work.
  The demo bootstraps using a verifier that accepts any RPK on the first fetch.
- The "short" key logs are just a suffix of the SPKI DER; they are not a full
  fingerprint.

## Why SPKI?

RFC7250 defines raw public keys as SubjectPublicKeyInfo (SPKI) DER, not as raw
32-byte Ed25519 keys. The code converts to/from SPKI for TLS, while the DID
publishes the raw key via `publicKeyMultibase`.
