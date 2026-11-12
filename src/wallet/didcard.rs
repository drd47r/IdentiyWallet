use ssi::dids::AnyDidMethod;
use ssi::prelude::*;

/// DID identity card shown to the agent.
/// For `did:jwk` / `did:key`, `did` is derived from the key. `label` and later
/// document overlay fields are local only.
#[derive(Debug, Clone)]
pub struct DidCard {
    pub did: ssi::dids::DIDBuf,
    pub document: ssi::dids::Document,
    pub label: Option<String>,
}

impl DidCard {
    pub async fn new(did: ssi::dids::DIDBuf) -> Self {
        let resolver = AnyDidMethod::default();
        let did_doc = resolver.resolve(&did).await.unwrap().document;
        Self {
            did,
            document: did_doc.into_document(),
            label: None,
        }
    }
}

/// Local-only patches to a [DidCard]. Does not rotate the DID.
#[derive(Debug, Clone, Default)]
pub struct DidCardUpdate {
    pub label: Option<String>,
    pub also_known_as: Option<Vec<String>>,
    pub services: Option<Vec<ssi::dids::document::Service>>,
}

/// Requests a system / agent can send the wallet.
#[derive(Debug, Clone)]
pub enum DidRequest {
    ResolveDid,
    Authenticate {
        challenge: String,
        domain: Option<String>,
    },
    SignClaims {
        claims: serde_json::Value,
    },
}

#[derive(Debug, Clone)]
pub enum DidResponse {
    Document(ssi::dids::Document),
    Jws(ssi::claims::JwsBuf),
}
