use ssi::dids::AnyDidMethod;
use ssi::prelude::*;

/// DID identity card shown to the agent.
///
/// For `did:key` / `did:jwk`, `did` is derived from the key and the document is
/// resolved from the method. For `did:web`, the DID is supplied and the document
/// is a local overlay that attaches the wallet public key. `label` and other
/// patches remain local only.
#[derive(Debug, Clone)]
pub struct DidCard {
    pub did: ssi::dids::DIDBuf,
    pub document: ssi::dids::Document,
    pub label: Option<String>,
}

impl DidCard {
    pub async fn new(did: ssi::dids::DIDBuf, jwk: Option<ssi_jwk::JWK>) -> Self {
        let didm = did.method_name();
        println!("DIDCard new did {:#?}, {:?}", &did, &didm);
        match didm {
            "web" => {
                let mut doc = ssi_dids::Document::new(did.clone());
                let key_id = ssi_dids::DIDURLBuf::new(format!("{did}#key-1").into_bytes()).unwrap();
                let vm = ssi_dids_core::document::DIDVerificationMethod {
                    id: key_id,
                    type_: "JsonWebKey2020".to_string(),
                    controller: did.clone(),
                    properties: serde_json::from_value(serde_json::json!({
                        "publicKeyJwk": jwk.map(|jwk| jwk.to_public())
                    }))
                    .unwrap(),
                };
                doc.verification_method.push(vm);

                return Self {
                    did,
                    document: doc,
                    label: None,
                };
            }
            _ => {
                let resolver = AnyDidMethod::default();
                let did_doc = resolver.resolve(&did).await.unwrap().document;
                return Self {
                    did,
                    document: did_doc.into_document(),
                    label: None,
                };
            }
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
