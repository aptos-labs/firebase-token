use crate::verifier::{JwtVerifier, VerificationError};
use jsonwebtoken::TokenData;
use serde::de::DeserializeOwned;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use crate::id_token_jwk_fetcher::IdTokenJwkFetcher;
use crate::session_token_jwk_fetcher::SessionTokenJwkFetcher;
use crate::jwk_fetcher::JwkFetcher;

const ID_TOKEN_ISSUER_URL: &str = "https://securetoken.google.com/";
const SESSION_TOKEN_ISSUER_URL: &str = "https://session.firebase.google.com/";

#[derive(Clone)]
pub struct FirebaseTokenAuth {
    verifiers: Vec<Arc<Mutex<JwtVerifier>>>,
}

impl FirebaseTokenAuth {
    pub async fn new(project_id: String) -> FirebaseTokenAuth {
        Self::new_with_options(project_id, true, true).await
    }

    async fn new_with_options(project_id: String, with_id_tokens: bool, with_session_tokens: bool) -> FirebaseTokenAuth {
        let mut verifiers = vec![];
        let audience = project_id.clone();

        if with_id_tokens {
            let issuer = format!("{}{}", ID_TOKEN_ISSUER_URL, project_id.clone());
            let verifier = Arc::new(Mutex::new(JwtVerifier::new(audience.clone(), issuer)));

            let jwk_fetcher = Box::new(IdTokenJwkFetcher::new());
            start_periodic_jwks_update(jwk_fetcher, verifier.clone(), "ID token".to_owned());
            verifiers.push(verifier);
        }

        if with_session_tokens {
            let issuer = format!("{}{}", SESSION_TOKEN_ISSUER_URL, project_id.clone());
            let verifier = Arc::new(Mutex::new(JwtVerifier::new(audience.clone(), issuer)));

            let jwk_fetcher = Box::new(SessionTokenJwkFetcher::new());
            start_periodic_jwks_update(jwk_fetcher, verifier.clone(), "Session token".to_owned());
            verifiers.push(verifier);
        }

        FirebaseTokenAuth {
            verifiers,
        }
    }

    pub async fn verify<'a, C: DeserializeOwned + 'a>(&self, token: &str) -> Result<TokenData<C>, VerificationError> {
        for verifier in &self.verifiers {
            let verifier = verifier.lock().await;
            match verifier.verify(token) {
                Err(VerificationError::JwkUnavailable) => {},
                result => return result,
            }
        }
        Err(VerificationError::JwkUnavailable)
    }
}

fn start_periodic_jwks_update(fetcher: Box<dyn JwkFetcher>, verifier: Arc<Mutex<JwtVerifier>>, label: String) {
    tokio::spawn(async move {
        loop {
            let ttl = match fetcher.fetch_keys().await {
                Ok(result) => {
                    let mut verifier = verifier.lock().await;
                    verifier.set_jwks(result.jwks);
                    result.ttl
                }
                Err(err) => {
                    tracing::error!("{:?} JWKs update error: {:?}", label, err);
                    Duration::from_secs(60)
                }
            };
            tracing::info!("Updated {:?} JWKs. Next refresh will be in {:?}", label, ttl);
            tokio::time::sleep(ttl).await;
        }
    });
}
