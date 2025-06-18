use crate::verifier::{JwtVerifier, VerificationError};
use jsonwebtoken::TokenData;
use serde::de::DeserializeOwned;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use crate::id_token_jwk_fetcher::IdTokenJwkFetcher;
use crate::session_token_jwk_fetcher::SessionTokenJwkFetcher;

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

            let jwk_fetcher = JwkFetcher::IdToken(IdTokenJwkFetcher::new());
            start_periodic_jwks_update(jwk_fetcher, verifier.clone());
            verifiers.push(verifier);
        }

        if with_session_tokens {
            let issuer = format!("{}{}", SESSION_TOKEN_ISSUER_URL, project_id.clone());
            let verifier = Arc::new(Mutex::new(JwtVerifier::new(audience.clone(), issuer)));

            let jwk_fetcher = JwkFetcher::SessionToken(SessionTokenJwkFetcher::new());
            start_periodic_jwks_update(jwk_fetcher, verifier.clone());
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

enum JwkFetcher {
    IdToken(IdTokenJwkFetcher),
    SessionToken(SessionTokenJwkFetcher),
}

fn start_periodic_jwks_update(fetcher: JwkFetcher, verifier: Arc<Mutex<JwtVerifier>>) {
    tokio::spawn(async move {
        let label = match &fetcher {
            JwkFetcher::IdToken(_f) => "ID token",
            JwkFetcher::SessionToken(_f) =>  "Session token",
        };

        loop {
            let result = match &fetcher {
                JwkFetcher::IdToken(f) => f.fetch_keys().await,
                JwkFetcher::SessionToken(f) =>  f.fetch_keys().await,
            };

            let ttl = match result {
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
