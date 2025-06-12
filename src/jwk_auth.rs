use crate::jwk::JwkFetcher;
use crate::verifier::JwkVerifier;
use jsonwebtoken::TokenData;
use serde::de::DeserializeOwned;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

const ISSUER_URL: &str = "https://securetoken.google.com/";
const SESSION_ISSUER_URL: &str = "https://session.firebase.google.com/";
const DEFAULT_PUBKEY_URL: &str =
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

#[derive(Clone)]
pub struct JwkAuth {
    verifier: Arc<Mutex<JwkVerifier>>,
}

impl JwkAuth {
    pub async fn new(project_id: String) -> JwkAuth {
        let pubkey_url = DEFAULT_PUBKEY_URL.to_string();
        Self::new_with_url(project_id, pubkey_url).await
    }

    pub async fn new_with_url(project_id: String, pubkey_url: String) -> JwkAuth {
        Self::new_with_options(project_id, pubkey_url, false).await
    }

    pub async fn new_accepting_session_tokens(project_id: String) -> JwkAuth {
        let pubkey_url = DEFAULT_PUBKEY_URL.to_string();
        Self::new_with_options(project_id, pubkey_url, true).await
    }

    pub async fn new_with_options(project_id: String, pubkey_url: String, accept_session_token: bool) -> JwkAuth {
        let issuer = format!("{}{}", ISSUER_URL, project_id.clone());
        let mut issuers = vec![issuer];
        if accept_session_token {
            let session_issuer = format!("{}{}", SESSION_ISSUER_URL, project_id.clone());
            issuers.push(session_issuer);
        }
        
        let audience = project_id;
        let fetcher = JwkFetcher::new(pubkey_url);

        let jwk_key_result = fetcher.fetch_keys().await;
        let jwk_keys = match jwk_key_result {
            Ok(keys) => keys,
            Err(err) => {
                panic!("Unable to fetch jwk keys {:?}!", err)
            }
        };

        let verifier = Arc::new(Mutex::new(JwkVerifier::new(
            jwk_keys.keys,
            audience,
            issuers,
        )));

        Self::start_periodic_key_update(fetcher, verifier.clone());

        JwkAuth { verifier }
    }

    pub async fn verify<'a, C: DeserializeOwned + 'a>(&self, token: &str) -> Option<TokenData<C>> {
        let verifier = self.verifier.lock().await;
        verifier.verify(token)
    }

    fn start_periodic_key_update(fetcher: JwkFetcher, verifier: Arc<Mutex<JwkVerifier>>) {
        tokio::spawn(async move {
            loop {
                let fetch_result = fetcher.fetch_keys().await;
                let delay = match fetch_result {
                    Ok(jwk_keys) => {
                        let mut verifier = verifier.lock().await;
                        verifier.set_keys(jwk_keys.keys);
                        tracing::info!(
                            "Updated JWK Keys. Next refresh will be in {:?}",
                            jwk_keys.validity
                        );
                        jwk_keys.validity
                    }
                    Err(err) => {
                        tracing::error!("Update JWK Keys Error {:?}", err);
                        Duration::from_secs(10)
                    }
                };
                tracing::info!("Fetcher sleeps {:?}", delay);
                tokio::time::sleep(delay).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::*;
    use crate::verifier::JwkConfig;

    #[tokio::test]
    async fn test_jwk_auth_new() {
        let keys = get_test_keys();
        let mock_server = get_mock_server().await;
        let project_id = "pj".to_string();

        let jwk_auth = JwkAuth::new_with_url(project_id.clone(), get_mock_url(&mock_server)).await;
        let verifier = jwk_auth.verifier.lock().await;

        assert_eq!(verifier.get_key("kid-0"), Some(&keys[0]));
        assert_eq!(verifier.get_key("kid-1"), Some(&keys[1]));
        assert_eq!(
            verifier.get_config(),
            Some(&JwkConfig {
                audience: project_id.clone(),
                issuers: vec![format!("{}{}", ISSUER_URL, project_id.clone())]
            })
        );
    }
}
