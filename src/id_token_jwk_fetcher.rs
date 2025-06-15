use crate::header_parser::get_max_age;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::{Deserialize};
use std::collections::HashMap;
use std::time::Duration;
use crate::jwk_fetcher::{JwkFetchError, JwkFetchResult, JwkFetcher, JwkInfo};
use std::str::FromStr;
use async_trait::async_trait;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

const DEFAULT_URL: &str =
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

#[derive(Deserialize)]
struct Jwk {
    e: String,
    alg: String,
    kid: String,
    n: String,
}

#[derive(Deserialize)]
struct ResponseBody {
    keys: Vec<Jwk>,
}

pub struct IdTokenJwkFetcher {
    url: String,
}

impl IdTokenJwkFetcher {
    pub fn new() -> IdTokenJwkFetcher {
        IdTokenJwkFetcher { url: DEFAULT_URL.to_string() }
    }

    #[cfg(test)]
    fn new_with_url(url: String) -> IdTokenJwkFetcher {
        IdTokenJwkFetcher { url }
    }
}

#[async_trait]
impl JwkFetcher for IdTokenJwkFetcher {
    async fn fetch_keys(&self) -> Result<JwkFetchResult, JwkFetchError> {
        let response = reqwest::get(&self.url)
            .await
            .map_err(JwkFetchError::RequestError)?;
        let ttl = get_max_age(&response).unwrap_or(DEFAULT_TIMEOUT);
        tracing::info!("IdTokenJwkFetcher::fetch_keys ttl:{:?}", ttl);

        let response_body = response
            .json::<ResponseBody>()
            .await
            .map_err(JwkFetchError::ResponseBodyError)?;

        let mut jwks = HashMap::new();
        for jwk in response_body.keys {
            let alg = match Algorithm::from_str(&jwk.alg) {
                Ok(alg) => alg,
                Err(err) => {
                    tracing::warn!("Failed parsing jwk algorithm: {:?}", err);
                    continue;
                }
            };

            let key = match DecodingKey::from_rsa_components(&jwk.n, &jwk.e) {
                Ok(key) => key,
                Err(err) => {
                    tracing::warn!("Failed parsing DecodingKey: {:?}", err);
                    continue;
                }
            };

            jwks.insert(jwk.kid, JwkInfo { alg, key });
        }
        Ok(JwkFetchResult { jwks, ttl })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use jsonwebtoken::Algorithm;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TEST_RESPONSE: &str = r#"{
        "keys": [
            {
                "e": "AQAB",
                "kid": "a4a10dece98366d6f63e167286ae9b611d2baa27",
                "n": "lou_DBKMBSETPo389O1zxMNXy5NmLd_t21kLc3lgXLvYrPl1b0Ay7bBMZavNmrNi3oPXmYtKgoZkhQNPNUB68xiq2GyLRGdg2pB1JFCOqhiOU1k7js8cJxLVaKFpffUC3wV1RAM4o0dw3EGuAk032ht6O07iBdGboSKT4HWGYKvLeCtslDxBZ5YAPEVXWgIq3RhTU3VCo8MbvcNGiNny1rTygGCAWWgxnlkF1QvUQem0aJToh0xPKFjDjoEMSMERURIAiwu9cMr1i6Qoqi7yj6Mk1wIoN4HZv15qrE2goTUUSGUqYkdkC_xRKAYeRrMOV2Wj_tgESxPBKKK-giVWaw",
                "alg": "RS256",
            }
        ]
    }"#;

    async fn get_mock_server() -> MockServer {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Cache-Control", "public, max-age=20045")
                    .set_body_raw(TEST_RESPONSE, "application/json"),
            )
            .mount(&mock_server)
            .await;

        mock_server
    }

    #[tokio::test]
    async fn test_fetch() {
        let mock_server = get_mock_server().await;
        let result = IdTokenJwkFetcher::new_with_url(mock_server.uri())
            .fetch_keys()
            .await;

        assert!(result.is_ok());
        let result = result.unwrap();

        assert_eq!(result.ttl, Duration::from_secs(20045));
        assert_eq!(result.jwks.len(), 1);
        
        let jwk = result.jwks.get("a4a10dece98366d6f63e167286ae9b611d2baa27");
        assert!(jwk.is_some_and(|jwk| jwk.alg == Algorithm::RS256));
    }
}
