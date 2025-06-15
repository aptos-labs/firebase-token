use crate::header_parser::get_max_age;
use crate::jwk_fetcher::{JwkFetchError, JwkFetchResult, JwkFetcher, JwkInfo};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::Deserialize;
use std::{collections::HashMap, time::Duration};
use async_trait::async_trait;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

const DEFAULT_URL: &str = "https://www.googleapis.com/identitytoolkit/v3/relyingparty/publicKeys";

#[derive(Deserialize)]
struct ResponseBody {
    #[serde(flatten)]
    keys: HashMap<String, String>,
}

pub struct SessionTokenJwkFetcher {
    url: String,
}

impl SessionTokenJwkFetcher {
    pub fn new() -> SessionTokenJwkFetcher {
        SessionTokenJwkFetcher {
            url: DEFAULT_URL.to_string(),
        }
    }

    #[cfg(test)]
    fn new_with_url(url: String) -> SessionTokenJwkFetcher {
        SessionTokenJwkFetcher { url }
    }


}

#[async_trait]
impl JwkFetcher for SessionTokenJwkFetcher {
    async fn fetch_keys(&self) -> Result<JwkFetchResult, JwkFetchError> {
        let response = reqwest::get(&self.url)
            .await
            .map_err(JwkFetchError::RequestError)?;
        let ttl = get_max_age(&response).unwrap_or(DEFAULT_TIMEOUT);
        tracing::info!("SessionTokenJwkFetcher::fetch_keys ttl:{:?}", ttl);

        let response_body = response
            .json::<ResponseBody>()
            .await
            .map_err(JwkFetchError::ResponseBodyError)?;

        let mut jwks = HashMap::new();
        for (kid, pem) in response_body.keys {
            match DecodingKey::from_rsa_pem(pem.as_bytes()) {
                Ok(key) => {
                    jwks.insert(
                        kid,
                        JwkInfo {
                            alg: Algorithm::RS256,
                            key,
                        },
                    );
                }
                Err(err) => {
                    tracing::warn!("Failed parsing DecodingKey: {:?}", err);
                }
            }
        }
        Ok(JwkFetchResult { jwks, ttl })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TEST_RESPONSE: &str = r#"{
        "bZ-_5g": "-----BEGIN CERTIFICATE-----\nMIIDHDCCAgSgAwIBAgIEWg2gfTANBgkqhkiG9w0BAQsFADAzMQ8wDQYDVQQDEwZH\naXRraXQxEzARBgNVBAoTCkdvb2dsZSBJbmMxCzAJBgNVBAYTAlVTMB4XDTI0MTIw\nNjAyMjUzM1oXDTI1MTIwMTAyMjUzM1owMzEPMA0GA1UEAxMGR2l0a2l0MRMwEQYD\nVQQKEwpHb29nbGUgSW5jMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBANyVAukjUNaA9z55PCK3I803APf7g5o+x+h89pOhFQdeHZd+\nAMamdbtLsbmgfZ0lxTaIAbaEdWW9ZLFTLbsO9F8Vc38n0goxdnngS85d1stih0Wm\nY2p04qAkuyFpjVMGLoTtcep9rguc+0UuDTBya0PsEsltE0Dgt8HVGl8ZFnF4QNY4\ncIFl/JTF0JPpGxCj801L/Za+KMneni1bMPxdn7NThoVbw39MVqdIYTjnWxFnDnZ5\nUSLIxOhFHtCaf6kQw3uNkykiZiM90XzADEb3RU1uShEweuSh/W890tnG8uXOe34/\nMVSRvwcbD4sJvMC4EKsYzzJ4mN/i4GC5gHfSjyMCAwEAAaM4MDYwDAYDVR0TAQH/\nBAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAjAOBgNVHQ8BAf8EBAMCB4AwDQYJ\nKoZIhvcNAQELBQADggEBAEIPdO5ldIQ1E50l0GakrIi2xc817CyiVpi6JtnQ0eHf\neO8u0USiITiYNbXqQqZwRfXeHumnhE5lojgYemPIhcaHJB1aCRH2rXe0drRhw26/\ncNPy7C7M5xQS1n5Ex1sdo4cwTALtNwzUPucSe7jZ8Ywv3p7ZAooY0i24TxKaAanw\nOSSGAeebItdRclHtl3nv8YtHXHlJWAtmnen8MvKQF5ECcoOeBgLlmvuHhhRaoA46\nxn6VvWTpCRA4zszqsWWbFwNCcvdCQfkX9HfE2l/zaJnqjpIkVpvJLi17ZZ6K1+sw\na0kVeYBiAp6FvAN5qEfC8SksLGG8ZgA7NYVNpwNiegQ=\n-----END CERTIFICATE-----\n"
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
    async fn test_fetch_and_verification() {
        let mock_server = get_mock_server().await;
        let result = SessionTokenJwkFetcher::new_with_url(mock_server.uri())
            .fetch_keys()
            .await;

        assert!(result.is_ok());
        let result = result.unwrap();

        assert_eq!(result.ttl, Duration::from_secs(20045));
        assert_eq!(result.jwks.len(), 1);

        let jwk = result.jwks.get("bZ-_5g");
        assert!(jwk.is_some_and(|jwk| jwk.alg == Algorithm::RS256));
    }
}
