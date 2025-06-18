use jsonwebtoken::{Algorithm, DecodingKey};
use std::collections::HashMap;
use std::fmt;
use std::fmt::Formatter;
use std::time::Duration;

pub(crate) struct JwkInfo {
    pub(crate) alg: Algorithm,
    pub(crate) key: DecodingKey,
}

impl fmt::Debug for JwkInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecodingKey")
            .field("alg", &self.alg)
            .finish()
    }
}

#[derive(Debug)]
pub(crate) struct JwkFetchResult {
    pub(crate) jwks: HashMap<String, JwkInfo>,
    pub(crate) ttl: Duration,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum JwkFetchError {
    RequestError(reqwest::Error),
    ResponseBodyError(reqwest::Error),
}

#[cfg(test)]
pub(crate) mod tests {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    
    pub(crate) const EXPECTED_MAX_AGE: u64 = 20045;
    
    pub(crate) async fn setup_mock_server(test_response: &str) -> MockServer {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Cache-Control", "public, max-age=20045")
                    .set_body_raw(test_response, "application/json"),
            )
            .mount(&mock_server)
            .await;

        mock_server
    }
}
