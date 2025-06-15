use async_trait::async_trait;
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

#[async_trait]
pub trait JwkFetcher: Send {
    async fn fetch_keys(&self) -> Result<JwkFetchResult, JwkFetchError>;
}
