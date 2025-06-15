mod header_parser;
mod id_token_jwk_fetcher;
mod auth;
mod jwk_fetcher;
mod session_token_jwk_fetcher;
mod verifier;

use serde::{Deserialize, Serialize};

pub use auth::FirebaseTokenAuth;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BasicClaims {
    pub aud: String,
    pub exp: i64,
    pub iss: String,
    pub sub: String,
    pub iat: i64,
}
