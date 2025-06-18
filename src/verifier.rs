use crate::jwk_fetcher::JwkInfo;
use jsonwebtoken::decode_header;
use jsonwebtoken::TokenData;
use jsonwebtoken::{decode, Validation};
use serde::de::DeserializeOwned;
use std::collections::HashMap;

#[derive(Debug)]
pub enum VerificationError {
    DecodingError,
    JwkUnavailable,
    InvalidSignature,
}

pub(crate) struct JwtVerifier {
    issuer: String,
    audience: String,
    jwks: HashMap<String, JwkInfo>,
}

impl JwtVerifier {
    pub(crate) fn new(audience: String, issuer: String) -> JwtVerifier {
        JwtVerifier {
            issuer,
            audience,
            jwks: HashMap::new(),
        }
    }

    pub(crate) fn set_jwks(&mut self, jwks: HashMap<String, JwkInfo>) {
        self.jwks = jwks;
    }

    pub(crate) fn verify<'a, C: DeserializeOwned + 'a>(
        &self,
        token: &str,
    ) -> Result<TokenData<C>, VerificationError> {
        let kid = match decode_header(token).map(|header| header.kid) {
            Ok(Some(header)) => header,
            _ => return Err(VerificationError::DecodingError),
        };

        let jwk = match self.jwks.get(&kid) {
            Some(jwk) => jwk,
            _ => return Err(VerificationError::JwkUnavailable),
        };

        let mut validation = Validation::new(jwk.alg);
        validation.set_issuer(&[self.issuer.clone()]);
        validation.set_audience(&[self.audience.clone()]);

        decode::<C>(token, &jwk.key, &validation).map_err(|_| VerificationError::InvalidSignature)
    }
}
