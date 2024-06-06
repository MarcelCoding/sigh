use crate::{Error, PrivateKey, PublicKey};
mod rsa_sha256;
use openssl::{hash::MessageDigest, rsa::Padding, sign::Verifier};
use rsa::sha2::Sha256;
use rsa::signature::SignatureEncoding;
use rsa::signature::Signer;
use rsa::{pkcs1v15::SigningKey, pkcs8::DecodePrivateKey, RsaPrivateKey};
pub use rsa_sha256::RsaSha256;

/// Find signature algorithm implementation by name
pub fn by_name(name: &str) -> Option<Box<dyn Algorithm>> {
    match name {
        "rsa-sha256" => Some(Box::new(rsa_sha256::RsaSha256)),
        _ => None,
    }
}

/// Signature algorithm
pub trait Algorithm {
    /// Signature algorithm name
    fn name(&self) -> &'static str;

    /// Generate private and public keys suitable for this algorithm
    fn generate_keys(&self) -> Result<(PrivateKey, PublicKey), Error>;

    /// `openssl::hash::MessageDigest` specified by this algorithm
    fn message_digest(&self) -> Option<MessageDigest>;

    /// RSA padding mode specified by this algorithm
    fn rsa_padding(&self) -> Option<Padding> {
        None
    }

    /// Sign data
    fn sign(&self, private_key: &PrivateKey, data: &[u8]) -> Result<Vec<u8>, Error> {
        let pkey = &private_key.0;
        let pem = pkey.private_key_to_pem_pkcs8().unwrap();
        let priv_key = RsaPrivateKey::from_pkcs8_pem(std::str::from_utf8(&pem).unwrap()).unwrap();
        let signing_key = SigningKey::<Sha256>::new(priv_key);
        let d = signing_key.sign(data);

        Ok(d.to_vec())
    }

    /// Verify a signature
    fn verify(&self, public_key: &PublicKey, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
        let pkey = &public_key.0;
        let mut verifier = match self.message_digest() {
            Some(message_digest) => Verifier::new(message_digest, &pkey)?,
            None => Verifier::new_without_digest(&pkey)?,
        };
        if let Some(padding) = self.rsa_padding() {
            verifier.set_rsa_padding(padding)?;
        }
        Ok(verifier.verify_oneshot(&signature, data)?)
    }
}
