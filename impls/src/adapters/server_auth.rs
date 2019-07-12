//! Https SlateSender that checks to make sure the public key presented by the remote server
//! matches an expected public key. Provides server authentication and encryption without
//! relying on Public Key Infastructure.

use crate::libwallet::{Error, ErrorKind, Slate};
use crate::SlateSender;
use url::Url;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct PublicKey(pub [u8; 32]);

/// Address to and public key of server running the V2 jsonrpc foreign api on https
pub struct AuthenticatedHttpsSlateSender {
	remote_base_url: Url,
	remote_pk: PublicKey,
}

impl AuthenticatedHttpsSlateSender {
	/// Create, return Error if url scheme is not https
	fn new(url: Url, public_key: PublicKey) -> Result<AuthenticatedHttpsSlateSender, NotHttps> {
		if url.scheme() == "https" {
			Ok(AuthenticatedHttpsSlateSender {
				remote_base_url: url,
				remote_pk: public_key,
			})
		} else {
			Err(NotHttps)
		}
	}
}

impl SlateSender for AuthenticatedHttpsSlateSender {
	fn send_tx(&self, _slate: &Slate) -> Result<Slate, Error> {
		// create TLSConfig with custom cert validation logic. That custom logic should only
		// assert the cert is valid if the servers public key == self.remote_pk
		// check out https://github.com/bddap/tryquinn for a starting point

		// create jsonrpc request maually, or if you want type checking use the generated
		// client stubs for foreign api

		// send post request to self.remote_base_url + "/v2/foreign" using custom tls config

		// parse and return result
	}
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct NotHttps;

impl Into<Error> for NotHttps {
	fn into(self) -> Error {
		let err_str = format!("url scheme must be https",);
		ErrorKind::GenericError(err_str).into()
	}
}
