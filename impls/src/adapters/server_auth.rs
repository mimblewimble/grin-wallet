//! Https SlateSender that checks to make sure the public key presented by the remote server
//! matches an expected public key. Provides server authentication and encryption without
//! relying on Public Key Infastructure.

// use crate::foreign_rpc_client;
use crate::libwallet::{Error, ErrorKind, Slate};
use crate::SlateSender;
use serde_json::{json, Value};
use url::Url;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct PublicKey(pub [u8; 32]);

/// Address to and public key of server running the V2 jsonrpc foreign api on https
pub struct AuthenticatedHttpsSlateSender {
	remote_foreign_url: Url,
	remote_pk: PublicKey,
}

impl AuthenticatedHttpsSlateSender {
	/// Create, return Error if url scheme is not https
	fn new(url: Url, public_key: PublicKey) -> Result<AuthenticatedHttpsSlateSender, NotHttps> {
		if url.scheme() == "https" {
			Ok(AuthenticatedHttpsSlateSender {
				remote_foreign_url: url
					.join("/v2/foreign")
					.expect("/v2/foreign is an invalid url path"),
				remote_pk: public_key,
			})
		} else {
			Err(NotHttps)
		}
	}

	fn post_authenticated(&self, body: &Value) -> Result<String, Error> {
		// create TLSConfig with custom cert validation logic. That custom logic should only
		// assert the cert is valid if the servers public key == self.remote_pk
		// check out https://github.com/bddap/tryquinn for a starting point

		// make an https post to server using said TLSConfig
	}
}

impl SlateSender for AuthenticatedHttpsSlateSender {
	fn send_tx(&self, slate: &Slate) -> Result<Slate, Error> {
		// create jsonrpc request maually
		// not using generated client helpers as adding grin_wallet_api to impls/Cargo.toml creates a
		// dependency cycle
		let req = json!({
			"jsonrpc": "2.0",
			"method": "receive_tx",
			"id": 1,
			"params": [slate, null, null]
		});

		// send post request to self.remote_foreign_url using custom tls config
		let res = self.post_authenticated(&req)?;

		// parse and return result
		let res: Value = serde_json::from_str(&res).map_err(|e| ErrorKind::SlateDeser)?;
		if res["error"] != json!(null) {
			Err(ErrorKind::ClientCallback(format!(
				"Posting transaction slate: Error: {}, Message: {}",
				res["error"]["code"], res["error"]["message"]
			))
			.into())
		} else {
			Slate::deserialize_upgrade(
				&serde_json::to_string(&res["result"]["Ok"])
					.expect("error serializing json value to string"),
			)
			.map_err(|_| ErrorKind::SlateDeser.into())
		}
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
