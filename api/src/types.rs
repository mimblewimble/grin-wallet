// Copyright 2019 The Grin Developers
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::core::libtx::secp_ser;
use crate::libwallet::dalek_ser;
use crate::libwallet::{Error, ErrorKind};
use crate::util::secp::key::{PublicKey, SecretKey};
use crate::util::{from_hex, to_hex};
use failure::ResultExt;

use base64;
use ed25519_dalek::PublicKey as DalekPublicKey;
use rand::{thread_rng, Rng};
use ring::aead;
use serde_json::{self, Value};
use std::collections::HashMap;

/// Represents a compliant JSON RPC 2.0 id.
/// Valid id: Integer, String.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum JsonId {
	/// Integer Id
	IntId(u32),
	/// String Id
	StrId(String),
}

/// Wrapper for API Tokens
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(transparent)]
pub struct Token {
	#[serde(with = "secp_ser::option_seckey_serde")]
	/// Token to XOR mask against the stored wallet seed
	pub keychain_mask: Option<SecretKey>,
}

/// Wrapper for dalek public keys, used as addresses
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(transparent)]
pub struct PubAddress {
	#[serde(with = "dalek_ser::dalek_pubkey_serde")]
	/// Public address
	pub address: DalekPublicKey,
}

/// Wrapper for ECDH Public keys
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(transparent)]
pub struct ECDHPubkey {
	/// public key, flattened
	#[serde(with = "secp_ser::pubkey_serde")]
	pub ecdh_pubkey: PublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedBody {
	/// nonce used for encryption
	pub nonce: String,
	/// Encrypted base64 body request
	pub body_enc: String,
}

impl EncryptedBody {
	/// Encrypts and encodes json as base 64
	pub fn from_json(json_in: &Value, enc_key: &SecretKey) -> Result<Self, Error> {
		let mut to_encrypt = serde_json::to_string(&json_in)
			.context(ErrorKind::APIEncryption(
				"EncryptedBody Enc: Unable to encode JSON".to_owned(),
			))?
			.as_bytes()
			.to_vec();

		let nonce: [u8; 12] = thread_rng().gen();

		let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &enc_key.0).unwrap();
		let sealing_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let aad = aead::Aad::from(&[]);
		let res = sealing_key.seal_in_place_append_tag(
			aead::Nonce::assume_unique_for_key(nonce),
			aad,
			&mut to_encrypt,
		);
		if let Err(_) = res {
			return Err(
				ErrorKind::APIEncryption("EncryptedBody: encryption failed".to_owned()).into(),
			);
		}

		Ok(EncryptedBody {
			nonce: to_hex(nonce.to_vec()),
			body_enc: base64::encode(&to_encrypt),
		})
	}

	/// return serialize JSON self
	pub fn as_json_value(&self) -> Result<Value, Error> {
		let res = serde_json::to_value(self).context(ErrorKind::APIEncryption(
			"EncryptedBody: JSON serialization failed".to_owned(),
		))?;
		Ok(res)
	}

	/// return serialized JSON self as string
	pub fn as_json_str(&self) -> Result<String, Error> {
		let res = self.as_json_value()?;
		let res = serde_json::to_string(&res).context(ErrorKind::APIEncryption(
			"EncryptedBody: JSON String serialization failed".to_owned(),
		))?;
		Ok(res)
	}

	/// Return original request
	pub fn decrypt(&self, dec_key: &SecretKey) -> Result<Value, Error> {
		let mut to_decrypt = base64::decode(&self.body_enc).context(ErrorKind::APIEncryption(
			"EncryptedBody Dec: Encrypted request contains invalid Base64".to_string(),
		))?;
		let nonce = from_hex(&self.nonce).map_err(|_| {
			ErrorKind::APIEncryption("EncryptedBody Dec: Invalid Nonce".to_string())
		})?;
		if nonce.len() < 12 {
			return Err(ErrorKind::APIEncryption(
				"EncryptedBody Dec: Invalid Nonce length".to_string(),
			)
			.into());
		}
		let mut n = [0u8; 12];
		n.copy_from_slice(&nonce[0..12]);
		let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &dec_key.0).unwrap();
		let opening_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let aad = aead::Aad::from(&[]);
		let res =
			opening_key.open_in_place(aead::Nonce::assume_unique_for_key(n), aad, &mut to_decrypt);
		if let Err(_) = res {
			return Err(
				ErrorKind::APIEncryption("EncryptedBody: decryption failed".to_owned()).into(),
			);
		}
		for _ in 0..aead::AES_256_GCM.tag_len() {
			to_decrypt.pop();
		}

		let decrypted = String::from_utf8(to_decrypt).context(ErrorKind::APIEncryption(
			"EncryptedBody Dec: Invalid UTF-8".to_string(),
		))?;
		Ok(
			serde_json::from_str(&decrypted).context(ErrorKind::APIEncryption(
				"EncryptedBody Dec: Invalid JSON".to_string(),
			))?,
		)
	}
}

/// Wrapper for secure JSON requests
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedRequest {
	/// JSON RPC response
	pub jsonrpc: String,
	/// method
	pub method: String,
	/// id
	pub id: JsonId,
	/// Body params, which includes nonce and encrypted request
	pub params: EncryptedBody,
}

impl EncryptedRequest {
	/// from json
	pub fn from_json(id: &JsonId, json_in: &Value, enc_key: &SecretKey) -> Result<Self, Error> {
		Ok(EncryptedRequest {
			jsonrpc: "2.0".to_owned(),
			method: "encrypted_request_v3".to_owned(),
			id: id.clone(),
			params: EncryptedBody::from_json(json_in, enc_key)?,
		})
	}

	/// return serialize JSON self
	pub fn as_json_value(&self) -> Result<Value, Error> {
		let res = serde_json::to_value(self).context(ErrorKind::APIEncryption(
			"EncryptedRequest: JSON serialization failed".to_owned(),
		))?;
		Ok(res)
	}

	/// return serialized JSON self as string
	pub fn as_json_str(&self) -> Result<String, Error> {
		let res = self.as_json_value()?;
		let res = serde_json::to_string(&res).context(ErrorKind::APIEncryption(
			"EncryptedRequest: JSON String serialization failed".to_owned(),
		))?;
		Ok(res)
	}

	/// Return decrypted body
	pub fn decrypt(&self, dec_key: &SecretKey) -> Result<Value, Error> {
		self.params.decrypt(dec_key)
	}
}

/// Wrapper for secure JSON requests
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedResponse {
	/// JSON RPC response
	pub jsonrpc: String,
	/// id
	pub id: JsonId,
	/// result
	pub result: HashMap<String, EncryptedBody>,
}

impl EncryptedResponse {
	/// from json
	pub fn from_json(id: &JsonId, json_in: &Value, enc_key: &SecretKey) -> Result<Self, Error> {
		let mut result_set = HashMap::new();
		result_set.insert(
			"Ok".to_string(),
			EncryptedBody::from_json(json_in, enc_key)?,
		);
		Ok(EncryptedResponse {
			jsonrpc: "2.0".to_owned(),
			id: id.clone(),
			result: result_set,
		})
	}

	/// return serialize JSON self
	pub fn as_json_value(&self) -> Result<Value, Error> {
		let res = serde_json::to_value(self).context(ErrorKind::APIEncryption(
			"EncryptedResponse: JSON serialization failed".to_owned(),
		))?;
		Ok(res)
	}

	/// return serialized JSON self as string
	pub fn as_json_str(&self) -> Result<String, Error> {
		let res = self.as_json_value()?;
		let res = serde_json::to_string(&res).context(ErrorKind::APIEncryption(
			"EncryptedResponse: JSON String serialization failed".to_owned(),
		))?;
		Ok(res)
	}

	/// Return decrypted body
	pub fn decrypt(&self, dec_key: &SecretKey) -> Result<Value, Error> {
		self.result.get("Ok").unwrap().decrypt(dec_key)
	}
}

/// Wrapper for encryption error responses
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptionError {
	/// code
	pub code: i32,
	/// message
	pub message: String,
}

/// Wrapper for encryption error responses
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptionErrorResponse {
	/// JSON RPC response
	pub jsonrpc: String,
	/// id
	#[serde(with = "secp_ser::string_or_u64")]
	pub id: u64,
	/// error
	pub error: EncryptionError,
}

impl EncryptionErrorResponse {
	/// Create new response
	pub fn new(id: u64, code: i32, message: &str) -> Self {
		EncryptionErrorResponse {
			jsonrpc: "2.0".to_owned(),
			id: id,
			error: EncryptionError {
				code: code,
				message: message.to_owned(),
			},
		}
	}

	/// return serialized JSON self
	pub fn as_json_value(&self) -> Value {
		let res = serde_json::to_value(self).context(ErrorKind::APIEncryption(
			"EncryptedResponse: JSON serialization failed".to_owned(),
		));
		match res {
			Ok(r) => r,
			// proverbial "should never happen"
			Err(r) => serde_json::json!({
					"json_rpc" : "2.0",
					"id" : "1",
					"error" : {
						"message": format!("internal error serialising json error response {}", r),
						"code": -32000
					}
				}
			),
		}
	}
}

#[test]
fn encrypted_request() -> Result<(), Error> {
	use crate::util::{from_hex, static_secp_instance};

	let sec_key_str = "e00dcc4a009e3427c6b1e1a550c538179d46f3827a13ed74c759c860761caf1e";
	let shared_key = {
		let secp_inst = static_secp_instance();
		let secp = secp_inst.lock();

		let sec_key_bytes = from_hex(sec_key_str).unwrap();
		SecretKey::from_slice(&secp, &sec_key_bytes)?
	};
	let req = serde_json::json!({
		"jsonrpc": "2.0",
		"method": "accounts",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000"
		}
	});
	let enc_req =
		EncryptedRequest::from_json(&JsonId::StrId(String::from("1")), &req, &shared_key)?;
	println!("{:?}", enc_req);
	let dec_req = enc_req.decrypt(&shared_key)?;
	println!("{:?}", dec_req);
	assert_eq!(req, dec_req);
	let enc_res = EncryptedResponse::from_json(&JsonId::IntId(1), &req, &shared_key)?;
	println!("{:?}", enc_res);
	println!("{:?}", enc_res.as_json_str()?);
	let dec_res = enc_res.decrypt(&shared_key)?;
	println!("{:?}", dec_res);
	assert_eq!(req, dec_res);
	Ok(())
}
