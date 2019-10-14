// Copyright 2019 The Grin Developers
//
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

//! Controller for wallet.. instantiates and handles listeners (or single-run
//! invocations) as needed.
use crate::api::{self, ApiServer, BasicAuthMiddleware, ResponseFuture, Router, TLSConfig};
use crate::keychain::Keychain;
use crate::libwallet::{
	Error, ErrorKind, NodeClient, NodeVersionInfo, Slate, WalletInst, WalletLCProvider,
	CURRENT_SLATE_VERSION, GRIN_BLOCK_HEADER_VERSION,
};
use crate::util::secp::key::SecretKey;
use crate::util::{from_hex, static_secp_instance, to_base64, Mutex};
use failure::ResultExt;
use futures::future::{err, ok};
use futures::{Future, Stream};
use hyper::header::HeaderValue;
use hyper::{Body, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::impls::tor::config as tor_config;
use crate::impls::tor::process as tor_process;

use crate::apiwallet::{
	EncryptedRequest, EncryptedResponse, EncryptionErrorResponse, Foreign,
	ForeignCheckMiddlewareFn, ForeignRpc, Owner, OwnerRpc, OwnerRpcS,
};
use easy_jsonrpc_mw;
use easy_jsonrpc_mw::{Handler, MaybeReply};

lazy_static! {
	pub static ref GRIN_OWNER_BASIC_REALM: HeaderValue =
		HeaderValue::from_str("Basic realm=GrinOwnerAPI").unwrap();
}

fn check_middleware(
	name: ForeignCheckMiddlewareFn,
	node_version_info: Option<NodeVersionInfo>,
	slate: Option<&Slate>,
) -> Result<(), Error> {
	match name {
		// allow coinbases to be built regardless
		ForeignCheckMiddlewareFn::BuildCoinbase => Ok(()),
		_ => {
			let mut bhv = 1;
			if let Some(n) = node_version_info {
				bhv = n.block_header_version;
			}
			if let Some(s) = slate {
				if s.version_info.version < CURRENT_SLATE_VERSION
					|| (bhv == 1 && s.version_info.block_header_version != 1)
					|| (bhv > 1 && s.version_info.block_header_version < GRIN_BLOCK_HEADER_VERSION)
				{
					Err(ErrorKind::Compatibility(
						"Incoming Slate is not compatible with this wallet. \
						 Please upgrade the node or use a different one."
							.into(),
					))?;
				}
			}
			Ok(())
		}
	}
}

/// initiate the tor listener
fn init_tor_listener<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	addr: &str,
) -> Result<tor_process::TorProcess, Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let mut process = tor_process::TorProcess::new();
	let mask = keychain_mask.lock();
	// eventually want to read a list of service config keys
	let mut w_lock = wallet.lock();
	let lc = w_lock.lc_provider()?;
	let w_inst = lc.wallet_inst()?;
	let k = w_inst.keychain((&mask).as_ref())?;
	let parent_key_id = w_inst.parent_key_id();
	let tor_dir = format!("{}/tor/listener", lc.get_top_level_directory()?);
	let sec_key = tor_config::address_derivation_path(&k, &parent_key_id, 0)
		.map_err(|e| ErrorKind::TorConfig(format!("{:?}", e).into()))?;
	let onion_address = tor_config::onion_address_from_seckey(&sec_key)
		.map_err(|e| ErrorKind::TorConfig(format!("{:?}", e).into()))?;
	warn!(
		"Starting TOR Hidden Service for API listener at address {}, binding to {}",
		onion_address, addr
	);
	tor_config::output_tor_listener_config(&tor_dir, addr, &vec![sec_key])
		.map_err(|e| ErrorKind::TorConfig(format!("{:?}", e).into()))?;
	// Start TOR process
	process
		.torrc_path(&format!("{}/torrc", tor_dir))
		.working_dir(&tor_dir)
		.timeout(20)
		.completion_percent(100)
		.launch()
		.map_err(|e| ErrorKind::TorProcess(format!("{:?}", e).into()))?;
	Ok(process)
}

/// Instantiate wallet Owner API for a single-use (command line) call
/// Return a function containing a loaded API context to call
pub fn owner_single_use<'a, L, F, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	f: F,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	F: FnOnce(&mut Owner<'a, L, C, K>, Option<&SecretKey>) -> Result<(), Error>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	f(&mut Owner::new(wallet), keychain_mask)?;
	Ok(())
}

/// Instantiate wallet Foreign API for a single-use (command line) call
/// Return a function containing a loaded API context to call
pub fn foreign_single_use<'a, L, F, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<SecretKey>,
	f: F,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	F: FnOnce(&mut Foreign<'a, L, C, K>) -> Result<(), Error>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	f(&mut Foreign::new(
		wallet,
		keychain_mask,
		Some(check_middleware),
	))?;
	Ok(())
}

/// Listener version, providing same API but listening for requests on a
/// port and wrapping the calls
/// Note keychain mask is only provided here in case the foreign listener is also being used
/// in the same wallet instance
pub fn owner_listener<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	addr: &str,
	api_secret: Option<String>,
	tls_config: Option<TLSConfig>,
	owner_api_include_foreign: Option<bool>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let mut router = Router::new();
	if api_secret.is_some() {
		let api_basic_auth =
			"Basic ".to_string() + &to_base64(&("grin:".to_string() + &api_secret.unwrap()));
		let basic_auth_middleware = Arc::new(BasicAuthMiddleware::new(
			api_basic_auth,
			&GRIN_OWNER_BASIC_REALM,
			Some("/v2/foreign".into()),
		));
		router.add_middleware(basic_auth_middleware);
	}
	let mut running_foreign = false;
	if owner_api_include_foreign.unwrap_or(false) {
		running_foreign = true;
	}

	let api_handler_v2 = OwnerAPIHandlerV2::new(wallet.clone());
	let api_handler_v3 =
		OwnerAPIHandlerV3::new(wallet.clone(), keychain_mask.clone(), running_foreign);

	router
		.add_route("/v2/owner", Arc::new(api_handler_v2))
		.map_err(|_| ErrorKind::GenericError("Router failed to add route".to_string()))?;

	router
		.add_route("/v3/owner", Arc::new(api_handler_v3))
		.map_err(|_| ErrorKind::GenericError("Router failed to add route".to_string()))?;

	// If so configured, add the foreign API to the same port
	if running_foreign {
		warn!("Starting HTTP Foreign API on Owner server at {}.", addr);
		let foreign_api_handler_v2 = ForeignAPIHandlerV2::new(wallet, keychain_mask);
		router
			.add_route("/v2/foreign", Arc::new(foreign_api_handler_v2))
			.map_err(|_| ErrorKind::GenericError("Router failed to add route".to_string()))?;
	}

	let mut apis = ApiServer::new();
	warn!("Starting HTTP Owner API server at {}.", addr);
	let socket_addr: SocketAddr = addr.parse().expect("unable to parse socket address");
	let api_thread =
		apis.start(socket_addr, router, tls_config)
			.context(ErrorKind::GenericError(
				"API thread failed to start".to_string(),
			))?;
	warn!("HTTP Owner listener started.");
	api_thread
		.join()
		.map_err(|e| ErrorKind::GenericError(format!("API thread panicked :{:?}", e)).into())
}

/// Listener version, providing same API but listening for requests on a
/// port and wrapping the calls
pub fn foreign_listener<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	addr: &str,
	tls_config: Option<TLSConfig>,
	use_tor: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	// need to keep in scope while the main listener is running
	let _tor_process = match use_tor {
		true => match init_tor_listener(wallet.clone(), keychain_mask.clone(), addr) {
			Ok(tp) => Some(tp),
			Err(e) => {
				warn!("Unable to start TOR listener; Check that TOR executable is installed and on your path");
				warn!("Tor Error: {}", e);
				warn!("Listener will be available via HTTP only");
				None
			}
		},
		false => None,
	};

	let api_handler_v2 = ForeignAPIHandlerV2::new(wallet, keychain_mask);
	let mut router = Router::new();

	router
		.add_route("/v2/foreign", Arc::new(api_handler_v2))
		.map_err(|_| ErrorKind::GenericError("Router failed to add route".to_string()))?;

	let mut apis = ApiServer::new();
	warn!("Starting HTTP Foreign listener API server at {}.", addr);
	let socket_addr: SocketAddr = addr.parse().expect("unable to parse socket address");
	let api_thread =
		apis.start(socket_addr, router, tls_config)
			.context(ErrorKind::GenericError(
				"API thread failed to start".to_string(),
			))?;

	warn!("HTTP Foreign listener started.");

	api_thread
		.join()
		.map_err(|e| ErrorKind::GenericError(format!("API thread panicked :{:?}", e)).into())
}

type WalletResponseFuture = Box<dyn Future<Item = Response<Body>, Error = Error> + Send>;

/// V2 API Handler/Wrapper for owner functions
pub struct OwnerAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Wallet instance
	pub wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
}

impl<L, C, K> OwnerAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Create a new owner API handler for GET methods
	pub fn new(
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	) -> OwnerAPIHandlerV2<L, C, K> {
		OwnerAPIHandlerV2 { wallet }
	}

	fn call_api(
		&self,
		req: Request<Body>,
		api: Owner<'static, L, C, K>,
	) -> Box<dyn Future<Item = serde_json::Value, Error = Error> + Send> {
		Box::new(parse_body(req).and_then(move |val: serde_json::Value| {
			let owner_api = &api as &dyn OwnerRpc;
			match owner_api.handle_request(val) {
				MaybeReply::Reply(r) => ok(r),
				MaybeReply::DontReply => {
					// Since it's http, we need to return something. We return [] because jsonrpc
					// clients will parse it as an empty batch response.
					ok(serde_json::json!([]))
				}
			}
		}))
	}

	fn handle_post_request(&self, req: Request<Body>) -> WalletResponseFuture {
		let api = Owner::new(self.wallet.clone());
		Box::new(
			self.call_api(req, api)
				.and_then(|resp| ok(json_response_pretty(&resp))),
		)
	}
}

impl<L, C, K> api::Handler for OwnerAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn post(&self, req: Request<Body>) -> ResponseFuture {
		Box::new(
			self.handle_post_request(req)
				.and_then(|r| ok(r))
				.or_else(|e| {
					error!("Request Error: {:?}", e);
					ok(create_error_response(e))
				}),
		)
	}

	fn options(&self, _req: Request<Body>) -> ResponseFuture {
		Box::new(ok(create_ok_response("{}")))
	}
}

/// V3 API Handler/Wrapper for owner functions, which include a secure
/// mode + lifecycle functions
pub struct OwnerAPIHandlerV3<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Wallet instance
	pub wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,

	/// ECDH shared key
	pub shared_key: Arc<Mutex<Option<SecretKey>>>,

	/// Keychain mask (to change if also running the foreign API)
	pub keychain_mask: Arc<Mutex<Option<SecretKey>>>,

	/// Whether we're running the foreign API on the same port, and therefore
	/// have to store the mask in-process
	pub running_foreign: bool,
}

pub struct OwnerV3Helpers;

impl OwnerV3Helpers {
	/// Checks whether a request is to init the secure API
	pub fn is_init_secure_api(val: &serde_json::Value) -> bool {
		if let Some(m) = val["method"].as_str() {
			match m {
				"init_secure_api" => true,
				_ => false,
			}
		} else {
			false
		}
	}

	/// Checks whether a request is to open the wallet
	pub fn is_open_wallet(val: &serde_json::Value) -> bool {
		if let Some(m) = val["method"].as_str() {
			match m {
				"open_wallet" => true,
				_ => false,
			}
		} else {
			false
		}
	}

	/// Checks whether a request is an encrypted request
	pub fn is_encrypted_request(val: &serde_json::Value) -> bool {
		if let Some(m) = val["method"].as_str() {
			match m {
				"encrypted_request_v3" => true,
				_ => false,
			}
		} else {
			false
		}
	}

	/// whether encryption is enabled
	pub fn encryption_enabled(key: Arc<Mutex<Option<SecretKey>>>) -> bool {
		let share_key_ref = key.lock();
		share_key_ref.is_some()
	}

	/// If incoming is an encrypted request, check there is a shared key,
	/// Otherwise return an error value
	pub fn check_encryption_started(
		key: Arc<Mutex<Option<SecretKey>>>,
	) -> Result<(), serde_json::Value> {
		match OwnerV3Helpers::encryption_enabled(key) {
			true => Ok(()),
			false => Err(EncryptionErrorResponse::new(
				1,
				-32001,
				"Encryption must be enabled. Please call 'init_secure_api` first",
			)
			.as_json_value()),
		}
	}

	/// Update the statically held owner API shared key
	pub fn update_owner_api_shared_key(
		key: Arc<Mutex<Option<SecretKey>>>,
		val: &serde_json::Value,
		new_key: Option<SecretKey>,
	) {
		if let Some(_) = val["result"]["Ok"].as_str() {
			let mut share_key_ref = key.lock();
			*share_key_ref = new_key;
		}
	}

	/// Update the shared mask, in case of foreign API being run
	pub fn update_mask(mask: Arc<Mutex<Option<SecretKey>>>, val: &serde_json::Value) {
		if let Some(key) = val["result"]["Ok"].as_str() {
			let key_bytes = match from_hex(key.to_owned()) {
				Ok(k) => k,
				Err(_) => return,
			};
			let secp_inst = static_secp_instance();
			let secp = secp_inst.lock();
			let sk = match SecretKey::from_slice(&secp, &key_bytes) {
				Ok(s) => s,
				Err(_) => return,
			};

			let mut shared_mask_ref = mask.lock();
			*shared_mask_ref = Some(sk);
		}
	}

	/// Decrypt an encrypted request
	pub fn decrypt_request(
		key: Arc<Mutex<Option<SecretKey>>>,
		req: &serde_json::Value,
	) -> Result<(u32, serde_json::Value), serde_json::Value> {
		let share_key_ref = key.lock();
		let shared_key = share_key_ref.as_ref().unwrap();
		let enc_req: EncryptedRequest = serde_json::from_value(req.clone()).map_err(|e| {
			EncryptionErrorResponse::new(
				1,
				-32002,
				&format!("Encrypted request format error: {}", e),
			)
			.as_json_value()
		})?;
		let id = enc_req.id;
		let res = enc_req.decrypt(&shared_key).map_err(|e| {
			EncryptionErrorResponse::new(1, -32002, &format!("Decryption error: {}", e.kind()))
				.as_json_value()
		})?;
		Ok((id, res))
	}

	/// Encrypt a response
	pub fn encrypt_response(
		key: Arc<Mutex<Option<SecretKey>>>,
		id: u32,
		res: &serde_json::Value,
	) -> Result<serde_json::Value, serde_json::Value> {
		let share_key_ref = key.lock();
		let shared_key = share_key_ref.as_ref().unwrap();
		let enc_res = EncryptedResponse::from_json(id, res, &shared_key).map_err(|e| {
			EncryptionErrorResponse::new(1, -32003, &format!("EncryptionError: {}", e.kind()))
				.as_json_value()
		})?;
		let res = enc_res.as_json_value().map_err(|e| {
			EncryptionErrorResponse::new(
				1,
				-32002,
				&format!("Encrypted response format error: {}", e),
			)
			.as_json_value()
		})?;
		Ok(res)
	}

	/// convert an internal error (if exists) as proper JSON-RPC
	pub fn check_error_response(val: &serde_json::Value) -> (bool, serde_json::Value) {
		// check for string first. This ensures that error messages
		// that are just strings aren't given weird formatting
		let err_string = if val["result"]["Err"].is_object() {
			let mut retval;
			let hashed: Result<HashMap<String, String>, serde_json::Error> =
				serde_json::from_value(val["result"]["Err"].clone());
			retval = match hashed {
				Err(e) => {
					debug!("Can't cast value to Hashmap<String> {}", e);
					None
				}
				Ok(h) => {
					let mut r = "".to_owned();
					for (k, v) in h.iter() {
						r = format!("{}: {}", k, v);
					}
					Some(r)
				}
			};
			// Otherwise, see if error message is a map that needs
			// to be stringified (and accept weird formatting)
			if retval.is_none() {
				let hashed: Result<HashMap<String, serde_json::Value>, serde_json::Error> =
					serde_json::from_value(val["result"]["Err"].clone());
				retval = match hashed {
					Err(e) => {
						debug!("Can't cast value to Hashmap<Value> {}", e);
						None
					}
					Ok(h) => {
						let mut r = "".to_owned();
						for (k, v) in h.iter() {
							r = format!("{}: {}", k, v);
						}
						Some(r)
					}
				}
			}
			retval
		} else if val["result"]["Err"].is_string() {
			let parsed = serde_json::from_value::<String>(val["result"]["Err"].clone());
			match parsed {
				Ok(p) => Some(p),
				Err(_) => None,
			}
		} else {
			None
		};
		match err_string {
			Some(s) => {
				return (
					true,
					serde_json::json!({
						"jsonrpc": "2.0",
						"id": val["id"],
						"error": {
							"message": s,
							"code": -32099
						}
					}),
				)
			}
			None => (false, val.clone()),
		}
	}
}

impl<L, C, K> OwnerAPIHandlerV3<L, C, K>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Create a new owner API handler for GET methods
	pub fn new(
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Arc<Mutex<Option<SecretKey>>>,
		running_foreign: bool,
	) -> OwnerAPIHandlerV3<L, C, K> {
		OwnerAPIHandlerV3 {
			wallet,
			shared_key: Arc::new(Mutex::new(None)),
			keychain_mask: keychain_mask,
			running_foreign,
		}
	}

	fn call_api(
		&self,
		req: Request<Body>,
		api: Owner<'static, L, C, K>,
	) -> Box<dyn Future<Item = serde_json::Value, Error = Error> + Send> {
		let key = self.shared_key.clone();
		let mask = self.keychain_mask.clone();
		let running_foreign = self.running_foreign;
		Box::new(parse_body(req).and_then(move |val: serde_json::Value| {
			let mut val = val;
			let owner_api_s = &api as &dyn OwnerRpcS;
			let mut is_init_secure_api = OwnerV3Helpers::is_init_secure_api(&val);
			let mut was_encrypted = false;
			let mut encrypted_req_id = 0;
			if !is_init_secure_api {
				if let Err(v) = OwnerV3Helpers::check_encryption_started(key.clone()) {
					return ok(v);
				}
				let res = OwnerV3Helpers::decrypt_request(key.clone(), &val);
				match res {
					Err(e) => return ok(e),
					Ok(v) => {
						encrypted_req_id = v.0;
						val = v.1;
					}
				}
				was_encrypted = true;
			}
			// check again, in case it was an encrypted call to init_secure_api
			is_init_secure_api = OwnerV3Helpers::is_init_secure_api(&val);
			// also need to intercept open/close wallet requests
			let is_open_wallet = OwnerV3Helpers::is_open_wallet(&val);
			match owner_api_s.handle_request(val) {
				MaybeReply::Reply(mut r) => {
					let (_was_error, unencrypted_intercept) =
						OwnerV3Helpers::check_error_response(&r.clone());
					if is_open_wallet && running_foreign {
						OwnerV3Helpers::update_mask(mask, &r.clone());
					}
					if was_encrypted {
						let res = OwnerV3Helpers::encrypt_response(
							key.clone(),
							encrypted_req_id,
							&unencrypted_intercept,
						);
						r = match res {
							Ok(v) => v,
							Err(v) => return ok(v),
						}
					}
					// intercept init_secure_api response (after encryption,
					// in case it was an encrypted call to 'init_api_secure')
					if is_init_secure_api {
						OwnerV3Helpers::update_owner_api_shared_key(
							key.clone(),
							&unencrypted_intercept,
							api.shared_key.lock().clone(),
						);
					}
					ok(r)
				}
				MaybeReply::DontReply => {
					// Since it's http, we need to return something. We return [] because jsonrpc
					// clients will parse it as an empty batch response.
					ok(serde_json::json!([]))
				}
			}
		}))
	}

	fn handle_post_request(&self, req: Request<Body>) -> WalletResponseFuture {
		let api = Owner::new(self.wallet.clone());
		Box::new(
			self.call_api(req, api)
				.and_then(|resp| ok(json_response_pretty(&resp))),
		)
	}
}

impl<L, C, K> api::Handler for OwnerAPIHandlerV3<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn post(&self, req: Request<Body>) -> ResponseFuture {
		Box::new(
			self.handle_post_request(req)
				.and_then(|r| ok(r))
				.or_else(|e| {
					error!("Request Error: {:?}", e);
					ok(create_error_response(e))
				}),
		)
	}

	fn options(&self, _req: Request<Body>) -> ResponseFuture {
		Box::new(ok(create_ok_response("{}")))
	}
}
/// V2 API Handler/Wrapper for foreign functions
pub struct ForeignAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Wallet instance
	pub wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	/// Keychain mask
	pub keychain_mask: Arc<Mutex<Option<SecretKey>>>,
}

impl<L, C, K> ForeignAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Create a new foreign API handler for GET methods
	pub fn new(
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	) -> ForeignAPIHandlerV2<L, C, K> {
		ForeignAPIHandlerV2 {
			wallet,
			keychain_mask,
		}
	}

	fn call_api(
		&self,
		req: Request<Body>,
		api: Foreign<'static, L, C, K>,
	) -> Box<dyn Future<Item = serde_json::Value, Error = Error> + Send> {
		Box::new(parse_body(req).and_then(move |val: serde_json::Value| {
			let foreign_api = &api as &dyn ForeignRpc;
			match foreign_api.handle_request(val) {
				MaybeReply::Reply(r) => ok({ r }),
				MaybeReply::DontReply => {
					// Since it's http, we need to return something. We return [] because jsonrpc
					// clients will parse it as an empty batch response.
					ok(serde_json::json!([]))
				}
			}
		}))
	}

	fn handle_post_request(&self, req: Request<Body>) -> WalletResponseFuture {
		let mask = self.keychain_mask.lock();
		let api = Foreign::new(self.wallet.clone(), mask.clone(), Some(check_middleware));
		Box::new(
			self.call_api(req, api)
				.and_then(|resp| ok(json_response_pretty(&resp))),
		)
	}
}

impl<L, C, K> api::Handler for ForeignAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn post(&self, req: Request<Body>) -> ResponseFuture {
		Box::new(
			self.handle_post_request(req)
				.and_then(|r| ok(r))
				.or_else(|e| {
					error!("Request Error: {:?}", e);
					ok(create_error_response(e))
				}),
		)
	}

	fn options(&self, _req: Request<Body>) -> ResponseFuture {
		Box::new(ok(create_ok_response("{}")))
	}
}

// Utility to serialize a struct into JSON and produce a sensible Response
// out of it.
fn _json_response<T>(s: &T) -> Response<Body>
where
	T: Serialize,
{
	match serde_json::to_string(s) {
		Ok(json) => response(StatusCode::OK, json),
		Err(_) => response(StatusCode::INTERNAL_SERVER_ERROR, ""),
	}
}

// pretty-printed version of above
fn json_response_pretty<T>(s: &T) -> Response<Body>
where
	T: Serialize,
{
	match serde_json::to_string_pretty(s) {
		Ok(json) => response(StatusCode::OK, json),
		Err(_) => response(StatusCode::INTERNAL_SERVER_ERROR, ""),
	}
}

fn create_error_response(e: Error) -> Response<Body> {
	Response::builder()
		.status(StatusCode::INTERNAL_SERVER_ERROR)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		)
		.body(format!("{}", e).into())
		.unwrap()
}

fn create_ok_response(json: &str) -> Response<Body> {
	Response::builder()
		.status(StatusCode::OK)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		)
		.header(hyper::header::CONTENT_TYPE, "application/json")
		.body(json.to_string().into())
		.unwrap()
}

/// Build a new hyper Response with the status code and body provided.
///
/// Whenever the status code is `StatusCode::OK` the text parameter should be
/// valid JSON as the content type header will be set to `application/json'
fn response<T: Into<Body>>(status: StatusCode, text: T) -> Response<Body> {
	let mut builder = &mut Response::builder();

	builder = builder
		.status(status)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		);

	if status == StatusCode::OK {
		builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");
	}

	builder.body(text.into()).unwrap()
}

fn parse_body<T>(req: Request<Body>) -> Box<dyn Future<Item = T, Error = Error> + Send>
where
	for<'de> T: Deserialize<'de> + Send + 'static,
{
	Box::new(
		req.into_body()
			.concat2()
			.map_err(|_| ErrorKind::GenericError("Failed to read request".to_owned()).into())
			.and_then(|body| match serde_json::from_reader(&body.to_vec()[..]) {
				Ok(obj) => ok(obj),
				Err(e) => {
					err(ErrorKind::GenericError(format!("Invalid request body: {}", e)).into())
				}
			}),
	)
}
