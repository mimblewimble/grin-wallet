// Copyright 2021 The Grin Developers
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

//! Controller for wallet, instantiates and handles listeners (or single-run
//! invocations) as needed.
use crate::api::{self, ApiServer, BasicAuthMiddleware, ResponseFuture, Router, TLSConfig};
use crate::apiwallet::{
	ConfigPath, EncryptedRequest, EncryptedResponse, EncryptionErrorResponse, Foreign,
	ForeignCheckMiddlewareFn, ForeignRpc, Owner, OwnerRpc,
};
use crate::config::TorWalletConfig;
use crate::keychain::Keychain;
use crate::libwallet::{
	address, Error, NodeClient, NodeVersionInfo, Slate, SlatepackAddress, WalletLCProvider,
	GRIN_BLOCK_HEADER_VERSION,
};
use crate::util::secp::key::SecretKey;
use crate::util::{from_hex, static_secp_instance, to_base64, Mutex};

use grin_api::ApiBody;
use grin_p2p::tor::config::BOOTSTRAP_TIMEOUT_SECS;
use grin_p2p::tor::ov3::OnionV3Address;
use grin_p2p::tor::{onion_service_status, start_onion_service, stop_onion_service, ServiceStatus};
use grin_wallet_api::JsonId;
use grin_wallet_config::config::{
	add_global_config_listener, get_global_config, get_global_tor_config,
	remove_global_config_listener,
};
use grin_wallet_libwallet::slatepack::SlatepackAddressIndex;

use easy_jsonrpc_mw;
use easy_jsonrpc_mw::{Handler, MaybeReply};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::{Request, Response, StatusCode};
use qr_code::QrCode;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::io::Cursor;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

lazy_static! {
	pub static ref GRIN_OWNER_BASIC_REALM: HeaderValue =
		HeaderValue::from_str("Basic realm=GrinOwnerAPI").unwrap();
}

fn check_middleware(
	name: ForeignCheckMiddlewareFn,
	_node_version_info: Option<NodeVersionInfo>,
	slate: Option<&Slate>,
) -> Result<(), Error> {
	match name {
		// allow coinbases to be built regardless
		ForeignCheckMiddlewareFn::BuildCoinbase => Ok(()),
		_ => {
			if let Some(s) = slate {
				if s.version_info.block_header_version > GRIN_BLOCK_HEADER_VERSION {
					Err(Error::Compatibility(
						"Incoming Slate is not compatible with this wallet. \
						 Please upgrade the wallet."
							.into(),
					))?;
				}
			}
			Ok(())
		}
	}
}

/// Instantiate wallet Foreign API for a single-use (command line) call
/// Return a function containing a loaded API context to call
pub fn foreign_single_use<'a, L, F, C, K>(
	wallet: grin_wallet_libwallet::WalletHandle<'a, L, C, K>,
	config_path: PathBuf,
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
		config_path,
		keychain_mask,
		Some(check_middleware),
		false,
	))?;
	Ok(())
}

/// Listener version, providing same API but listening for requests on a
/// port and wrapping the calls
/// Note keychain mask is only provided here in case the foreign listener is also being used
/// in the same wallet instance
pub fn owner_listener<L, C, K>(
	owner_api: &mut Owner<L, C, K>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	addr: &str,
	api_secret: Option<String>,
	tls_config: Option<TLSConfig>,
	owner_api_include_foreign: Option<bool>,
	test_mode: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let mut router = Router::new();
	if let Some(api_secret) = api_secret {
		let api_basic_auth =
			"Basic ".to_string() + &to_base64(&("grin:".to_string() + &api_secret));
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

	let wallet = owner_api.wallet_inst.clone();
	let api_handler_v3 = OwnerAPIHandlerV3::new(owner_api, keychain_mask.clone(), running_foreign);

	router
		.add_route("/v3/owner", Arc::new(api_handler_v3))
		.map_err(|_| Error::GenericError("Router failed to add route".to_string()))?;

	// If so configured, add the foreign API to the same port
	if running_foreign {
		warn!("Starting HTTP Foreign API on Owner server at {}.", addr);
		let foreign_api_handler_v2 = ForeignAPIHandlerV2::new(
			wallet,
			owner_api.shared_config_path(),
			keychain_mask,
			test_mode,
		);
		router
			.add_route("/v2/foreign", Arc::new(foreign_api_handler_v2))
			.map_err(|_| Error::GenericError("Router failed to add route".to_string()))?;
	}

	let api_chan: (mpsc::Sender<()>, mpsc::Receiver<()>) = mpsc::channel::<()>(1);
	let stop_tx = api_chan.0.clone();

	let mut apis = ApiServer::new();
	warn!("Starting HTTP Owner API server at {}.", addr);
	let socket_addr: SocketAddr = addr.parse().expect("unable to parse socket address");
	let api_thread = apis
		.start(socket_addr, router, tls_config, api_chan)
		.map_err(|_| Error::GenericError("API thread failed to start".to_string()))?;
	warn!("HTTP Owner listener started.");
	let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
	let shutdown = api_shutdown(stop_tx, None, finished_rx, None);
	let res = api_thread
		.join()
		.map_err(|e| Error::GenericError(format!("API thread panicked :{:?}", e)));
	let _ = finished_tx.send(());
	let shutdown = shutdown
		.join()
		.map_err(|_| Error::GenericError("API shutdown thread panicked".into()))?;
	res.and(shutdown.map(|_| ()))
}

/// Listener version, providing same API but listening for requests on a
/// port and wrapping the calls
#[allow(clippy::too_many_arguments)]
pub fn foreign_listener<L, C, K>(
	wallet: grin_wallet_libwallet::WalletHandle<'static, L, C, K>,
	config_path: PathBuf,
	bridge: Option<String>,
	use_tor: Option<bool>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	addr: &str,
	tls_config: Option<TLSConfig>,
	test_mode: bool,
	stop_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	loop {
		if *stop_rx.borrow() {
			return Ok(());
		}
		let (restart_tx, restart_rx) = std::sync::mpsc::channel::<()>();

		// Check if wallet has been opened first
		let (sec_key, onion_address) = {
			let mask = keychain_mask.lock();
			let mut w_lock = wallet.lock();
			let lc = w_lock.lc_provider()?;
			let w_inst = lc.wallet_inst()?;
			let k = w_inst.keychain(mask.as_ref())?;
			let parent_key_id = w_inst.parent_key_id();
			let sec_key =
				address::address_from_derivation_path(&k, &parent_key_id, SlatepackAddressIndex(0))
					.map_err(|e| Error::TorConfig(format!("{:?}", e)))?;
			let onion_address = OnionV3Address::from_private(&sec_key.0)
				.map_err(|e| Error::TorConfig(format!("{:?}", e)))?;
			(sec_key, onion_address)
		};

		let sp_address = SlatepackAddress::try_from(onion_address.clone())?;

		let api_handler_v2 = ForeignAPIHandlerV2::new(
			wallet.clone(),
			config_path.clone().into(),
			keychain_mask.clone(),
			test_mode,
		);
		let mut router = Router::new();

		router
			.add_route("/v2/foreign", Arc::new(api_handler_v2))
			.map_err(|_| Error::GenericError("Router failed to add route".to_string()))?;

		let api_chan: (mpsc::Sender<()>, mpsc::Receiver<()>) = mpsc::channel::<()>(1);
		let stop_tx = api_chan.0.clone();

		let mut apis = ApiServer::new();
		warn!("Starting HTTP Foreign listener API server at {}.", addr);
		let socket_addr: SocketAddr = addr
			.parse()
			.map_err(|_| Error::GenericError("Invalid listener address".into()))?;
		register_config_listener(&config_path, "foreign_listener", restart_tx)?;
		let tor_config =
			listener_tor_config(&config_path, bridge.clone(), use_tor).inspect_err(|_| {
				remove_global_config_listener(&config_path, "foreign_listener");
			})?;
		let api_thread = apis
			.start(socket_addr, router, tls_config.clone(), api_chan)
			.map_err(|_| {
				remove_global_config_listener(&config_path, "foreign_listener");
				Error::GenericError("API thread failed to start".to_string())
			})?;
		warn!("HTTP Foreign listener started.");
		let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
		let shutdown = api_shutdown(
			stop_tx,
			Some(restart_rx),
			finished_rx,
			Some(stop_rx.clone()),
		);

		let deadline = Instant::now()
			+ Duration::from_secs(
				tor_config
					.bootstrap_timeout_secs
					.filter(|secs| *secs > 0)
					.unwrap_or(BOOTSTRAP_TIMEOUT_SECS),
			);
		let tor_started = if tor_config.use_tor_listener {
			match start_onion_service(sec_key, addr, &tor_config) {
				Ok(_) => {
					warn!(
						"Starting Tor Hidden Service for API listener at address {}, binding to {}",
						onion_address, addr
					);
					true
				}
				Err(e) => {
					warn!("Unable to start TOR listener");
					error!("Tor Error: {}", e);
					warn!("Listener is available on {}", addr);
					false
				}
			}
		} else {
			warn!("Listener is available on {}", addr);
			false
		};

		let startup = if tor_started {
			loop {
				if shutdown.is_finished() {
					break Ok(());
				}
				match listener_ready(onion_service_status(onion_address.to_string()), deadline) {
					Ok(false) => thread::sleep(
						deadline
							.saturating_duration_since(Instant::now())
							.min(Duration::from_millis(500)),
					),
					Ok(true) => {
						let qr_string = match QrCode::new(sp_address.to_string()) {
							Ok(qr) => qr.to_string(false, 3),
							Err(_) => "Failed to generate QR code!".to_string(),
						};
						warn!("Slatepack Address is: {}\n{}", sp_address, qr_string);
						break Ok(());
					}
					Err(e) => {
						warn!("Unable to start TOR listener");
						error!("Tor Error: {}", e);
						break Err(e);
					}
				}
			}
		} else {
			Ok(())
		};
		let mut retry_at = None;
		let retry = loop {
			if !tor_started
				|| startup.is_err()
				|| shutdown.is_finished()
				|| api_thread.is_finished()
			{
				break false;
			}
			if listener_retry(
				onion_service_status(onion_address.to_string()),
				&mut retry_at,
				Instant::now(),
			) {
				warn!("Restarting Tor listener");
				break true;
			}
			thread::sleep(Duration::from_millis(500));
		};
		if startup.is_err() || retry {
			apis.stop();
		}

		let res = api_thread
			.join()
			.map_err(|e| Error::GenericError(format!("API thread panicked :{:?}", e)));
		let _ = finished_tx.send(());
		let restart = shutdown
			.join()
			.map_err(|_| Error::GenericError("API shutdown thread panicked".into()));
		remove_global_config_listener(&config_path, "foreign_listener");
		let stopped = if tor_started {
			stop_onion_service(onion_address.to_string()).map_err(Error::from)
		} else {
			Ok(())
		};
		if let Err(ref e) = stopped {
			error!("Unable to stop Tor listener: {}", e);
		}
		res?;
		stopped?;
		if restart?? || retry {
			continue;
		}
		startup?;
		return Ok(());
	}
}

fn listener_ready(status: ServiceStatus, deadline: Instant) -> Result<bool, Error> {
	if Instant::now() >= deadline {
		return Err(Error::GenericError("Tor listener startup timed out".into()));
	}
	match status {
		ServiceStatus::Running | ServiceStatus::Bootstrapped | ServiceStatus::Degraded => Ok(true),
		ServiceStatus::Errored(e) => Err(Error::from(e)),
		_ => Ok(false),
	}
}

fn listener_retry(status: ServiceStatus, retry_at: &mut Option<Instant>, now: Instant) -> bool {
	match status {
		ServiceStatus::Errored(_) | ServiceStatus::Stopped => {
			now >= *retry_at.get_or_insert(now + Duration::from_secs(10))
		}
		_ => {
			*retry_at = None;
			false
		}
	}
}

fn api_shutdown(
	stop_tx: mpsc::Sender<()>,
	restart_rx: Option<std::sync::mpsc::Receiver<()>>,
	finished_rx: tokio::sync::oneshot::Receiver<()>,
	stop_rx: Option<tokio::sync::watch::Receiver<bool>>,
) -> thread::JoinHandle<Result<bool, Error>> {
	thread::spawn(move || {
		let res = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.map_err(|e| Error::GenericError(format!("API shutdown runtime failed: {}", e)))
			.map(|runtime| {
				runtime.block_on(async {
					tokio::select! {
						biased;
						_ = async {
							match stop_rx {
								Some(mut rx) => {
									let _ = rx.wait_for(|stop| *stop).await;
								}
								None => std::future::pending::<()>().await,
							}
						} => false,
						_ = async {
							if let Err(e) = tokio::signal::ctrl_c().await {
								warn!("Unable to handle Ctrl+C: {}", e);
								std::future::pending::<()>().await;
							}
						} => false,
						restart = async {
							match restart_rx.as_ref() {
								Some(rx) => loop {
									match rx.try_recv() {
										Ok(()) => break true,
										Err(std::sync::mpsc::TryRecvError::Disconnected) => break false,
										Err(std::sync::mpsc::TryRecvError::Empty) => {}
									}
									tokio::time::sleep(Duration::from_millis(500)).await;
								},
								None => std::future::pending::<bool>().await,
							}
						} => restart,
						_ = finished_rx => restart_rx.as_ref().is_some_and(|rx| rx.try_recv().is_ok()),
					}
				})
			});
		let _ = stop_tx.try_send(());
		res
	})
}

fn register_config_listener(
	config_path: &PathBuf,
	listener_id: &str,
	tx: std::sync::mpsc::Sender<()>,
) -> Result<(), Error> {
	get_global_config(config_path)?;
	add_global_config_listener(config_path, listener_id, tx);
	Ok(())
}

fn listener_tor_config(
	config_path: &Path,
	bridge: Option<String>,
	use_tor: Option<bool>,
) -> Result<TorWalletConfig, Error> {
	let mut tor_config = get_global_tor_config(config_path)?;
	if let Some(bridge) = bridge {
		tor_config.set_bridge(bridge);
	}
	if let Some(use_tor) = use_tor {
		tor_config.use_tor_listener = use_tor;
	}
	Ok(tor_config)
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
	pub wallet: grin_wallet_libwallet::WalletHandle<'static, L, C, K>,

	/// Handle to Owner API
	owner_api: Arc<Owner<L, C, K>>,

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
		matches!(val["method"].as_str(), Some("init_secure_api"))
	}

	/// Checks whether a request is to open the wallet
	pub fn is_open_wallet(val: &serde_json::Value) -> bool {
		matches!(val["method"].as_str(), Some("open_wallet"))
	}

	/// Checks whether a request is an encrypted request
	pub fn is_encrypted_request(val: &serde_json::Value) -> bool {
		matches!(val["method"].as_str(), Some("encrypted_request_v3"))
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
		if val["result"]["Ok"].as_str().is_some() {
			let mut share_key_ref = key.lock();
			*share_key_ref = new_key;
		}
	}

	/// Update the shared mask, in case of foreign API being run
	pub fn update_mask(mask: Arc<Mutex<Option<SecretKey>>>, val: &serde_json::Value) {
		if let Some(key) = val["result"]["Ok"].as_str() {
			let key_bytes = match from_hex(key) {
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
	) -> Result<(JsonId, serde_json::Value), serde_json::Value> {
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
		let id = enc_req.id.clone();
		let res = enc_req.decrypt(shared_key).map_err(|e| {
			EncryptionErrorResponse::new(1, -32002, &format!("Decryption error: {}", e))
				.as_json_value()
		})?;
		Ok((id, res))
	}

	/// Encrypt a response
	pub fn encrypt_response(
		key: Arc<Mutex<Option<SecretKey>>>,
		id: &JsonId,
		res: &serde_json::Value,
	) -> Result<serde_json::Value, serde_json::Value> {
		let share_key_ref = key.lock();
		let shared_key = share_key_ref.as_ref().unwrap();
		let enc_res = EncryptedResponse::from_json(id, res, shared_key).map_err(|e| {
			EncryptionErrorResponse::new(1, -32003, &format!("EncryptionError: {}", e))
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
			parsed.ok()
		} else {
			None
		};
		match err_string {
			Some(s) => (
				true,
				serde_json::json!({
					"jsonrpc": "2.0",
					"id": val["id"],
					"error": {
						"message": s,
						"code": -32099
					}
				}),
			),
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
		owner_api: &Owner<L, C, K>,
		keychain_mask: Arc<Mutex<Option<SecretKey>>>,
		running_foreign: bool,
	) -> OwnerAPIHandlerV3<L, C, K> {
		let wallet = owner_api.wallet_inst.clone();
		let config_path = owner_api.shared_config_path();
		let owner_api = Owner::new(wallet.clone(), None, config_path);
		OwnerAPIHandlerV3 {
			wallet,
			owner_api: Arc::new(owner_api),
			shared_key: Arc::new(Mutex::new(None)),
			keychain_mask,
			running_foreign,
		}
	}

	async fn call_api(
		req: Request<Incoming>,
		key: Arc<Mutex<Option<SecretKey>>>,
		mask: Arc<Mutex<Option<SecretKey>>>,
		running_foreign: bool,
		api: Arc<Owner<L, C, K>>,
	) -> Result<serde_json::Value, Error> {
		let mut val: serde_json::Value = parse_body(req).await?;
		let mut is_init_secure_api = OwnerV3Helpers::is_init_secure_api(&val);
		let mut was_encrypted = false;
		let mut encrypted_req_id = JsonId::StrId(String::from(""));
		if !is_init_secure_api {
			if let Err(v) = OwnerV3Helpers::check_encryption_started(key.clone()) {
				return Ok(v);
			}
			let res = OwnerV3Helpers::decrypt_request(key.clone(), &val);
			match res {
				Err(e) => return Ok(e),
				Ok(v) => {
					encrypted_req_id = v.0.clone();
					val = v.1;
				}
			}
			was_encrypted = true;
		}
		// check again, in case it was an encrypted call to init_secure_api
		is_init_secure_api = OwnerV3Helpers::is_init_secure_api(&val);
		// also need to intercept open/close wallet requests
		let is_open_wallet = OwnerV3Helpers::is_open_wallet(&val);
		let rpc_api = api.clone();
		let reply =
			tokio::task::spawn_blocking(move || <dyn OwnerRpc>::handle_request(&*rpc_api, val))
				.await
				.map_err(|e| Error::GenericError(format!("Owner API task failed: {}", e)))?;
		match reply {
			MaybeReply::Reply(mut r) => {
				let (_was_error, unencrypted_intercept) =
					OwnerV3Helpers::check_error_response(&r.clone());
				if is_open_wallet && running_foreign {
					OwnerV3Helpers::update_mask(mask, &r.clone());
				}
				if was_encrypted {
					let res = OwnerV3Helpers::encrypt_response(
						key.clone(),
						&encrypted_req_id,
						&unencrypted_intercept,
					);
					r = match res {
						Ok(v) => v,
						Err(v) => return Ok(v),
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
				Ok(r)
			}
			MaybeReply::DontReply => {
				// Since it's http, we need to return something. We return [] because jsonrpc
				// clients will parse it as an empty batch response.
				Ok(serde_json::json!([]))
			}
		}
	}

	async fn handle_post_request(
		req: Request<Incoming>,
		key: Arc<Mutex<Option<SecretKey>>>,
		mask: Arc<Mutex<Option<SecretKey>>>,
		running_foreign: bool,
		api: Arc<Owner<L, C, K>>,
	) -> Result<Response<ApiBody>, Error> {
		let res = Self::call_api(req, key, mask, running_foreign, api).await?;
		Ok(json_response_pretty(&res))
	}
}

impl<L, C, K> api::Handler for OwnerAPIHandlerV3<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn post(&self, req: Request<Incoming>) -> ResponseFuture {
		let key = self.shared_key.clone();
		let mask = self.keychain_mask.clone();
		let running_foreign = self.running_foreign;
		let api = self.owner_api.clone();

		Box::pin(async move {
			match Self::handle_post_request(req, key, mask, running_foreign, api).await {
				Ok(r) => Ok(r),
				Err(e) => {
					error!("Request Error: {:?}", e);
					Ok(create_error_response(e))
				}
			}
		})
	}

	fn options(&self, _req: Request<Incoming>) -> ResponseFuture {
		Box::pin(async { Ok(create_ok_response("{}")) })
	}
}
/// V2 API Handler/Wrapper for foreign functions
pub struct ForeignAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Wallet instance.
	pub wallet: grin_wallet_libwallet::WalletHandle<'static, L, C, K>,
	/// Wallet configuration path.
	pub config_path: ConfigPath,
	/// Keychain mask
	pub keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	/// run in doctest mode
	pub test_mode: bool,
}

impl<L, C, K> ForeignAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Create a new foreign API handler for GET methods
	pub fn new(
		wallet: grin_wallet_libwallet::WalletHandle<'static, L, C, K>,
		config_path: ConfigPath,
		keychain_mask: Arc<Mutex<Option<SecretKey>>>,
		test_mode: bool,
	) -> ForeignAPIHandlerV2<L, C, K> {
		ForeignAPIHandlerV2 {
			wallet,
			config_path,
			keychain_mask,
			test_mode,
		}
	}

	async fn call_api(
		req: Request<Incoming>,
		api: Foreign<'static, L, C, K>,
	) -> Result<serde_json::Value, Error> {
		let val: serde_json::Value = parse_body(req).await?;
		let reply =
			tokio::task::spawn_blocking(move || <dyn ForeignRpc>::handle_request(&api, val))
				.await
				.map_err(|e| Error::GenericError(format!("Foreign API task failed: {}", e)))?;
		match reply {
			MaybeReply::Reply(r) => Ok(r),
			MaybeReply::DontReply => {
				// Since it's http, we need to return something. We return [] because jsonrpc
				// clients will parse it as an empty batch response.
				Ok(serde_json::json!([]))
			}
		}
	}

	async fn handle_post_request(
		req: Request<Incoming>,
		mask: Option<SecretKey>,
		wallet: grin_wallet_libwallet::WalletHandle<'static, L, C, K>,
		config_path: ConfigPath,
		test_mode: bool,
	) -> Result<Response<ApiBody>, Error> {
		let api = Foreign::new(wallet, config_path, mask, Some(check_middleware), test_mode);
		let res = Self::call_api(req, api).await?;
		Ok(json_response_pretty(&res))
	}
}

impl<L, C, K> api::Handler for ForeignAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn post(&self, req: Request<Incoming>) -> ResponseFuture {
		let mask = self.keychain_mask.lock().clone();
		let wallet = self.wallet.clone();
		let test_mode = self.test_mode;
		let config_path = self.config_path.clone();

		Box::pin(async move {
			match Self::handle_post_request(req, mask, wallet, config_path, test_mode).await {
				Ok(v) => Ok(v),
				Err(e) => {
					error!("Request Error: {:?}", e);
					Ok(create_error_response(e))
				}
			}
		})
	}

	fn options(&self, _req: Request<Incoming>) -> ResponseFuture {
		Box::pin(async { Ok(create_ok_response("{}")) })
	}
}

/// Utility to serialize a struct into JSON and produce a sensible Response
/// out of it.
fn json_response_pretty<T>(s: &T) -> Response<ApiBody>
where
	T: Serialize,
{
	match serde_json::to_string_pretty(s) {
		Ok(json) => response(StatusCode::OK, Full::from(json).boxed()),
		Err(_) => response(StatusCode::INTERNAL_SERVER_ERROR, Full::from("").boxed()),
	}
}

fn create_error_response(e: Error) -> Response<ApiBody> {
	Response::builder()
		.status(StatusCode::INTERNAL_SERVER_ERROR)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		)
		.body(Full::from(format!("{}", e)).boxed())
		.unwrap()
}

fn create_ok_response(json: &str) -> Response<ApiBody> {
	Response::builder()
		.status(StatusCode::OK)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		)
		.header(hyper::header::CONTENT_TYPE, "application/json")
		.body(Full::from(json.to_string()).boxed())
		.unwrap()
}

/// Build a new hyper Response with the status code and body provided.
///
/// Whenever the status code is `StatusCode::OK` the text parameter should be
/// valid JSON as the content type header will be set to `application/json'
fn response<T: Into<ApiBody>>(status: StatusCode, text: T) -> Response<ApiBody> {
	let mut builder = Response::builder()
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

async fn parse_body<T>(req: Request<Incoming>) -> Result<T, Error>
where
	for<'de> T: Deserialize<'de> + Send + 'static,
{
	let body_req = req
		.into_body()
		.collect()
		.await
		.map_err(|e| Error::GenericError(format!("Failed to read request: {}", e)))?;
	let raw = body_req.to_bytes();

	let cursor = Cursor::new(raw);
	serde_json::from_reader(cursor)
		.map_err(|e| Error::GenericError(format!("Invalid request body: {}", e)))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::core::global::ChainTypes;
	use grin_wallet_config::config::update_global_config;
	use grin_wallet_config::GlobalWalletConfig;
	use std::fs;
	use std::sync::mpsc::channel;
	use std::time::Duration;
	use uuid::Uuid;

	#[test]
	fn listener_ready() {
		let deadline = Instant::now() + Duration::from_secs(60);
		assert!(!super::listener_ready(ServiceStatus::Stopped, deadline).unwrap());
		assert!(super::listener_ready(ServiceStatus::Running, deadline).unwrap());
		assert!(super::listener_ready(ServiceStatus::Degraded, deadline).unwrap());
		assert!(super::listener_ready(ServiceStatus::Recovering, Instant::now()).is_err());
	}

	#[test]
	fn retry_delay() {
		use ServiceStatus::*;
		let mut now = Instant::now();
		let mut retry_at = None;
		let failed = || Errored(grin_p2p::tor::Error::Generic("stopped".into()));
		assert!(!listener_retry(failed(), &mut retry_at, now));
		now += Duration::from_secs(9);
		assert!(!listener_retry(failed(), &mut retry_at, now));
		now += Duration::from_secs(1);
		assert!(listener_retry(failed(), &mut retry_at, now));
		assert!(!listener_retry(Running, &mut retry_at, now));
		assert!(retry_at.is_none());
		assert!(!listener_retry(Stopped, &mut retry_at, now));
		assert!(!listener_retry(Recovering, &mut retry_at, now));
		assert!(retry_at.is_none());
	}

	#[test]
	fn api_stop() {
		let (stop_tx, mut stop_rx) = mpsc::channel(1);
		let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
		let shutdown = api_shutdown(stop_tx, None, finished_rx, None);
		finished_tx.send(()).unwrap();
		assert!(!shutdown.join().unwrap().unwrap());
		assert_eq!(stop_rx.try_recv(), Ok(()));

		let (stop_tx, mut stop_rx) = mpsc::channel(1);
		let (_finished_tx, finished_rx) = tokio::sync::oneshot::channel();
		let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
		cancel_tx.send(true).unwrap();
		let (restart_tx, restart_rx) = channel();
		restart_tx.send(()).unwrap();
		let shutdown = api_shutdown(stop_tx, Some(restart_rx), finished_rx, Some(cancel_rx));
		assert!(!shutdown.join().unwrap().unwrap());
		assert_eq!(stop_rx.try_recv(), Ok(()));
	}

	#[test]
	fn listener_reload() {
		let dir = std::env::temp_dir().join(format!("grin-wallet-listener-{}", Uuid::new_v4()));
		fs::create_dir(&dir).unwrap();
		let path = dir.join("grin-wallet.toml");
		let mut config = GlobalWalletConfig::for_chain(&ChainTypes::AutomatedTesting, &path);
		config
			.write_to_file(path.to_str().unwrap(), false, None, None)
			.unwrap();

		let (restart_tx, restart_rx) = channel();
		register_config_listener(&path, "test_listener", restart_tx).unwrap();

		let (stop_tx, mut stop_rx) = mpsc::channel(1);
		let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();

		update_global_config(&path, |config| {
			config.members.tor.as_mut().unwrap().socks_proxy_addr = "127.0.0.1:59051".into();
			Ok(())
		})
		.unwrap();
		finished_tx.send(()).unwrap();
		let shutdown = api_shutdown(stop_tx, Some(restart_rx), finished_rx, None);
		assert!(shutdown.join().unwrap().unwrap());
		assert_eq!(stop_rx.try_recv(), Ok(()));

		let tor_config =
			listener_tor_config(&path, Some("obfs4 test-bridge".into()), Some(false)).unwrap();
		assert_eq!(tor_config.socks_proxy_addr, "127.0.0.1:59051");
		assert_eq!(
			tor_config.bridges[0].bridge_line.as_deref(),
			Some("obfs4 test-bridge")
		);
		assert!(!tor_config.use_tor_listener);

		remove_global_config_listener(&path, "test_listener");
		fs::remove_dir_all(dir).unwrap();
	}
}
