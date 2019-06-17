// Copyright 2018 The Grin Developers
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
	Error, ErrorKind, NodeClient, NodeVersionInfo, Slate, WalletBackend, CURRENT_SLATE_VERSION,
	GRIN_BLOCK_HEADER_VERSION,
};
use crate::util::to_base64;
use crate::util::Mutex;
use failure::ResultExt;
use futures::future::{err, ok};
use futures::{Future, Stream};
use hyper::header::HeaderValue;
use hyper::{Body, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::apiwallet::{Foreign, ForeignCheckMiddlewareFn, ForeignRpc, Owner, OwnerRpc};
use easy_jsonrpc;
use easy_jsonrpc::{Handler, MaybeReply};

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

/// Instantiate wallet Owner API for a single-use (command line) call
/// Return a function containing a loaded API context to call
pub fn owner_single_use<F, T: ?Sized, C, K>(wallet: Arc<Mutex<T>>, f: F) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	F: FnOnce(&mut Owner<T, C, K>) -> Result<(), Error>,
	C: NodeClient,
	K: Keychain,
{
	f(&mut Owner::new(wallet.clone()))?;
	Ok(())
}

/// Instantiate wallet Foreign API for a single-use (command line) call
/// Return a function containing a loaded API context to call
pub fn foreign_single_use<F, T: ?Sized, C, K>(wallet: Arc<Mutex<T>>, f: F) -> Result<(), Error>
where
	T: WalletBackend<C, K>,
	F: FnOnce(&mut Foreign<T, C, K>) -> Result<(), Error>,
	C: NodeClient,
	K: Keychain,
{
	f(&mut Foreign::new(wallet.clone(), Some(check_middleware)))?;
	Ok(())
}

/// Listener version, providing same API but listening for requests on a
/// port and wrapping the calls
pub fn owner_listener<T: ?Sized, C, K>(
	wallet: Arc<Mutex<T>>,
	addr: &str,
	api_secret: Option<String>,
	tls_config: Option<TLSConfig>,
	owner_api_include_foreign: Option<bool>,
) -> Result<(), Error>
where
	T: WalletBackend<C, K> + Send + Sync + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let api_handler_v2 = OwnerAPIHandlerV2::new(wallet.clone());

	let mut router = Router::new();
	if api_secret.is_some() {
		let api_basic_auth =
			"Basic ".to_string() + &to_base64(&("grin:".to_string() + &api_secret.unwrap()));
		let basic_auth_middleware = Arc::new(BasicAuthMiddleware::new(
			api_basic_auth,
			&GRIN_OWNER_BASIC_REALM,
		));
		router.add_middleware(basic_auth_middleware);
	}

	router
		.add_route("/v2/owner", Arc::new(api_handler_v2))
		.map_err(|_| ErrorKind::GenericError("Router failed to add route".to_string()))?;

	// If so configured, add the foreign API to the same port
	if owner_api_include_foreign.unwrap_or(false) {
		info!("Starting HTTP Foreign API on Owner server at {}.", addr);
		let foreign_api_handler_v2 = ForeignAPIHandlerV2::new(wallet.clone());
		router
			.add_route("/v2/foreign", Arc::new(foreign_api_handler_v2))
			.map_err(|_| ErrorKind::GenericError("Router failed to add route".to_string()))?;
	}

	let mut apis = ApiServer::new();
	info!("Starting HTTP Owner API server at {}.", addr);
	let socket_addr: SocketAddr = addr.parse().expect("unable to parse socket address");
	let api_thread =
		apis.start(socket_addr, router, tls_config)
			.context(ErrorKind::GenericError(
				"API thread failed to start".to_string(),
			))?;
	api_thread
		.join()
		.map_err(|e| ErrorKind::GenericError(format!("API thread panicked :{:?}", e)).into())
}

/// Listener version, providing same API but listening for requests on a
/// port and wrapping the calls
pub fn foreign_listener<T: ?Sized, C, K>(
	wallet: Arc<Mutex<T>>,
	addr: &str,
	tls_config: Option<TLSConfig>,
) -> Result<(), Error>
where
	T: WalletBackend<C, K> + Send + Sync + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let api_handler_v2 = ForeignAPIHandlerV2::new(wallet);

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
pub struct OwnerAPIHandlerV2<T: ?Sized, C, K>
where
	T: WalletBackend<C, K> + Send + Sync + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Wallet instance
	pub wallet: Arc<Mutex<T>>,
	phantom: PhantomData<K>,
	phantom_c: PhantomData<C>,
}

impl<T: ?Sized, C, K> OwnerAPIHandlerV2<T, C, K>
where
	T: WalletBackend<C, K> + Send + Sync + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Create a new owner API handler for GET methods
	pub fn new(wallet: Arc<Mutex<T>>) -> OwnerAPIHandlerV2<T, C, K> {
		OwnerAPIHandlerV2 {
			wallet,
			phantom: PhantomData,
			phantom_c: PhantomData,
		}
	}

	fn call_api(
		&self,
		req: Request<Body>,
		api: Owner<T, C, K>,
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

impl<T: ?Sized, C, K> api::Handler for OwnerAPIHandlerV2<T, C, K>
where
	T: WalletBackend<C, K> + Send + Sync + 'static,
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
pub struct ForeignAPIHandlerV2<T: ?Sized, C, K>
where
	T: WalletBackend<C, K> + Send + Sync + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Wallet instance
	pub wallet: Arc<Mutex<T>>,
	phantom: PhantomData<K>,
	phantom_c: PhantomData<C>,
}

impl<T: ?Sized, C, K> ForeignAPIHandlerV2<T, C, K>
where
	T: WalletBackend<C, K> + Send + Sync + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	/// Create a new foreign API handler for GET methods
	pub fn new(wallet: Arc<Mutex<T>>) -> ForeignAPIHandlerV2<T, C, K> {
		ForeignAPIHandlerV2 {
			wallet,
			phantom: PhantomData,
			phantom_c: PhantomData,
		}
	}

	fn call_api(
		&self,
		req: Request<Body>,
		api: Foreign<T, C, K>,
	) -> Box<dyn Future<Item = serde_json::Value, Error = Error> + Send> {
		Box::new(parse_body(req).and_then(move |val: serde_json::Value| {
			let foreign_api = &api as &dyn ForeignRpc;
			match foreign_api.handle_request(val) {
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
		let api = Foreign::new(self.wallet.clone(), Some(check_middleware));
		Box::new(
			self.call_api(req, api)
				.and_then(|resp| ok(json_response_pretty(&resp))),
		)
	}
}

impl<T: ?Sized, C, K> api::Handler for ForeignAPIHandlerV2<T, C, K>
where
	T: WalletBackend<C, K> + Send + Sync + 'static,
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
