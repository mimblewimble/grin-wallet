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

//! High level JSON/HTTP client API

use crate::client_utils::Socksv5Connector;
use crate::util::to_base64;
use failure::{Backtrace, Context, Fail, ResultExt};
use futures::future::result;
use futures::future::{err, ok, Either};
use futures::stream::Stream;
use http::uri::{InvalidUri, Uri};
use hyper::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use hyper::rt::Future;
use hyper::{self, Body, Request};
use hyper_rustls;
use hyper_timeout::TimeoutConnector;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fmt::{self, Display};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::runtime::Runtime;

/// Errors that can be returned by an ApiEndpoint implementation.
#[derive(Debug)]
pub struct Error {
	inner: Context<ErrorKind>,
}

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
	#[fail(display = "Internal error: {}", _0)]
	Internal(String),
	#[fail(display = "Bad arguments: {}", _0)]
	Argument(String),
	#[fail(display = "Not found.")]
	_NotFound,
	#[fail(display = "Request error: {}", _0)]
	RequestError(String),
	#[fail(display = "ResponseError error: {}", _0)]
	ResponseError(String),
}

impl Fail for Error {
	fn cause(&self) -> Option<&dyn Fail> {
		self.inner.cause()
	}

	fn backtrace(&self) -> Option<&Backtrace> {
		self.inner.backtrace()
	}
}

impl Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		Display::fmt(&self.inner, f)
	}
}

impl Error {
	pub fn _kind(&self) -> &ErrorKind {
		self.inner.get_context()
	}
}

impl From<ErrorKind> for Error {
	fn from(kind: ErrorKind) -> Error {
		Error {
			inner: Context::new(kind),
		}
	}
}

impl From<Context<ErrorKind>> for Error {
	fn from(inner: Context<ErrorKind>) -> Error {
		Error { inner: inner }
	}
}

pub type ClientResponseFuture<T> = Box<dyn Future<Item = T, Error = Error> + Send>;

pub struct Client {
	/// Whether to use socks proxy
	pub use_socks: bool,
	/// Proxy url/port
	pub socks_proxy_addr: Option<SocketAddr>,
}

impl Client {
	/// New client
	pub fn new() -> Self {
		Client {
			use_socks: false,
			socks_proxy_addr: None,
		}
	}

	/// Helper function to easily issue a HTTP GET request against a given URL that
	/// returns a JSON object. Handles request building, JSON deserialization and
	/// response code checking.
	pub fn get<'a, T>(&self, url: &'a str, api_secret: Option<String>) -> Result<T, Error>
	where
		for<'de> T: Deserialize<'de>,
	{
		self.handle_request(self.build_request(url, "GET", api_secret, None)?)
	}

	/// Helper function to easily issue an async HTTP GET request against a given
	/// URL that returns a future. Handles request building, JSON deserialization
	/// and response code checking.
	pub fn get_async<'a, T>(
		&self,
		url: &'a str,
		api_secret: Option<String>,
	) -> ClientResponseFuture<T>
	where
		for<'de> T: Deserialize<'de> + Send + 'static,
	{
		match self.build_request(url, "GET", api_secret, None) {
			Ok(req) => Box::new(self.handle_request_async(req)),
			Err(e) => Box::new(err(e)),
		}
	}

	/// Helper function to easily issue a HTTP GET request
	/// on a given URL that returns nothing. Handles request
	/// building and response code checking.
	pub fn _get_no_ret(&self, url: &str, api_secret: Option<String>) -> Result<(), Error> {
		let req = self.build_request(url, "GET", api_secret, None)?;
		self.send_request(req)?;
		Ok(())
	}

	/// Helper function to easily issue a HTTP POST request with the provided JSON
	/// object as body on a given URL that returns a JSON object. Handles request
	/// building, JSON serialization and deserialization, and response code
	/// checking.
	pub fn _post<IN, OUT>(
		&self,
		url: &str,
		api_secret: Option<String>,
		input: &IN,
	) -> Result<OUT, Error>
	where
		IN: Serialize,
		for<'de> OUT: Deserialize<'de>,
	{
		let req = self.create_post_request(url, api_secret, input)?;
		self.handle_request(req)
	}

	/// Helper function to easily issue an async HTTP POST request with the
	/// provided JSON object as body on a given URL that returns a future. Handles
	/// request building, JSON serialization and deserialization, and response code
	/// checking.
	pub fn _post_async<IN, OUT>(
		&self,
		url: &str,
		input: &IN,
		api_secret: Option<String>,
	) -> ClientResponseFuture<OUT>
	where
		IN: Serialize,
		OUT: Send + 'static,
		for<'de> OUT: Deserialize<'de>,
	{
		match self.create_post_request(url, api_secret, input) {
			Ok(req) => Box::new(self.handle_request_async(req)),
			Err(e) => Box::new(err(e)),
		}
	}

	/// Helper function to easily issue a HTTP POST request with the provided JSON
	/// object as body on a given URL that returns nothing. Handles request
	/// building, JSON serialization, and response code
	/// checking.
	pub fn post_no_ret<IN>(
		&self,
		url: &str,
		api_secret: Option<String>,
		input: &IN,
	) -> Result<(), Error>
	where
		IN: Serialize,
	{
		let req = self.create_post_request(url, api_secret, input)?;
		self.send_request(req)?;
		Ok(())
	}

	/// Helper function to easily issue an async HTTP POST request with the
	/// provided JSON object as body on a given URL that returns a future. Handles
	/// request building, JSON serialization and deserialization, and response code
	/// checking.
	pub fn _post_no_ret_async<IN>(
		&self,
		url: &str,
		api_secret: Option<String>,
		input: &IN,
	) -> ClientResponseFuture<()>
	where
		IN: Serialize,
	{
		match self.create_post_request(url, api_secret, input) {
			Ok(req) => Box::new(self.send_request_async(req).and_then(|_| ok(()))),
			Err(e) => Box::new(err(e)),
		}
	}

	fn build_request(
		&self,
		url: &str,
		method: &str,
		api_secret: Option<String>,
		body: Option<String>,
	) -> Result<Request<Body>, Error> {
		let uri = url.parse::<Uri>().map_err::<Error, _>(|e: InvalidUri| {
			e.context(ErrorKind::Argument(format!("Invalid url {}", url)))
				.into()
		})?;
		let mut builder = Request::builder();
		if let Some(api_secret) = api_secret {
			let basic_auth = format!("Basic {}", to_base64(&format!("grin:{}", api_secret)));
			builder.header(AUTHORIZATION, basic_auth);
		}

		builder
			.method(method)
			.uri(uri)
			.header(USER_AGENT, "grin-client")
			.header(ACCEPT, "application/json")
			.header(CONTENT_TYPE, "application/json")
			.body(match body {
				None => Body::empty(),
				Some(json) => json.into(),
			})
			.map_err(|e| {
				ErrorKind::RequestError(format!("Bad request {} {}: {}", method, url, e)).into()
			})
	}

	pub fn create_post_request<IN>(
		&self,
		url: &str,
		api_secret: Option<String>,
		input: &IN,
	) -> Result<Request<Body>, Error>
	where
		IN: Serialize,
	{
		let json = serde_json::to_string(input).context(ErrorKind::Internal(
			"Could not serialize data to JSON".to_owned(),
		))?;
		self.build_request(url, "POST", api_secret, Some(json))
	}

	fn handle_request<T>(&self, req: Request<Body>) -> Result<T, Error>
	where
		for<'de> T: Deserialize<'de>,
	{
		let data = self.send_request(req)?;
		serde_json::from_str(&data).map_err(|e| {
			e.context(ErrorKind::ResponseError("Cannot parse response".to_owned()))
				.into()
		})
	}

	fn handle_request_async<T>(&self, req: Request<Body>) -> ClientResponseFuture<T>
	where
		for<'de> T: Deserialize<'de> + Send + 'static,
	{
		Box::new(self.send_request_async(req).and_then(|data| {
			serde_json::from_str(&data).map_err(|e| {
				e.context(ErrorKind::ResponseError("Cannot parse response".to_owned()))
					.into()
			})
		}))
	}

	fn send_request_async(
		&self,
		req: Request<Body>,
	) -> Box<dyn Future<Item = String, Error = Error> + Send> {
		//TODO: redundant code, enjoy figuring out type params for dynamic dispatch of client
		match self.use_socks {
			false => {
				let https = hyper_rustls::HttpsConnector::new(1);
				let mut connector = TimeoutConnector::new(https);
				connector.set_connect_timeout(Some(Duration::from_secs(20)));
				connector.set_read_timeout(Some(Duration::from_secs(20)));
				connector.set_write_timeout(Some(Duration::from_secs(20)));
				let client = hyper::Client::builder().build::<_, hyper::Body>(connector);
				Box::new(
					client
						.request(req)
						.map_err(|e| {
							ErrorKind::RequestError(format!("Cannot make request: {}", e)).into()
						})
						.and_then(|resp| {
							if !resp.status().is_success() {
								Either::A(err(ErrorKind::RequestError(format!(
									"Wrong response code: {} with data {:?}",
									resp.status(),
									resp.body()
								))
								.into()))
							} else {
								Either::B(
									resp.into_body()
										.map_err(|e| {
											ErrorKind::RequestError(format!(
												"Cannot read response body: {}",
												e
											))
											.into()
										})
										.concat2()
										.and_then(|ch| {
											ok(String::from_utf8_lossy(&ch.to_vec()).to_string())
										}),
								)
							}
						}),
				)
			}
			true => {
				let addr = match self.socks_proxy_addr {
					Some(a) => a,
					None => {
						return Box::new(result(Err(ErrorKind::RequestError(format!(
							"Can't parse Socks proxy address"
						))
						.into())))
					}
				};
				let socks_connector = Socksv5Connector::new(addr);
				let mut connector = TimeoutConnector::new(socks_connector);
				connector.set_connect_timeout(Some(Duration::from_secs(20)));
				connector.set_read_timeout(Some(Duration::from_secs(20)));
				connector.set_write_timeout(Some(Duration::from_secs(20)));
				let client = hyper::Client::builder().build::<_, hyper::Body>(connector);
				Box::new(
					client
						.request(req)
						.map_err(|e| {
							ErrorKind::RequestError(format!("Cannot make request: {}", e)).into()
						})
						.and_then(|resp| {
							if !resp.status().is_success() {
								Either::A(err(ErrorKind::RequestError(format!(
									"Wrong response code: {} with data {:?}",
									resp.status(),
									resp.body()
								))
								.into()))
							} else {
								Either::B(
									resp.into_body()
										.map_err(|e| {
											ErrorKind::RequestError(format!(
												"Cannot read response body: {}",
												e
											))
											.into()
										})
										.concat2()
										.and_then(|ch| {
											ok(String::from_utf8_lossy(&ch.to_vec()).to_string())
										}),
								)
							}
						}),
				)
			}
		}
	}

	pub fn send_request(&self, req: Request<Body>) -> Result<String, Error> {
		let task = self.send_request_async(req);
		let mut rt =
			Runtime::new().context(ErrorKind::Internal("can't create Tokio runtime".to_owned()))?;
		Ok(rt.block_on(task)?)
	}
}
