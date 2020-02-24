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

use crate::util::to_base64;
use crossbeam_utils::thread::scope;
use failure::{Backtrace, Context, Fail, ResultExt};
use hyper::body;
use hyper::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use hyper::{self, Body, Client as HyperClient, Request, Uri};
use hyper_rustls;
use hyper_timeout::TimeoutConnector;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fmt::{self, Display};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::runtime::Builder;

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
	_Argument(String),
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
	pub fn _get<'a, T>(&self, url: &'a str, api_secret: Option<String>) -> Result<T, Error>
	where
		for<'de> T: Deserialize<'de>,
	{
		self.handle_request(self.build_request(url, "GET", api_secret, None)?)
	}

	/// Helper function to easily issue an async HTTP GET request against a given
	/// URL that returns a future. Handles request building, JSON deserialization
	/// and response code checking.
	pub async fn _get_async<'a, T>(
		&self,
		url: &'a str,
		api_secret: Option<String>,
	) -> Result<T, Error>
	where
		for<'de> T: Deserialize<'de> + Send + 'static,
	{
		self.handle_request_async(self.build_request(url, "GET", api_secret, None)?)
			.await
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
	pub fn post<IN, OUT>(
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
	pub async fn post_async<IN, OUT>(
		&self,
		url: &str,
		input: &IN,
		api_secret: Option<String>,
	) -> Result<OUT, Error>
	where
		IN: Serialize,
		OUT: Send + 'static,
		for<'de> OUT: Deserialize<'de>,
	{
		self.handle_request_async(self.create_post_request(url, api_secret, input)?)
			.await
	}

	/// Helper function to easily issue a HTTP POST request with the provided JSON
	/// object as body on a given URL that returns nothing. Handles request
	/// building, JSON serialization, and response code
	/// checking.
	pub fn _post_no_ret<IN>(
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
	pub async fn _post_no_ret_async<IN>(
		&self,
		url: &str,
		api_secret: Option<String>,
		input: &IN,
	) -> Result<(), Error>
	where
		IN: Serialize,
	{
		self.send_request_async(self.create_post_request(url, api_secret, input)?)
			.await?;
		Ok(())
	}

	fn build_request(
		&self,
		url: &str,
		method: &str,
		api_secret: Option<String>,
		body: Option<String>,
	) -> Result<Request<Body>, Error> {
		let uri: Uri = url
			.parse()
			.map_err(|_| ErrorKind::RequestError(format!("Invalid url {}", url)))?;
		let mut builder = Request::builder();
		if let Some(api_secret) = api_secret {
			let basic_auth = format!("Basic {}", to_base64(&format!("grin:{}", api_secret)));
			builder = builder.header(AUTHORIZATION, basic_auth);
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

	async fn handle_request_async<T>(&self, req: Request<Body>) -> Result<T, Error>
	where
		for<'de> T: Deserialize<'de> + Send + 'static,
	{
		let data = self.send_request_async(req).await?;
		let ser = serde_json::from_str(&data)
			.map_err(|e| e.context(ErrorKind::ResponseError("Cannot parse response".to_owned())))?;
		Ok(ser)
	}

	async fn send_request_async(&self, req: Request<Body>) -> Result<String, Error> {
		let resp = if !self.use_socks {
			let https = hyper_rustls::HttpsConnector::new();
			let mut connector = TimeoutConnector::new(https);
			connector.set_connect_timeout(Some(Duration::from_secs(20)));
			connector.set_read_timeout(Some(Duration::from_secs(20)));
			connector.set_write_timeout(Some(Duration::from_secs(20)));
			let client = HyperClient::builder().build::<_, Body>(connector);

			client.request(req).await
		} else {
			let addr = self.socks_proxy_addr.ok_or_else(|| {
				ErrorKind::RequestError("Missing Socks proxy address".to_string())
			})?;
			let auth = format!("{}:{}", addr.ip(), addr.port());

			let https = hyper_rustls::HttpsConnector::new();
			let socks = hyper_socks2::SocksConnector {
				proxy_addr: hyper::Uri::builder()
					.scheme("socks5")
					.authority(auth.as_str())
					.path_and_query("/")
					.build()
					.map_err(|_| {
						ErrorKind::RequestError("Can't parse Socks proxy address".to_string())
					})?,
				auth: None,
				connector: https,
			};
			let mut connector = TimeoutConnector::new(socks);
			connector.set_connect_timeout(Some(Duration::from_secs(20)));
			connector.set_read_timeout(Some(Duration::from_secs(20)));
			connector.set_write_timeout(Some(Duration::from_secs(20)));
			let client = HyperClient::builder().build::<_, Body>(connector);

			client.request(req).await
		};
		let resp =
			resp.map_err(|e| ErrorKind::RequestError(format!("Cannot make request: {}", e)))?;

		let raw = body::to_bytes(resp)
			.await
			.map_err(|e| ErrorKind::RequestError(format!("Cannot read response body: {}", e)))?;

		Ok(String::from_utf8_lossy(&raw).to_string())
	}

	pub fn send_request(&self, req: Request<Body>) -> Result<String, Error> {
		let task = self.send_request_async(req);
		scope(|s| {
			let handle = s.spawn(|_| {
				let mut rt = Builder::new()
					.basic_scheduler()
					.enable_all()
					.build()
					.context(ErrorKind::Internal("can't create Tokio runtime".to_owned()))?;
				rt.block_on(task)
			});
			handle.join().unwrap()
		})
		.unwrap()
	}
}
