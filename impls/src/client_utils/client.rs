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
use failure::{Backtrace, Context, Fail, ResultExt};
use lazy_static::lazy_static;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use reqwest::{ClientBuilder, Method, Proxy, RequestBuilder};
use serde::{Deserialize, Serialize};
use serde_json;
use std::fmt::{self, Display};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::{Builder, Handle, Runtime};

// Global Tokio runtime.
// Needs a `Mutex` because `Runtime::block_on` requires mutable access.
// Tokio v0.3 requires immutable self, but we are waiting on upstream
// updates before we can upgrade.
// See: https://github.com/seanmonstar/reqwest/pull/1076
lazy_static! {
	pub static ref RUNTIME: Arc<Mutex<Runtime>> = Arc::new(Mutex::new(
		Builder::new()
			.threaded_scheduler()
			.enable_all()
			.build()
			.unwrap()
	));
}

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

#[derive(Clone)]
pub struct Client {
	client: reqwest::Client,
}

impl Client {
	/// New client
	pub fn new(read_and_write_timeout: Option<u64>) -> Result<Self, Error> {
		Self::build(None, read_and_write_timeout)
	}

	pub fn with_socks_proxy(socks_proxy_addr: SocketAddr, read_and_write_timeout: Option<u64>) -> Result<Self, Error> {
		Self::build(Some(socks_proxy_addr), read_and_write_timeout)
	}

	fn build(socks_proxy_addr: Option<SocketAddr>, read_and_write_timeout: Option<u64>) -> Result<Self, Error> {
		let mut headers = HeaderMap::new();
		headers.insert(USER_AGENT, HeaderValue::from_static("grin-client"));
		headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
		headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

		let mut builder = ClientBuilder::new()
			.timeout(Duration::from_secs(read_and_write_timeout.unwrap_or(20)))
			.connect_timeout(Duration::from_secs(20))
			.use_rustls_tls()
			.default_headers(headers);

		if let Some(s) = socks_proxy_addr {
			let proxy = Proxy::all(&format!("socks5h://{}:{}", s.ip(), s.port()))
				.map_err(|e| ErrorKind::Internal(format!("Unable to create proxy: {}", e)))?;
			builder = builder.proxy(proxy);
		}

		let client = builder
			.build()
			.map_err(|e| ErrorKind::Internal(format!("Unable to build client: {}", e)))?;

		Ok(Client { client })
	}

	/// Helper function to easily issue a HTTP GET request against a given URL that
	/// returns a JSON object. Handles request building, JSON deserialization and
	/// response code checking.
	pub fn _get<'a, T>(&self, url: &'a str, api_secret: Option<String>) -> Result<T, Error>
	where
		for<'de> T: Deserialize<'de>,
	{
		self.handle_request(self.build_request(url, Method::GET, api_secret, None)?)
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
		self.handle_request_async(self.build_request(url, Method::GET, api_secret, None)?)
			.await
	}

	/// Helper function to easily issue a HTTP GET request
	/// on a given URL that returns nothing. Handles request
	/// building and response code checking.
	pub fn _get_no_ret(&self, url: &str, api_secret: Option<String>) -> Result<(), Error> {
		let req = self.build_request(url, Method::GET, api_secret, None)?;
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
		method: Method,
		api_secret: Option<String>,
		body: Option<String>,
	) -> Result<RequestBuilder, Error> {
		let mut builder = self.client.request(method, url);
		if let Some(api_secret) = api_secret {
			let basic_auth = format!("Basic {}", to_base64(&format!("grin:{}", api_secret)));
			builder = builder.header(AUTHORIZATION, basic_auth);
		}

		if let Some(body) = body {
			builder = builder.body(body);
		}

		Ok(builder)
	}

	pub fn create_post_request<IN>(
		&self,
		url: &str,
		api_secret: Option<String>,
		input: &IN,
	) -> Result<RequestBuilder, Error>
	where
		IN: Serialize,
	{
		let json = serde_json::to_string(input).context(ErrorKind::Internal(
			"Could not serialize data to JSON".to_owned(),
		))?;
		self.build_request(url, Method::POST, api_secret, Some(json))
	}

	fn handle_request<T>(&self, req: RequestBuilder) -> Result<T, Error>
	where
		for<'de> T: Deserialize<'de>,
	{
		let data = self.send_request(req)?;
		serde_json::from_str(&data).map_err(|e| {
			e.context(ErrorKind::ResponseError("Cannot parse response".to_owned()))
				.into()
		})
	}

	async fn handle_request_async<T>(&self, req: RequestBuilder) -> Result<T, Error>
	where
		for<'de> T: Deserialize<'de> + Send + 'static,
	{
		let data = self.send_request_async(req).await?;
		let ser = serde_json::from_str(&data)
			.map_err(|e| e.context(ErrorKind::ResponseError("Cannot parse response".to_owned())))?;
		Ok(ser)
	}

	async fn send_request_async(&self, req: RequestBuilder) -> Result<String, Error> {
		let resp = req
			.send()
			.await
			.map_err(|e| ErrorKind::RequestError(format!("Cannot make request: {}", e)))?;
		let text = resp
			.text()
			.await
			.map_err(|e| ErrorKind::ResponseError(format!("Cannot parse response: {}", e)))?;
		Ok(text)
	}

	pub fn send_request(&self, req: RequestBuilder) -> Result<String, Error> {
		// This client is currently used both outside and inside of a tokio runtime
		// context. In the latter case we are not allowed to do a blocking call to
		// our global runtime, which unfortunately means we have to spawn a new thread
		if Handle::try_current().is_ok() {
			let rt = RUNTIME.clone();
			let client = self.clone();
			std::thread::spawn(move || {
				rt.lock()
					.unwrap()
					.block_on(async { client.send_request_async(req).await })
			})
			.join()
			.unwrap()
		} else {
			RUNTIME
				.lock()
				.unwrap()
				.block_on(self.send_request_async(req))
		}
	}
}
