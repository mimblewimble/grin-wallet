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

//! Public types for config modules

use crate::core::global::ChainTypes;
use crate::util::logger::LoggingConfig;
use grin_p2p::tor::config::{
	TorBridgeConfig, TorConfig, TorProxyConfig, BOOTSTRAP_TIMEOUT_SECS, MIN_CIRCUIT_TIMEOUT_MS,
	REQUEST_TIMEOUT_SECS,
};
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

/// Command-line wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletConfig {
	/// Chain parameters (default to Mainnet if none at the moment)
	pub chain_type: Option<ChainTypes>,
	/// The port this wallet will run on
	pub api_listen_port: u16,
	/// The port this wallet's owner API will run on
	pub owner_api_listen_port: Option<u16>,
	/// Location of the secret for basic auth on the Owner API
	pub api_secret_path: Option<String>,
	/// Location of the node api secret for basic auth on the Grin API
	pub node_api_secret_path: Option<String>,
	/// The api address of a running server node against which transaction inputs
	/// will be checked during send
	pub check_node_api_http_addr: String,
	/// Request timeout for requests to node API.
	pub node_api_request_timeout_secs: Option<u64>,
	/// Whether to include foreign API endpoints on the Owner API
	pub owner_api_include_foreign: Option<bool>,
	/// The directory in which wallet files are stored
	pub data_file_dir: String,
	/// If Some(true), don't cache commits alongside output data
	/// speed improvement, but your commits are in the database
	pub no_commit_cache: Option<bool>,
	/// TLS certificate file
	pub tls_certificate_file: Option<String>,
	/// TLS certificate private key file
	pub tls_certificate_key: Option<String>,
	/// Whether to use the black background color scheme for command line
	/// if enabled, wallet command output color will be suitable for black background terminal
	pub dark_background_color_scheme: Option<bool>,
	/// Scaling factor from transaction weight to transaction fee
	/// should match accept_fee_base parameter in grin-server
	pub accept_fee_base: Option<u64>,
}

impl Default for WalletConfig {
	fn default() -> WalletConfig {
		WalletConfig {
			chain_type: Some(ChainTypes::Mainnet),
			api_listen_port: 3415,
			owner_api_listen_port: Some(WalletConfig::default_owner_api_listen_port()),
			api_secret_path: Some(".owner_api_secret".to_string()),
			node_api_secret_path: Some(".foreign_api_secret".to_string()),
			check_node_api_http_addr: "http://127.0.0.1:3413".to_string(),
			node_api_request_timeout_secs: Some(Self::NODE_API_REQUEST_TIMEOUT_SECS),
			owner_api_include_foreign: Some(false),
			data_file_dir: ".".to_string(),
			no_commit_cache: Some(false),
			tls_certificate_file: None,
			tls_certificate_key: None,
			dark_background_color_scheme: Some(true),
			accept_fee_base: None,
		}
	}
}

impl WalletConfig {
	/// Default Node API request timeout in seconds.
	pub const NODE_API_REQUEST_TIMEOUT_SECS: u64 = 60;

	/// API Listen address
	pub fn api_listen_addr(&self) -> String {
		format!("127.0.0.1:{}", self.api_listen_port)
	}

	/// Default listener port
	pub fn default_owner_api_listen_port() -> u16 {
		3420
	}

	/// Default listener port
	pub fn default_accept_fee_base() -> u64 {
		500_000
	}

	/// Use value from config file, defaulting to sensible value if missing.
	pub fn owner_api_listen_port(&self) -> u16 {
		self.owner_api_listen_port
			.unwrap_or_else(WalletConfig::default_owner_api_listen_port)
	}

	/// Owner API listen address
	pub fn owner_api_listen_addr(&self) -> String {
		format!("127.0.0.1:{}", self.owner_api_listen_port())
	}

	/// Accept fee base
	pub fn accept_fee_base(&self) -> u64 {
		self.accept_fee_base
			.unwrap_or_else(WalletConfig::default_accept_fee_base)
	}

	/// Node API requests timeout.
	pub fn api_request_timeout(&self) -> Duration {
		Duration::from_secs(
			self.node_api_request_timeout_secs
				.filter(|s| *s > 0)
				.unwrap_or(Self::NODE_API_REQUEST_TIMEOUT_SECS),
		)
	}
}
/// Error type wrapping config errors.
#[derive(Debug)]
pub enum ConfigError {
	/// Error with parsing of config file
	ParseError(String, String),

	/// Error with fileIO while reading config file
	FileIOError(String, String),

	/// No file found
	FileNotFoundError(String),

	/// Error serializing config values
	SerializationError(String),

	/// Path doesn't exist
	PathNotFoundError(String),
}

impl fmt::Display for ConfigError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match *self {
			ConfigError::ParseError(ref file_name, ref message) => write!(
				f,
				"Error parsing configuration file at {} - {}",
				file_name, message
			),
			ConfigError::FileIOError(ref file_name, ref message) => {
				write!(f, "{} {}", message, file_name)
			}
			ConfigError::FileNotFoundError(ref file_name) => {
				write!(f, "Configuration file not found: {}", file_name)
			}
			ConfigError::SerializationError(ref message) => {
				write!(f, "Error serializing configuration: {}", message)
			}
			ConfigError::PathNotFoundError(ref message) => write!(f, "Path not found: {}", message),
		}
	}
}

impl From<io::Error> for ConfigError {
	fn from(error: io::Error) -> ConfigError {
		ConfigError::FileIOError(
			String::from(""),
			format!("Error loading config file: {}", error),
		)
	}
}

/// Tor configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TorWalletConfig {
	/// Whether to use integrated Tor library.
	pub use_integrated: Option<bool>,
	/// Whether to skip any attempts to send via Tor.
	pub skip_send_attempt: Option<bool>,
	/// Whether to start Tor listener on listener startup (default true).
	pub use_tor_listener: bool,
	/// The address of the socks proxy for external process.
	pub socks_proxy_addr: String,
	/// Send configuration directory.
	pub send_config_dir: String,
	/// Total timeout for request in seconds.
	pub request_timeout_secs: Option<u64>,
	/// Timeout for bootstrap in seconds.
	pub bootstrap_timeout_secs: Option<u64>,
	/// Minimum Tor circuit build timeout in milliseconds.
	pub min_circuit_timeout_ms: Option<i32>,
	/// Tor bridge config.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub bridges: Vec<TorBridgeConfig>,
	/// Tor proxy config.
	#[serde(default)]
	pub proxy: TorProxyConfig,
}

impl TorConfig for TorWalletConfig {
	fn use_integrated(&self) -> bool {
		self.use_integrated.unwrap_or(false)
	}

	fn request_timeout_secs(&self) -> Option<u64> {
		self.request_timeout_secs
	}

	fn bootstrap_timeout_secs(&self) -> Option<u64> {
		self.bootstrap_timeout_secs
	}

	fn min_circuit_timeout_ms(&self) -> Option<i32> {
		self.min_circuit_timeout_ms
	}

	fn bridge_config(&self) -> &[TorBridgeConfig] {
		&self.bridges
	}

	fn proxy_config(&self) -> &TorProxyConfig {
		&self.proxy
	}

	fn data_dir(&self) -> PathBuf {
		let mut path = PathBuf::from(&self.send_config_dir);
		path.push("tor");
		path
	}

	fn socks_proxy_addr(&self) -> String {
		self.socks_proxy_addr.clone()
	}
}

impl Default for TorWalletConfig {
	fn default() -> TorWalletConfig {
		TorWalletConfig {
			use_integrated: Some(true),
			skip_send_attempt: Some(false),
			use_tor_listener: true,
			socks_proxy_addr: "127.0.0.1:59050".to_owned(),
			send_config_dir: ".".into(),
			request_timeout_secs: Some(REQUEST_TIMEOUT_SECS),
			bootstrap_timeout_secs: Some(BOOTSTRAP_TIMEOUT_SECS),
			min_circuit_timeout_ms: Some(MIN_CIRCUIT_TIMEOUT_MS),
			bridges: Vec::new(),
			proxy: TorProxyConfig::default(),
		}
	}
}

impl TorWalletConfig {
	/// Maximum Tor response size in bytes
	pub const RESPONSE_LIMIT: usize = 16 * 1024 * 1024;

	/// Override the configured bridges with a single bridge
	pub fn set_bridge(&mut self, line: String) {
		self.bridges.resize_with(1, TorBridgeConfig::default);
		self.bridges[0].bridge_line = Some(line);
	}

	/// Check if attempt to send over Tor is needed using provided possible argument at priority.
	pub fn send_tor(&self, skip_arg: Option<bool>) -> bool {
		if let Some(skip_tor) = skip_arg {
			return !skip_tor;
		}
		!self.skip_send_attempt.unwrap_or(false)
	}
}

/// Wallet should be split into a separate configuration file
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GlobalWalletConfig {
	/// Keep track of the file we've read
	pub config_file_path: PathBuf,
	/// Wallet members
	pub members: GlobalWalletConfigMembers,
}

/// Wallet internal members
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GlobalWalletConfigMembers {
	/// Config file version (None == version 1)
	#[serde(default)]
	pub config_file_version: Option<u32>,
	/// Wallet configuration
	#[serde(default)]
	pub wallet: WalletConfig,
	/// Tor config
	pub tor: Option<TorWalletConfig>,
	/// Logging config
	pub logging: Option<LoggingConfig>,
}
