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

use std::fmt;
use std::io;
use std::path::PathBuf;

use crate::core::global::ChainTypes;
use crate::util::logger::LoggingConfig;

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
pub struct TorConfig {
	/// whether to skip any attempts to send via TOR
	pub skip_send_attempt: Option<bool>,
	/// Whether to start tor listener on listener startup (default true)
	pub use_tor_listener: bool,
	/// Just the address of the socks proxy for now
	pub socks_proxy_addr: String,
	/// Send configuration directory
	pub send_config_dir: String,
	/// tor bridge config
	#[serde(default)]
	pub bridge: TorBridgeConfig,
	/// tor proxy config
	#[serde(default)]
	pub proxy: TorProxyConfig,
}

impl Default for TorConfig {
	fn default() -> TorConfig {
		TorConfig {
			skip_send_attempt: Some(false),
			use_tor_listener: true,
			socks_proxy_addr: "127.0.0.1:59050".to_owned(),
			send_config_dir: ".".into(),
			bridge: TorBridgeConfig::default(),
			proxy: TorProxyConfig::default(),
		}
	}
}

/// Tor Bridge Config
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TorBridgeConfig {
	/// Bridge Line
	pub bridge_line: Option<String>,
	/// Client Option
	pub client_option: Option<String>,
}

impl fmt::Display for TorBridgeConfig {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{:?}", self)
	}
}

/// Tor Proxy configuration (useful for protocols such as shadowsocks)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TorProxyConfig {
	/// socks4 |socks5 | http(s)
	pub transport: Option<String>,
	/// ip or dns
	pub address: Option<String>,
	/// user for auth - socks5|https(s)
	pub username: Option<String>,
	/// pass for auth - socks5|https(s)
	pub password: Option<String>,
	/// allowed port - proxy
	pub allowed_port: Option<Vec<u16>>,
}

impl fmt::Display for TorProxyConfig {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{:?}", self)
	}
}

/// Wallet should be split into a separate configuration file
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GlobalWalletConfig {
	/// Keep track of the file we've read
	pub config_file_path: Option<PathBuf>,
	/// Wallet members
	pub members: Option<GlobalWalletConfigMembers>,
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
	pub tor: Option<TorConfig>,
	/// Logging config
	pub logging: Option<LoggingConfig>,
}
