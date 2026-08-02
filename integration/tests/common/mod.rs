// Copyright 2026 The Grin Developers
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

//! Helpers for live node + wallet foreign-HTTP integration tests.

use grin_api as api;
use grin_core::global::{self, ChainTypes};
use grin_keychain::ExtKeychain;
use grin_p2p as p2p;
use grin_servers as servers;
use grin_util::{Mutex, StopState, ZeroingString};
use grin_wallet_api::ConfigPath;
use grin_wallet_config::config::{reload_global_config, WALLET_CONFIG_FILE_NAME};
use grin_wallet_config::{GlobalWalletConfig, TorConfig};
use grin_wallet_controller::controller::ForeignAPIHandlerV2;
use grin_wallet_impls::{DefaultLCProvider, DefaultWalletImpl, HTTPNodeClient};
use grin_wallet_libwallet::slate_versions::{SlateVersion, VersionedSlate};
use grin_wallet_libwallet::{Slate, WalletInst};
use serde_json::{json, Value};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{fs, thread};
use tokio::sync::mpsc;

/// Configure AutomatedTesting for the test thread and server worker threads.
pub fn init_chain() {
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_global_chain_type(ChainTypes::AutomatedTesting);
}

/// Remove leftover data from a previous run.
pub fn clean_all_output(test_name_dir: &str) {
	let target_dir = format!("target/tmp/{}", test_name_dir);
	if let Err(e) = fs::remove_dir_all(&target_dir) {
		if Path::new(&target_dir).exists() {
			println!(
				"can't remove output from previous test {}: {}, may be ok",
				target_dir, e
			);
		}
	}
}

pub fn settle() {
	thread::sleep(Duration::from_millis(500));
}

/// Build a node `ServerConfig` with unique ports derived from `n`.
pub fn node_config(n: u16, test_name_dir: &str) -> servers::ServerConfig {
	servers::ServerConfig {
		api_http_addr: format!("127.0.0.1:{}", 20000 + n),
		api_secret_path: None,
		foreign_api_secret_path: None,
		db_root: format!("target/tmp/{}/grin-node-{}", test_name_dir, n),
		p2p_config: p2p::P2PConfig {
			host: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
			port: 10000 + n,
			seeding_type: p2p::Seeding::None,
			seeds: None,
			..p2p::P2PConfig::default()
		},
		chain_type: ChainTypes::AutomatedTesting,
		archive_mode: Some(true),
		skip_sync_wait: Some(true),
		run_tui: Some(false),
		run_test_miner: Some(false),
		stratum_mining_config: None,
		..Default::default()
	}
}

/// Start a node. Shutdown is via `Server::stop()`.
pub fn start_node(cfg: servers::ServerConfig) -> servers::Server {
	let (tx, rx) = mpsc::channel::<()>(1);
	servers::Server::new(cfg, None, None, (tx, rx)).expect("node starts")
}

pub type WalletHandle = Arc<
	Mutex<
		Box<
			dyn WalletInst<
				'static,
				DefaultLCProvider<HTTPNodeClient, ExtKeychain>,
				HTTPNodeClient,
				ExtKeychain,
			>,
		>,
	>,
>;

/// Create wallet data dir, write `grin-wallet.toml`, open wallet, register global config.
pub fn create_wallet(
	test_dir: &str,
	name: &str,
	node_url: &str,
	foreign_port: u16,
) -> (
	WalletHandle,
	Option<grin_util::secp::key::SecretKey>,
	PathBuf,
) {
	let dir = format!("target/tmp/{}/{}", test_dir, name);
	fs::create_dir_all(&dir).unwrap();

	let config_path = PathBuf::from(&dir).join(WALLET_CONFIG_FILE_NAME);
	let mut global = GlobalWalletConfig::for_chain(&ChainTypes::AutomatedTesting, &config_path);
	global.members.wallet.data_file_dir = dir.clone();
	global.members.wallet.check_node_api_http_addr = node_url.to_string();
	global.members.wallet.api_listen_port = foreign_port;
	global.members.wallet.api_secret_path = None;
	global.members.wallet.node_api_secret_path = None;
	// No Tor in these tests.
	global.members.tor = Some(TorConfig {
		use_tor_listener: false,
		skip_send_attempt: Some(true),
		send_config_dir: dir.clone(),
		..TorConfig::default()
	});
	global
		.write_to_file(config_path.to_str().unwrap(), false, None, None)
		.expect("write wallet config");
	reload_global_config(&config_path).expect("load global config");

	let client =
		HTTPNodeClient::new(node_url, None, Duration::from_secs(30)).expect("HTTPNodeClient");
	let mut wallet = Box::new(DefaultWalletImpl::<HTTPNodeClient>::new(client).unwrap())
		as Box<
			dyn WalletInst<
				'static,
				DefaultLCProvider<HTTPNodeClient, ExtKeychain>,
				HTTPNodeClient,
				ExtKeychain,
			>,
		>;
	let mask = {
		let lc = wallet.lc_provider().unwrap();
		lc.set_top_level_directory(&dir).unwrap();
		lc.create_wallet(None, None, 32, ZeroingString::from(""), false)
			.unwrap();
		lc.open_wallet(None, ZeroingString::from(""), false, false)
			.unwrap()
	};
	(Arc::new(Mutex::new(wallet)), mask, config_path)
}

/// Running foreign HTTP listener with readiness wait and clean stop.
pub struct ForeignListener {
	stop_tx: mpsc::Sender<()>,
	join: Option<thread::JoinHandle<Result<(), String>>>,
	addr: String,
}

impl ForeignListener {
	pub fn addr(&self) -> &str {
		&self.addr
	}

	pub fn stop(mut self) {
		let _ = self.stop_tx.try_send(());
		if let Some(j) = self.join.take() {
			let _ = j.join();
		}
	}
}

impl Drop for ForeignListener {
	fn drop(&mut self) {
		let _ = self.stop_tx.try_send(());
		if let Some(j) = self.join.take() {
			let _ = j.join();
		}
	}
}

/// Start a foreign HTTP listener (v2 receive_tx) without Tor.
///
/// Reports readiness by waiting until the port accepts TCP connections, and
/// surfaces startup failures from the listener thread. Call `stop()` (or drop)
/// to shut the API server down cleanly.
pub fn start_foreign_listener(
	wallet: WalletHandle,
	mask: Option<grin_util::secp::key::SecretKey>,
	config_path: PathBuf,
	addr: &str,
) -> ForeignListener {
	let keychain_mask = Arc::new(Mutex::new(mask));
	let listen = addr.to_string();
	let (stop_tx, stop_rx) = mpsc::channel::<()>(1);
	let stop_for_thread = stop_tx.clone();
	let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();

	let join = thread::Builder::new()
		.name(format!("foreign-{}", addr))
		.spawn(move || {
			let api_handler = ForeignAPIHandlerV2::new(
				wallet,
				ConfigPath::from(config_path),
				keychain_mask,
				true, // test_mode
			);
			let mut router = api::Router::new();
			if let Err(e) = router.add_route("/v2/foreign", Arc::new(api_handler)) {
				let msg = format!("router: {}", e);
				let _ = ready_tx.send(Err(msg.clone()));
				return Err(msg);
			}

			let api_chan: (mpsc::Sender<()>, mpsc::Receiver<()>) = (stop_for_thread, stop_rx);
			let mut apis = api::ApiServer::new();
			let socket_addr: SocketAddr = listen
				.parse()
				.map_err(|e| format!("bad listen addr: {}", e))?;
			let api_thread = match apis.start(socket_addr, router, None, api_chan) {
				Ok(t) => t,
				Err(e) => {
					let msg = format!("API start failed: {:?}", e);
					let _ = ready_tx.send(Err(msg.clone()));
					return Err(msg);
				}
			};
			// Server is bound; signal readiness.
			let _ = ready_tx.send(Ok(()));
			api_thread
				.join()
				.map_err(|e| format!("API thread panicked: {:?}", e))
		})
		.expect("spawn foreign listener");

	// Wait for bind success or failure (do not assume after a fixed sleep).
	match ready_rx.recv_timeout(Duration::from_secs(10)) {
		Ok(Ok(())) => {}
		Ok(Err(e)) => panic!("foreign listener failed to start: {}", e),
		Err(_) => panic!("foreign listener readiness timed out for {}", addr),
	}

	// Extra TCP check so callers know the port is accepting connections.
	wait_for_port(addr, Duration::from_secs(5)).expect("listener port");

	ForeignListener {
		stop_tx,
		join: Some(join),
		addr: addr.to_string(),
	}
}

fn wait_for_port(addr: &str, timeout: Duration) -> Result<(), String> {
	let deadline = Instant::now() + timeout;
	while Instant::now() < deadline {
		if TcpStream::connect(addr).is_ok() {
			return Ok(());
		}
		thread::sleep(Duration::from_millis(50));
	}
	Err(format!("timed out waiting for {}", addr))
}

/// POST a slate to a foreign HTTP listener's `receive_tx` (real network path).
pub fn receive_tx_via_http(base_url: &str, slate: &Slate) -> Result<Slate, String> {
	let trailing = if base_url.ends_with('/') { "" } else { "/" };
	let url = format!("{}{}v2/foreign", base_url, trailing);

	// Version negotiation (same as TorSlateSender::check_other_version).
	let ver_req = json!({
		"jsonrpc": "2.0",
		"method": "check_version",
		"id": 1,
		"params": []
	});
	let ver_res: Value = api::client::post(&url, None, &ver_req, api::client::TimeOut::default())
		.map_err(|e| format!("check_version: {}", e))?;
	if ver_res["error"] != json!(null) {
		return Err(format!("check_version error: {}", ver_res["error"]));
	}
	let supported: Vec<String> =
		serde_json::from_value(ver_res["result"]["Ok"]["supported_slate_versions"].clone())
			.map_err(|e| format!("parse versions: {}", e))?;
	if !supported.iter().any(|v| v == "V4") {
		return Err("remote does not support slate V4".into());
	}

	let slate_send = VersionedSlate::into_version(slate.clone(), SlateVersion::V4)
		.map_err(|e| format!("version slate: {}", e))?;
	let req = json!({
		"jsonrpc": "2.0",
		"method": "receive_tx",
		"id": 1,
		"params": [slate_send, null, null]
	});
	let res: Value = api::client::post(&url, None, &req, api::client::TimeOut::default())
		.map_err(|e| format!("receive_tx http: {}", e))?;
	if res["error"] != json!(null) {
		return Err(format!("receive_tx error: {}", res["error"]));
	}
	let slate_value = res["result"]["Ok"].clone();
	let slate_str =
		serde_json::to_string(&slate_value).map_err(|e| format!("serialize slate: {}", e))?;
	Slate::deserialize_upgrade(&slate_str).map_err(|e| format!("deserialize slate: {}", e))
}

/// Mine with the internal test miner, sending coinbase to `wallet_url` if set.
pub fn start_test_miner(server: &servers::Server, wallet_url: Option<String>) -> Arc<StopState> {
	let stop = Arc::new(StopState::new());
	server.start_test_miner(wallet_url, stop.clone());
	stop
}
