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

//! Helpers for multi-process node + wallet integration tests.

#![allow(dead_code)]

use futures::channel::oneshot;
use grin_core::global::{self, ChainTypes};
use grin_keychain::ExtKeychain;
use grin_p2p as p2p;
use grin_p2p::msg::PeerAddrs;
use grin_p2p::PeerAddr;
use grin_servers as servers;
use grin_util::{Mutex, StopState, ZeroingString};
use grin_wallet_controller as controller;
use grin_wallet_impls::{DefaultLCProvider, DefaultWalletImpl, HTTPNodeClient};
use grin_wallet_libwallet::WalletInst;
use std::default::Default;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::{fs, thread, time};

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

pub fn leak_api_chan() -> &'static mut (oneshot::Sender<()>, oneshot::Receiver<()>) {
	Box::leak(Box::new(oneshot::channel::<()>()))
}

pub fn settle() {
	thread::sleep(time::Duration::from_millis(500));
}

/// Build a node `ServerConfig` with unique ports derived from `n`.
pub fn node_config(n: u16, test_name_dir: &str) -> servers::ServerConfig {
	servers::ServerConfig {
		api_http_addr: format!("127.0.0.1:{}", 20000 + n),
		api_secret_path: None,
		foreign_api_secret_path: None,
		db_root: format!("target/tmp/{}/grin-node-{}", test_name_dir, n),
		p2p_config: p2p::P2PConfig {
			host: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
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

pub fn start_node(cfg: servers::ServerConfig) -> servers::Server {
	// grin_servers 5.4.1: (config, stop_state, api_chan)
	servers::Server::new(cfg, None, leak_api_chan()).expect("node starts")
}

pub type WalletHandle = Arc<
	Mutex<
		Box<
			dyn WalletInst<
				'static,
				DefaultLCProvider<'static, HTTPNodeClient, ExtKeychain>,
				HTTPNodeClient,
				ExtKeychain,
			>,
		>,
	>,
>;

/// Create and open a local wallet pointed at `node_url`.
pub fn create_wallet(
	test_dir: &str,
	name: &str,
	node_url: &str,
) -> (WalletHandle, Option<grin_util::secp::key::SecretKey>) {
	let dir = format!("target/tmp/{}/{}", test_dir, name);
	fs::create_dir_all(&dir).unwrap();

	let client = HTTPNodeClient::new(node_url, None).expect("HTTPNodeClient");
	let mut wallet = Box::new(DefaultWalletImpl::<HTTPNodeClient>::new(client).unwrap())
		as Box<
			dyn WalletInst<
				DefaultLCProvider<'static, HTTPNodeClient, ExtKeychain>,
				HTTPNodeClient,
				ExtKeychain,
			>,
		>;
	let lc = wallet.lc_provider().unwrap();
	lc.set_top_level_directory(&dir).unwrap();
	lc.create_wallet(None, None, 32, ZeroingString::from(""), false)
		.unwrap();
	let mask = lc
		.open_wallet(None, ZeroingString::from(""), false, false)
		.unwrap();
	(Arc::new(Mutex::new(wallet)), mask)
}

/// Start foreign HTTP listener (coinbase / slate receive) on a background thread.
pub fn start_foreign_listener(wallet: WalletHandle, mask: Option<grin_util::secp::key::SecretKey>, addr: &str) {
	let keychain_mask = Arc::new(Mutex::new(mask));
	let listen = addr.to_string();
	thread::spawn(move || {
		let _ = controller::controller::foreign_listener(
			wallet,
			keychain_mask,
			&listen,
			None,
			false,
			true,
			None,
		);
	});
	// Give the listener time to bind.
	thread::sleep(time::Duration::from_millis(800));
}

/// Start owner HTTP listener (optional foreign) on a background thread.
pub fn start_owner_listener(
	wallet: WalletHandle,
	mask: Option<grin_util::secp::key::SecretKey>,
	addr: &str,
	include_foreign: bool,
) {
	let keychain_mask = Arc::new(Mutex::new(mask));
	let listen = addr.to_string();
	thread::spawn(move || {
		let _ = controller::controller::owner_listener(
			wallet,
			keychain_mask,
			&listen,
			None,
			None,
			Some(include_foreign),
			None,
			true,
		);
	});
	thread::sleep(time::Duration::from_millis(800));
}

/// Mine with the internal test miner, sending coinbase to `wallet_url` if set.
pub fn start_test_miner(
	server: &servers::Server,
	wallet_url: Option<String>,
) -> Arc<StopState> {
	let stop = Arc::new(StopState::new());
	server.start_test_miner(wallet_url, stop.clone());
	stop
}

pub fn peer_addr(addr: &str) -> PeerAddr {
	PeerAddr(addr.parse::<SocketAddr>().expect("peer addr"))
}

pub fn seeds(addrs: &[&str]) -> Option<PeerAddrs> {
	Some(PeerAddrs {
		peers: addrs.iter().map(|a| peer_addr(a)).collect(),
	})
}
