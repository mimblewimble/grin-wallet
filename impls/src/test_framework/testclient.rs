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

//! Test client that acts against a local instance of a node
//! so that wallet API can be fully exercised
//! Operates directly on a chain instance

use crate::api::{self, LocatedTxKernel};
use crate::chain::types::NoopAdapter;
use crate::chain::Chain;
use crate::core::core::{Transaction, TxKernel};
use crate::core::global::{set_local_chain_type, ChainTypes};
use crate::core::pow;
use crate::keychain::Keychain;
use crate::libwallet;
use crate::libwallet::api_impl::foreign;
use crate::libwallet::slate_versions::v4::SlateV4;
use crate::libwallet::{NodeClient, NodeVersionInfo, Slate, WalletInst, WalletLCProvider};
use crate::util;
use crate::util::secp::key::SecretKey;
use crate::util::secp::pedersen;
use crate::util::secp::pedersen::Commitment;
use crate::util::{Mutex, ToHex};
use failure::ResultExt;
use serde_json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Messages to simulate wallet requests/responses
#[derive(Clone, Debug)]
pub struct WalletProxyMessage {
	/// sender ID
	pub sender_id: String,
	/// destination wallet (or server)
	pub dest: String,
	/// method (like a GET url)
	pub method: String,
	/// payload (json body)
	pub body: String,
}

/// communicates with a chain instance or other wallet
/// listener APIs via message queues
pub struct WalletProxy<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	/// directory to create the chain in
	pub chain_dir: String,
	/// handle to chain itself
	pub chain: Arc<Chain>,
	/// list of interested wallets
	pub wallets: HashMap<
		String,
		(
			Sender<WalletProxyMessage>,
			Arc<Mutex<Box<dyn WalletInst<'a, L, C, K> + 'a>>>,
			Option<SecretKey>,
		),
	>,
	/// simulate json send to another client
	/// address, method, payload (simulate HTTP request)
	pub tx: Sender<WalletProxyMessage>,
	/// simulate json receiving
	pub rx: Receiver<WalletProxyMessage>,
	/// queue control
	pub running: Arc<AtomicBool>,
}

impl<'a, L, C, K> WalletProxy<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	/// Create a new client that will communicate with the given grin node
	pub fn new(chain_dir: &str) -> Self {
		set_local_chain_type(ChainTypes::AutomatedTesting);
		let genesis_block = pow::mine_genesis_block().unwrap();
		let dir_name = format!("{}/.grin", chain_dir);
		let c = Chain::init(
			dir_name,
			Arc::new(NoopAdapter {}),
			genesis_block,
			pow::verify_size,
			false,
		)
		.unwrap();
		let (tx, rx) = channel();
		WalletProxy {
			chain_dir: chain_dir.to_owned(),
			chain: Arc::new(c),
			tx: tx,
			rx: rx,
			wallets: HashMap::new(),
			running: Arc::new(AtomicBool::new(false)),
		}
	}

	/// Add wallet with a given "address"
	pub fn add_wallet(
		&mut self,
		addr: &str,
		tx: Sender<WalletProxyMessage>,
		wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K> + 'a>>>,
		keychain_mask: Option<SecretKey>,
	) {
		self.wallets
			.insert(addr.to_owned(), (tx, wallet, keychain_mask));
	}

	pub fn stop(&mut self) {
		self.running.store(false, Ordering::Relaxed);
	}

	/// Run the incoming message queue and respond more or less
	/// synchronously
	pub fn run(&mut self) -> Result<(), libwallet::Error> {
		// We run the wallet_proxy within a spawned thread in tests.
		// We set the local chain_type here within the thread.
		set_local_chain_type(ChainTypes::AutomatedTesting);

		self.running.store(true, Ordering::Relaxed);
		loop {
			thread::sleep(Duration::from_millis(10));
			if !self.running.load(Ordering::Relaxed) {
				info!("Proxy stopped");
				return Ok(());
			}

			// read queue
			let m = match self.rx.recv_timeout(Duration::from_millis(10)) {
				Ok(m) => m,
				Err(_) => continue,
			};
			trace!("Wallet Client Proxy Received: {:?}", m);
			let resp = match m.method.as_ref() {
				"get_chain_tip" => self.get_chain_tip(m)?,
				"get_outputs_from_node" => self.get_outputs_from_node(m)?,
				"get_outputs_by_pmmr_index" => self.get_outputs_by_pmmr_index(m)?,
				"height_range_to_pmmr_indices" => self.height_range_to_pmmr_indices(m)?,
				"send_tx_slate" => self.send_tx_slate(m)?,
				"post_tx" => self.post_tx(m)?,
				"get_kernel" => self.get_kernel(m)?,
				_ => panic!("Unknown Wallet Proxy Message"),
			};

			self.respond(resp);
		}
	}

	/// Return a message to a given wallet client
	fn respond(&mut self, m: WalletProxyMessage) {
		if let Some(s) = self.wallets.get_mut(&m.dest) {
			if let Err(e) = s.0.send(m.clone()) {
				panic!("Error sending response from proxy: {:?}, {}", m, e);
			}
		} else {
			panic!("Unknown wallet recipient for response message: {:?}", m);
		}
	}

	/// post transaction to the chain (and mine it, taking the reward)
	fn post_tx(&mut self, m: WalletProxyMessage) -> Result<WalletProxyMessage, libwallet::Error> {
		let dest_wallet = self.wallets.get_mut(&m.sender_id).unwrap().1.clone();
		let dest_wallet_mask = self.wallets.get_mut(&m.sender_id).unwrap().2.clone();
		let tx: Transaction = serde_json::from_str(&m.body).context(
			libwallet::ErrorKind::ClientCallback("Error parsing Transaction".to_owned()),
		)?;

		super::award_block_to_wallet(
			&self.chain,
			&[tx],
			dest_wallet,
			(&dest_wallet_mask).as_ref(),
		)?;

		Ok(WalletProxyMessage {
			sender_id: "node".to_owned(),
			dest: m.sender_id,
			method: m.method,
			body: "".to_owned(),
		})
	}

	/// send tx slate
	fn send_tx_slate(
		&mut self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, libwallet::Error> {
		let dest_wallet = self.wallets.get_mut(&m.dest);
		let wallet = match dest_wallet {
			None => panic!("Unknown wallet destination for send_tx_slate: {:?}", m),
			Some(w) => w,
		};

		let slate: SlateV4 = serde_json::from_str(&m.body).context(
			libwallet::ErrorKind::ClientCallback("Error parsing TxWrapper".to_owned()),
		)?;

		let slate: Slate = {
			let mut w_lock = wallet.1.lock();
			let w = w_lock.lc_provider()?.wallet_inst()?;
			let mask = wallet.2.clone();
			// receive tx
			match foreign::receive_tx(&mut **w, (&mask).as_ref(), &Slate::from(slate), None, false)
			{
				Err(e) => {
					return Ok(WalletProxyMessage {
						sender_id: m.dest,
						dest: m.sender_id,
						method: m.method,
						body: serde_json::to_string(&format!("Error: {}", e)).unwrap(),
					})
				}
				Ok(s) => s,
			}
		};

		Ok(WalletProxyMessage {
			sender_id: m.dest,
			dest: m.sender_id,
			method: m.method,
			body: serde_json::to_string(&SlateV4::from(slate)).unwrap(),
		})
	}

	/// get chain height
	fn get_chain_tip(
		&mut self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, libwallet::Error> {
		let height = self.chain.head().unwrap().height;
		let hash = self.chain.head().unwrap().last_block_h.to_hex();

		Ok(WalletProxyMessage {
			sender_id: "node".to_owned(),
			dest: m.sender_id,
			method: m.method,
			body: format!("{},{}", height, hash),
		})
	}

	/// get api outputs
	fn get_outputs_from_node(
		&mut self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, libwallet::Error> {
		let split = m.body.split(',');
		//let mut api_outputs: HashMap<pedersen::Commitment, String> = HashMap::new();
		let mut outputs: Vec<api::Output> = vec![];
		for o in split {
			let o_str = String::from(o);
			if o_str.is_empty() {
				continue;
			}
			let c = util::from_hex(&o_str).unwrap();
			let commit = Commitment::from_vec(c);
			let out = super::get_output_local(&self.chain.clone(), commit);
			if let Some(o) = out {
				outputs.push(o);
			}
		}
		Ok(WalletProxyMessage {
			sender_id: "node".to_owned(),
			dest: m.sender_id,
			method: m.method,
			body: serde_json::to_string(&outputs).unwrap(),
		})
	}

	/// get api outputs
	fn get_outputs_by_pmmr_index(
		&mut self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, libwallet::Error> {
		let split = m.body.split(',').collect::<Vec<&str>>();
		let start_index = split[0].parse::<u64>().unwrap();
		let max = split[1].parse::<u64>().unwrap();
		let end_index = split[2].parse::<u64>().unwrap();
		let end_index = match end_index {
			0 => None,
			e => Some(e),
		};
		let ol =
			super::get_outputs_by_pmmr_index_local(self.chain.clone(), start_index, end_index, max);
		Ok(WalletProxyMessage {
			sender_id: "node".to_owned(),
			dest: m.sender_id,
			method: m.method,
			body: serde_json::to_string(&ol).unwrap(),
		})
	}

	/// get api outputs by height
	fn height_range_to_pmmr_indices(
		&mut self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, libwallet::Error> {
		let split = m.body.split(',').collect::<Vec<&str>>();
		let start_index = split[0].parse::<u64>().unwrap();
		let end_index = split[1].parse::<u64>().unwrap();
		let end_index = match end_index {
			0 => None,
			e => Some(e),
		};
		let ol =
			super::height_range_to_pmmr_indices_local(self.chain.clone(), start_index, end_index);
		Ok(WalletProxyMessage {
			sender_id: "node".to_owned(),
			dest: m.sender_id,
			method: m.method,
			body: serde_json::to_string(&ol).unwrap(),
		})
	}

	/// get kernel
	fn get_kernel(
		&mut self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, libwallet::Error> {
		let split = m.body.split(',').collect::<Vec<&str>>();
		let excess = split[0].parse::<String>().unwrap();
		let min = split[1].parse::<u64>().unwrap();
		let max = split[2].parse::<u64>().unwrap();
		let commit_bytes = util::from_hex(&excess).unwrap();
		let commit = pedersen::Commitment::from_vec(commit_bytes);
		let min = match min {
			0 => None,
			m => Some(m),
		};
		let max = match max {
			0 => None,
			m => Some(m),
		};
		let k = super::get_kernel_local(self.chain.clone(), &commit, min, max);
		Ok(WalletProxyMessage {
			sender_id: "node".to_owned(),
			dest: m.sender_id,
			method: m.method,
			body: serde_json::to_string(&k).unwrap(),
		})
	}
}

#[derive(Clone)]
pub struct LocalWalletClient {
	/// wallet identifier for the proxy queue
	pub id: String,
	/// proxy's tx queue (receive messages from other wallets or node
	pub proxy_tx: Arc<Mutex<Sender<WalletProxyMessage>>>,
	/// my rx queue
	pub rx: Arc<Mutex<Receiver<WalletProxyMessage>>>,
	/// my tx queue
	pub tx: Arc<Mutex<Sender<WalletProxyMessage>>>,
}

impl LocalWalletClient {
	/// new
	pub fn new(id: &str, proxy_rx: Sender<WalletProxyMessage>) -> Self {
		let (tx, rx) = channel();
		LocalWalletClient {
			id: id.to_owned(),
			proxy_tx: Arc::new(Mutex::new(proxy_rx)),
			rx: Arc::new(Mutex::new(rx)),
			tx: Arc::new(Mutex::new(tx)),
		}
	}

	/// get an instance of the send queue for other senders
	pub fn get_send_instance(&self) -> Sender<WalletProxyMessage> {
		self.tx.lock().clone()
	}

	/// Send the slate to a listening wallet instance
	pub fn send_tx_slate_direct(
		&self,
		dest: &str,
		slate: &Slate,
	) -> Result<Slate, libwallet::Error> {
		let m = WalletProxyMessage {
			sender_id: self.id.clone(),
			dest: dest.to_owned(),
			method: "send_tx_slate".to_owned(),
			body: serde_json::to_string(&SlateV4::from(slate)).unwrap(),
		};
		{
			let p = self.proxy_tx.lock();
			p.send(m).context(libwallet::ErrorKind::ClientCallback(
				"Send TX Slate".to_owned(),
			))?;
		}
		let r = self.rx.lock();
		let m = r.recv().unwrap();
		trace!("Received send_tx_slate response: {:?}", m.clone());
		let slate: SlateV4 = serde_json::from_str(&m.body).context(
			libwallet::ErrorKind::ClientCallback("Parsing send_tx_slate response".to_owned()),
		)?;
		Ok(Slate::from(slate))
	}
}

impl NodeClient for LocalWalletClient {
	fn node_url(&self) -> &str {
		"node"
	}
	fn node_api_secret(&self) -> Option<String> {
		None
	}
	fn set_node_url(&mut self, _node_url: &str) {}
	fn set_node_api_secret(&mut self, _node_api_secret: Option<String>) {}
	fn get_version_info(&mut self) -> Option<NodeVersionInfo> {
		None
	}
	/// Posts a transaction to a grin node
	/// In this case it will create a new block with award rewarded to
	fn post_tx(&self, tx: &Transaction, _fluff: bool) -> Result<(), libwallet::Error> {
		let m = WalletProxyMessage {
			sender_id: self.id.clone(),
			dest: self.node_url().to_owned(),
			method: "post_tx".to_owned(),
			body: serde_json::to_string(tx).unwrap(),
		};
		{
			let p = self.proxy_tx.lock();
			p.send(m).context(libwallet::ErrorKind::ClientCallback(
				"post_tx send".to_owned(),
			))?;
		}
		let r = self.rx.lock();
		let m = r.recv().unwrap();
		trace!("Received post_tx response: {:?}", m);
		Ok(())
	}

	/// Return the chain tip from a given node
	fn get_chain_tip(&self) -> Result<(u64, String), libwallet::Error> {
		let m = WalletProxyMessage {
			sender_id: self.id.clone(),
			dest: self.node_url().to_owned(),
			method: "get_chain_tip".to_owned(),
			body: "".to_owned(),
		};
		{
			let p = self.proxy_tx.lock();
			p.send(m).context(libwallet::ErrorKind::ClientCallback(
				"Get chain height send".to_owned(),
			))?;
		}
		let r = self.rx.lock();
		let m = r.recv().unwrap();
		trace!("Received get_chain_tip response: {:?}", m.clone());
		let res = m
			.body
			.parse::<String>()
			.context(libwallet::ErrorKind::ClientCallback(
				"Parsing get_height response".to_owned(),
			))?;
		let split: Vec<&str> = res.split(',').collect();
		Ok((split[0].parse::<u64>().unwrap(), split[1].to_owned()))
	}

	/// Retrieve outputs from node
	fn get_outputs_from_node(
		&self,
		wallet_outputs: Vec<pedersen::Commitment>,
	) -> Result<HashMap<pedersen::Commitment, (String, u64, u64)>, libwallet::Error> {
		let query_params: Vec<String> = wallet_outputs
			.iter()
			.map(|commit| commit.as_ref().to_hex())
			.collect();
		let query_str = query_params.join(",");
		let m = WalletProxyMessage {
			sender_id: self.id.clone(),
			dest: self.node_url().to_owned(),
			method: "get_outputs_from_node".to_owned(),
			body: query_str,
		};
		{
			let p = self.proxy_tx.lock();
			p.send(m).context(libwallet::ErrorKind::ClientCallback(
				"Get outputs from node send".to_owned(),
			))?;
		}
		let r = self.rx.lock();
		let m = r.recv().unwrap();
		let outputs: Vec<api::Output> = serde_json::from_str(&m.body).unwrap();
		let mut api_outputs: HashMap<pedersen::Commitment, (String, u64, u64)> = HashMap::new();
		for out in outputs {
			api_outputs.insert(
				out.commit.commit(),
				(out.commit.to_hex(), out.height, out.mmr_index),
			);
		}
		Ok(api_outputs)
	}

	fn get_kernel(
		&mut self,
		excess: &pedersen::Commitment,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<Option<(TxKernel, u64, u64)>, libwallet::Error> {
		let mut query = format!("{},", excess.0.as_ref().to_hex());
		if let Some(h) = min_height {
			query += &format!("{},", h);
		} else {
			query += "0,"
		}
		if let Some(h) = max_height {
			query += &format!("{}", h);
		} else {
			query += "0"
		}

		let m = WalletProxyMessage {
			sender_id: self.id.clone(),
			dest: self.node_url().to_owned(),
			method: "get_kernel".to_owned(),
			body: query,
		};
		{
			let p = self.proxy_tx.lock();
			p.send(m).context(libwallet::ErrorKind::ClientCallback(
				"Get outputs from node by PMMR index send".to_owned(),
			))?;
		}
		let r = self.rx.lock();
		let m = r.recv().unwrap();
		let res: Option<LocatedTxKernel> = serde_json::from_str(&m.body).context(
			libwallet::ErrorKind::ClientCallback("Get transaction kernels send".to_owned()),
		)?;
		match res {
			Some(k) => Ok(Some((k.tx_kernel, k.height, k.mmr_index))),
			None => Ok(None),
		}
	}

	fn get_outputs_by_pmmr_index(
		&self,
		start_index: u64,
		end_index: Option<u64>,
		max_outputs: u64,
	) -> Result<
		(
			u64,
			u64,
			Vec<(
				pedersen::Commitment,
				pedersen::RangeProof,
				bool,
				bool,
				u64,
				u64,
			)>,
		),
		libwallet::Error,
	> {
		// start index, max
		let mut query_str = format!("{},{}", start_index, max_outputs);
		match end_index {
			Some(e) => query_str = format!("{},{}", query_str, e),
			None => query_str = format!("{},0", query_str),
		};
		let m = WalletProxyMessage {
			sender_id: self.id.clone(),
			dest: self.node_url().to_owned(),
			method: "get_outputs_by_pmmr_index".to_owned(),
			body: query_str,
		};
		{
			let p = self.proxy_tx.lock();
			p.send(m).context(libwallet::ErrorKind::ClientCallback(
				"Get outputs from node by PMMR index send".to_owned(),
			))?;
		}

		let r = self.rx.lock();
		let m = r.recv().unwrap();
		let o: api::OutputListing = serde_json::from_str(&m.body).unwrap();

		let mut api_outputs: Vec<(
			pedersen::Commitment,
			pedersen::RangeProof,
			bool,
			bool,
			u64,
			u64,
		)> = Vec::new();

		for out in o.outputs {
			let (is_coinbase, is_multisig) = match out.output_type {
				api::OutputType::Coinbase => (true, false),
				api::OutputType::Transaction => (false, false),
				api::OutputType::Multisig => (false, true),
			};
			api_outputs.push((
				out.commit,
				out.range_proof().unwrap(),
				is_coinbase,
				is_multisig,
				out.block_height.unwrap(),
				out.mmr_index,
			));
		}
		Ok((o.highest_index, o.last_retrieved_index, api_outputs))
	}

	fn height_range_to_pmmr_indices(
		&self,
		start_height: u64,
		end_height: Option<u64>,
	) -> Result<(u64, u64), libwallet::Error> {
		// start index, max
		let mut query_str = format!("{}", start_height);
		match end_height {
			Some(e) => query_str = format!("{},{}", query_str, e),
			None => query_str = format!("{},0", query_str),
		};
		let m = WalletProxyMessage {
			sender_id: self.id.clone(),
			dest: self.node_url().to_owned(),
			method: "height_range_to_pmmr_indices".to_owned(),
			body: query_str,
		};
		{
			let p = self.proxy_tx.lock();
			p.send(m).context(libwallet::ErrorKind::ClientCallback(
				"Get outputs within height range send".to_owned(),
			))?;
		}

		let r = self.rx.lock();
		let m = r.recv().unwrap();
		let o: api::OutputListing = serde_json::from_str(&m.body).unwrap();
		Ok((o.last_retrieved_index, o.highest_index))
	}
}
unsafe impl<'a, L, C, K> Send for WalletProxy<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
}
