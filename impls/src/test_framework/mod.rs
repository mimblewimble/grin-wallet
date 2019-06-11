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

use crate::api;
use crate::chain;
use crate::chain::Chain;
use crate::config::WalletConfig;
use crate::core;
use crate::core::core::{OutputFeatures, OutputIdentifier, Transaction};
use crate::core::{consensus, global, pow};
use crate::keychain;
use crate::libwallet;
use crate::libwallet::api_impl::{foreign, owner};
use crate::libwallet::{
	BlockFees, CbData, InitTxArgs, NodeClient, WalletBackend, WalletInfo, WalletInst,
};
use crate::util;
use crate::util::secp::pedersen;
use crate::util::Mutex;
use crate::LMDBBackend;
use crate::WalletSeed;
use chrono::Duration;
use std::sync::Arc;
use std::thread;

mod testclient;

pub use self::{testclient::LocalWalletClient, testclient::WalletProxy};

/// Get an output from the chain locally and present it back as an API output
fn get_output_local(chain: &chain::Chain, commit: &pedersen::Commitment) -> Option<api::Output> {
	let outputs = [
		OutputIdentifier::new(OutputFeatures::Plain, commit),
		OutputIdentifier::new(OutputFeatures::Coinbase, commit),
	];

	for x in outputs.iter() {
		if let Ok(_) = chain.is_unspent(&x) {
			let block_height = chain.get_header_for_output(&x).unwrap().height;
			let output_pos = chain.get_output_pos(&x.commit).unwrap_or(0);
			return Some(api::Output::new(&commit, block_height, output_pos));
		}
	}
	None
}

/// get output listing traversing pmmr from local
fn get_outputs_by_pmmr_index_local(
	chain: Arc<chain::Chain>,
	start_index: u64,
	max: u64,
) -> api::OutputListing {
	let outputs = chain
		.unspent_outputs_by_insertion_index(start_index, max)
		.unwrap();
	api::OutputListing {
		last_retrieved_index: outputs.0,
		highest_index: outputs.1,
		outputs: outputs
			.2
			.iter()
			.map(|x| {
				api::OutputPrintable::from_output(x, chain.clone(), None, true, false).unwrap()
			})
			.collect(),
	}
}

/// Adds a block with a given reward to the chain and mines it
pub fn add_block_with_reward(chain: &Chain, txs: Vec<&Transaction>, reward: CbData) {
	let prev = chain.head_header().unwrap();
	let next_header_info = consensus::next_difficulty(1, chain.difficulty_iter().unwrap());
	let mut b = core::core::Block::new(
		&prev,
		txs.into_iter().cloned().collect(),
		next_header_info.clone().difficulty,
		(reward.output, reward.kernel),
	)
	.unwrap();
	b.header.timestamp = prev.timestamp + Duration::seconds(60);
	b.header.pow.secondary_scaling = next_header_info.secondary_scaling;
	chain.set_txhashset_roots(&mut b).unwrap();
	pow::pow_size(
		&mut b.header,
		next_header_info.difficulty,
		global::proofsize(),
		global::min_edge_bits(),
	)
	.unwrap();
	chain.process_block(b, chain::Options::MINE).unwrap();
	chain.validate(false).unwrap();
}

/// adds a reward output to a wallet, includes that reward in a block, mines
/// the block and adds it to the chain, with option transactions included.
/// Helpful for building up precise wallet balances for testing.
pub fn award_block_to_wallet<C, K>(
	chain: &Chain,
	txs: Vec<&Transaction>,
	wallet: Arc<Mutex<dyn WalletInst<C, K>>>,
) -> Result<(), libwallet::Error>
where
	C: NodeClient,
	K: keychain::Keychain,
{
	// build block fees
	let prev = chain.head_header().unwrap();
	let fee_amt = txs.iter().map(|tx| tx.fee()).sum();
	let block_fees = BlockFees {
		fees: fee_amt,
		key_id: None,
		height: prev.height + 1,
	};
	// build coinbase (via api) and add block
	let coinbase_tx = {
		let mut w = wallet.lock();
		w.open_with_credentials()?;
		let res = foreign::build_coinbase(&mut *w, &block_fees, false)?;
		w.close()?;
		res
	};
	add_block_with_reward(chain, txs, coinbase_tx.clone());
	Ok(())
}

/// Award a blocks to a wallet directly
pub fn award_blocks_to_wallet<C, K>(
	chain: &Chain,
	wallet: Arc<Mutex<dyn WalletInst<C, K>>>,
	number: usize,
	pause_between: bool,
) -> Result<(), libwallet::Error>
where
	C: NodeClient,
	K: keychain::Keychain,
{
	for _ in 0..number {
		award_block_to_wallet(chain, vec![], wallet.clone())?;
		if pause_between {
			thread::sleep(std::time::Duration::from_millis(100));
		}
	}
	Ok(())
}

/// dispatch a db wallet
pub fn create_wallet<C, K>(
	dir: &str,
	n_client: C,
	rec_phrase: Option<&str>,
) -> Arc<Mutex<dyn WalletInst<C, K>>>
where
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let z_string = match rec_phrase {
		Some(s) => Some(util::ZeroingString::from(s)),
		None => None,
	};
	let mut wallet_config = WalletConfig::default();
	wallet_config.data_file_dir = String::from(dir);
	let _ = WalletSeed::init_file(&wallet_config, 32, z_string, "");
	let mut wallet = LMDBBackend::new(wallet_config.clone(), "", n_client)
		.unwrap_or_else(|e| panic!("Error creating wallet: {:?} Config: {:?}", e, wallet_config));
	wallet.open_with_credentials().unwrap_or_else(|e| {
		panic!(
			"Error initializing wallet: {:?} Config: {:?}",
			e, wallet_config
		)
	});
	Arc::new(Mutex::new(wallet))
}

/// send an amount to a destination
pub fn send_to_dest<T: ?Sized, C, K>(
	wallet: Arc<Mutex<dyn WalletInst<C, K>>>,
	client: LocalWalletClient,
	dest: &str,
	amount: u64,
	test_mode: bool,
) -> Result<(), libwallet::Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: keychain::Keychain,
{
	let slate = {
		let mut w = wallet.lock();
		w.open_with_credentials()?;
		let args = InitTxArgs {
			src_acct_name: None,
			amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let slate_i = owner::init_send_tx(&mut *w, args, test_mode)?;
		let slate = client.send_tx_slate_direct(dest, &slate_i)?;
		owner::tx_lock_outputs(&mut *w, &slate, 0)?;
		let slate = owner::finalize_tx(&mut *w, &slate)?;
		w.close()?;
		slate
	};
	let client = {
		let mut w = wallet.lock();
		w.w2n_client().clone()
	};
	owner::post_tx(&client, &slate.tx, false)?; // mines a block
	Ok(())
}

/// get wallet info totals
pub fn wallet_info<T: ?Sized, C, K>(
	wallet: Arc<Mutex<dyn WalletInst<C, K>>>,
) -> Result<WalletInfo, libwallet::Error>
where
	T: WalletBackend<C, K>,
	C: NodeClient,
	K: keychain::Keychain,
{
	let mut w = wallet.lock();
	w.open_with_credentials()?;
	let (wallet_refreshed, wallet_info) = owner::retrieve_summary_info(&mut *w, true, 1)?;
	assert!(wallet_refreshed);
	w.close()?;
	Ok(wallet_info)
}
