// Copyright 2021 The Grin Developers
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

#[macro_use]
extern crate log;
extern crate grin_wallet_controller as wallet;
extern crate grin_wallet_impls as impls;
extern crate grin_wallet_util;

use grin_core::core::OutputFeatures;
use grin_keychain::{
	mnemonic, BlindingFactor, ExtKeychain, ExtKeychainPath, Keychain, SwitchCommitmentType,
};
use grin_util::{secp, ZeroingString};
use grin_wallet_libwallet as libwallet;
use impls::test_framework::LocalWalletClient;
use rand::{thread_rng, Rng};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{clean_output_dir, create_wallet_proxy, setup};

fn build_output_test_impl(test_dir: &'static str) -> Result<(), libwallet::Error> {
	// Generate seed so we can verify the blinding factor is derived correctly
	let seed: [u8; 32] = thread_rng().gen();
	let keychain = ExtKeychain::from_seed(&seed, false).unwrap();
	let mnemonic = mnemonic::from_entropy(&seed).unwrap();

	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let stopper = wallet_proxy.running.clone();

	create_wallet_and_add!(
		client1,
		wallet1,
		mask1_i,
		test_dir,
		"wallet1",
		Some(ZeroingString::from(mnemonic)),
		&mut wallet_proxy,
		false
	);

	let mask1 = (&mask1_i).as_ref();

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	let secp = secp::Secp256k1::with_caps(secp::ContextFlag::Commit);
	let features = OutputFeatures::Plain;
	let amount = 60_000_000_000;
	wallet::controller::owner_single_use(Some(wallet1.clone()), mask1, None, |sender_api, m| {
		let built_output = sender_api.build_output(m, features, amount)?;

		let key_id = built_output.key_id;
		assert_eq!(key_id.to_path(), ExtKeychainPath::new(3, 0, 0, 0, 0));

		let blind = built_output.blind;
		let key = keychain.derive_key(amount, &key_id, SwitchCommitmentType::Regular)?;
		assert_eq!(blind, BlindingFactor::from_secret_key(key.clone()));

		let output = built_output.output;
		assert_eq!(output.features(), features);
		assert_eq!(output.commitment(), secp.commit(amount, key)?);
		output.verify_proof()?;

		Ok(())
	})?;

	// let logging finish
	stopper.store(false, Ordering::Relaxed);
	thread::sleep(Duration::from_millis(200));
	Ok(())
}

#[test]
fn build_output() {
	let test_dir = "test_output/build_output";
	setup(test_dir);
	if let Err(e) = build_output_test_impl(test_dir) {
		panic!("Libwallet Error: {}", e);
	}
	clean_output_dir(test_dir);
}
