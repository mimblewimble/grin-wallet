// Copyright 2018 The Grin Developers
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

//! Wallet seed encryption tests
extern crate grin_wallet_impls as impls;

use impls::{EncryptedWalletSeed, WalletSeed};

#[test]
fn wallet_seed_encrypt() {
	let password = "passwoid";
	let wallet_seed = WalletSeed::init_new(32);
	let mut enc_wallet_seed = EncryptedWalletSeed::from_seed(&wallet_seed, password).unwrap();
	println!("EWS: {:?}", enc_wallet_seed);
	let decrypted_wallet_seed = enc_wallet_seed.decrypt(password).unwrap();
	assert_eq!(wallet_seed, decrypted_wallet_seed);

	// Wrong password
	let decrypted_wallet_seed = enc_wallet_seed.decrypt("");
	assert!(decrypted_wallet_seed.is_err());

	// Wrong nonce
	enc_wallet_seed.nonce = "wrongnonce".to_owned();
	let decrypted_wallet_seed = enc_wallet_seed.decrypt(password);
	assert!(decrypted_wallet_seed.is_err());
}
