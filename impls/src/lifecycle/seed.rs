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

use core::num::NonZeroU32;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::path::MAIN_SEPARATOR;

use crate::blake2;
use rand::{thread_rng, Rng};
use serde_json;

use ring::aead;
use ring::pbkdf2;

use crate::keychain::{mnemonic, Keychain};
use crate::util::{self, ToHex};
use crate::Error;

pub const SEED_FILE: &str = "wallet.seed";

#[derive(Clone, Debug, PartialEq)]
pub struct WalletSeed(Vec<u8>);

impl WalletSeed {
	pub fn from_bytes(bytes: &[u8]) -> WalletSeed {
		WalletSeed(bytes.to_vec())
	}

	pub fn from_mnemonic(word_list: util::ZeroingString) -> Result<WalletSeed, Error> {
		let res = mnemonic::to_entropy(&word_list);
		match res {
			Ok(s) => Ok(WalletSeed::from_bytes(&s)),
			Err(_) => Err(Error::Mnemonic.into()),
		}
	}

	pub fn _from_hex(hex: &str) -> Result<WalletSeed, Error> {
		let bytes = util::from_hex(&hex.to_string())
			.map_err(|_| Error::GenericError("Invalid hex".to_owned()))?;
		Ok(WalletSeed::from_bytes(&bytes))
	}

	pub fn _to_hex(&self) -> String {
		self.0.to_vec().to_hex()
	}

	pub fn to_mnemonic(&self) -> Result<String, Error> {
		let result = mnemonic::from_entropy(&self.0);
		match result {
			Ok(r) => Ok(r),
			Err(_) => Err(Error::Mnemonic.into()),
		}
	}

	pub fn _derive_keychain_old(old_wallet_seed: [u8; 32], password: &str) -> Vec<u8> {
		let seed = blake2::blake2b::blake2b(64, password.as_bytes(), &old_wallet_seed);
		seed.as_bytes().to_vec()
	}

	pub fn derive_keychain<K: Keychain>(&self, is_testnet: bool) -> Result<K, Error> {
		let result = K::from_seed(&self.0, is_testnet)?;
		Ok(result)
	}

	pub fn init_new(
		seed_length: usize,
		test_mode: bool,
		password: Option<util::ZeroingString>,
	) -> WalletSeed {
		let mut seed: Vec<u8> = vec![];
		let mut rng = thread_rng();
		if !test_mode {
			for _ in 0..seed_length {
				seed.push(rng.gen());
			}
		} else {
			// Hash password and use for test seed so we have a way of keeping test wallets unique
			// but predictable
			seed = blake2::blake2b::blake2b(32, b"", password.unwrap().as_bytes())
				.as_bytes()
				.to_vec();
		}
		WalletSeed(seed)
	}

	pub fn seed_file_exists(data_file_dir: &str) -> Result<bool, Error> {
		let seed_file_path = &format!("{}{}{}", data_file_dir, MAIN_SEPARATOR, SEED_FILE,);
		debug!("Seed file path: {}", seed_file_path);
		if Path::new(seed_file_path).exists() {
			Ok(true)
		} else {
			Ok(false)
		}
	}

	pub fn backup_seed(data_file_dir: &str) -> Result<String, Error> {
		let seed_file_name = &format!("{}{}{}", data_file_dir, MAIN_SEPARATOR, SEED_FILE,);

		let mut path = Path::new(seed_file_name).to_path_buf();
		path.pop();
		let mut backup_seed_file_name =
			format!("{}{}{}.bak", data_file_dir, MAIN_SEPARATOR, SEED_FILE);
		let mut i = 1;
		while Path::new(&backup_seed_file_name).exists() {
			backup_seed_file_name =
				format!("{}{}{}.bak.{}", data_file_dir, MAIN_SEPARATOR, SEED_FILE, i);
			i += 1;
		}
		path.push(backup_seed_file_name.clone());
		if fs::rename(seed_file_name, backup_seed_file_name.as_str()).is_err() {
			return Err(Error::GenericError("Can't rename wallet seed file".to_owned()).into());
		}
		warn!("{} backed up as {}", seed_file_name, backup_seed_file_name);
		Ok(backup_seed_file_name)
	}

	pub fn recover_from_phrase(
		data_file_dir: &str,
		word_list: util::ZeroingString,
		password: util::ZeroingString,
	) -> Result<(), Error> {
		let seed_file_path = &format!("{}{}{}", data_file_dir, MAIN_SEPARATOR, SEED_FILE,);
		debug!("data file dir: {}", data_file_dir);
		if let Ok(true) = WalletSeed::seed_file_exists(data_file_dir) {
			debug!("seed file exists");
			WalletSeed::backup_seed(data_file_dir)?;
		}
		if !Path::new(&data_file_dir).exists() {
			return Err(Error::WalletDoesntExist(
				data_file_dir.to_owned(),
				"To create a new wallet from a recovery phrase, use 'grin-wallet init -r'"
					.to_owned(),
			)
			.into());
		}
		let seed = WalletSeed::from_mnemonic(word_list)?;
		let enc_seed = EncryptedWalletSeed::from_seed(&seed, password)?;
		let enc_seed_json = serde_json::to_string_pretty(&enc_seed).map_err(|_| Error::Format)?;
		let mut file = File::create(seed_file_path).map_err(|_| Error::IO)?;
		file.write_all(&enc_seed_json.as_bytes())
			.map_err(|_| Error::IO)?;
		warn!("Seed created from word list");
		Ok(())
	}

	pub fn init_file(
		data_file_dir: &str,
		seed_length: usize,
		recovery_phrase: Option<util::ZeroingString>,
		password: util::ZeroingString,
		test_mode: bool,
	) -> Result<WalletSeed, Error> {
		// create directory if it doesn't exist
		fs::create_dir_all(data_file_dir).map_err(|_| Error::IO)?;

		let seed_file_path = &format!("{}{}{}", data_file_dir, MAIN_SEPARATOR, SEED_FILE,);

		warn!("Generating wallet seed file at: {}", seed_file_path);
		let exists = WalletSeed::seed_file_exists(data_file_dir)?;
		if exists && !test_mode {
			let msg = format!("Wallet seed already exists at: {}", data_file_dir);
			error!("{}", msg);
			return Err(Error::WalletSeedExists(msg));
		}

		let seed = match recovery_phrase {
			Some(p) => WalletSeed::from_mnemonic(p)?,
			None => WalletSeed::init_new(seed_length, test_mode, Some(password.clone())),
		};

		let enc_seed = EncryptedWalletSeed::from_seed(&seed, password)?;
		let enc_seed_json = serde_json::to_string_pretty(&enc_seed).map_err(|_| Error::Format)?;
		let mut file = File::create(seed_file_path).map_err(|_| Error::IO)?;
		file.write_all(&enc_seed_json.as_bytes())
			.map_err(|_| Error::IO)?;
		Ok(seed)
	}

	pub fn from_file(
		data_file_dir: &str,
		password: util::ZeroingString,
	) -> Result<WalletSeed, Error> {
		// create directory if it doesn't exist
		fs::create_dir_all(data_file_dir).map_err(|_| Error::IO)?;

		let seed_file_path = &format!("{}{}{}", data_file_dir, MAIN_SEPARATOR, SEED_FILE,);

		debug!("Using wallet seed file at: {}", seed_file_path);

		if Path::new(seed_file_path).exists() {
			let mut file = File::open(seed_file_path).map_err(|_| Error::IO)?;
			let mut buffer = String::new();
			file.read_to_string(&mut buffer).map_err(|_| Error::IO)?;
			let enc_seed: EncryptedWalletSeed =
				serde_json::from_str(&buffer).map_err(|_| Error::Format)?;
			let wallet_seed = enc_seed.decrypt(&password)?;
			Ok(wallet_seed)
		} else {
			error!(
				"wallet seed file {} could not be opened (grin-wallet init). \
				 Run \"grin-wallet init\" to initialize a new wallet.",
				seed_file_path
			);
			Err(Error::WalletSeedDoesntExist)
		}
	}

	pub fn delete_seed_file(data_file_dir: &str) -> Result<(), Error> {
		let seed_file_path = &format!("{}{}{}", data_file_dir, MAIN_SEPARATOR, SEED_FILE,);
		if Path::new(seed_file_path).exists() {
			debug!("Deleting wallet seed file at: {}", seed_file_path);
			fs::remove_file(seed_file_path).map_err(|_| Error::IO)?;
		}
		Ok(())
	}
}

/// Encrypted wallet seed, for storing on disk and decrypting
/// with provided password

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EncryptedWalletSeed {
	encrypted_seed: String,
	/// Salt, not so useful in single case but include anyhow for situations
	/// where someone wants to store many of these
	pub salt: String,
	/// Nonce
	pub nonce: String,
}

impl EncryptedWalletSeed {
	/// Create a new encrypted seed from the given seed + password
	pub fn from_seed(
		seed: &WalletSeed,
		password: util::ZeroingString,
	) -> Result<EncryptedWalletSeed, Error> {
		let salt: [u8; 8] = thread_rng().gen();
		let nonce: [u8; 12] = thread_rng().gen();
		let password = password.as_bytes();
		let mut key = [0; 32];
		pbkdf2::derive(
			ring::pbkdf2::PBKDF2_HMAC_SHA512,
			NonZeroU32::new(100).unwrap(),
			&salt,
			password,
			&mut key,
		);
		let content = seed.0.to_vec();
		let mut enc_bytes = content;
		/*let suffix_len = aead::CHACHA20_POLY1305.tag_len();
		for _ in 0..suffix_len {
			enc_bytes.push(0);
		}*/
		let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap();
		let sealing_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let aad = aead::Aad::from(&[]);
		let res = sealing_key.seal_in_place_append_tag(
			aead::Nonce::assume_unique_for_key(nonce),
			aad,
			&mut enc_bytes,
		);
		if let Err(_) = res {
			return Err(Error::Encryption);
		}

		Ok(EncryptedWalletSeed {
			encrypted_seed: enc_bytes.to_hex(),
			salt: salt.to_hex(),
			nonce: nonce.to_hex(),
		})
	}

	/// Decrypt seed
	pub fn decrypt(&self, password: &str) -> Result<WalletSeed, Error> {
		let mut encrypted_seed = match util::from_hex(&self.encrypted_seed.clone()) {
			Ok(s) => s,
			Err(_) => return Err(Error::Encryption),
		};
		let salt = match util::from_hex(&self.salt.clone()) {
			Ok(s) => s,
			Err(_) => return Err(Error::Encryption),
		};
		let nonce = match util::from_hex(&self.nonce.clone()) {
			Ok(s) => s,
			Err(_) => return Err(Error::Encryption),
		};
		let password = password.as_bytes();
		let mut key = [0; 32];
		pbkdf2::derive(
			ring::pbkdf2::PBKDF2_HMAC_SHA512,
			NonZeroU32::new(100).unwrap(),
			&salt,
			password,
			&mut key,
		);

		let mut n = [0u8; 12];
		n.copy_from_slice(&nonce[0..12]);
		let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap();
		let opening_key: aead::LessSafeKey = aead::LessSafeKey::new(unbound_key);
		let aad = aead::Aad::from(&[]);
		let res = opening_key.open_in_place(
			aead::Nonce::assume_unique_for_key(n),
			aad,
			&mut encrypted_seed,
		);
		if let Err(_) = res {
			return Err(Error::Encryption);
		}
		for _ in 0..aead::AES_256_GCM.tag_len() {
			encrypted_seed.pop();
		}

		Ok(WalletSeed::from_bytes(&encrypted_seed))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::util::ZeroingString;
	#[test]
	fn wallet_seed_encrypt() {
		let password = ZeroingString::from("passwoid");
		let wallet_seed = WalletSeed::init_new(32, false, None);
		let mut enc_wallet_seed =
			EncryptedWalletSeed::from_seed(&wallet_seed, password.clone()).unwrap();
		println!("EWS: {:?}", enc_wallet_seed);
		let decrypted_wallet_seed = enc_wallet_seed.decrypt(&password).unwrap();
		assert_eq!(wallet_seed, decrypted_wallet_seed);

		// Wrong password
		let decrypted_wallet_seed = enc_wallet_seed.decrypt("");
		assert!(decrypted_wallet_seed.is_err());

		// Wrong nonce
		enc_wallet_seed.nonce = "wrongnonce".to_owned();
		let decrypted_wallet_seed = enc_wallet_seed.decrypt(&password);
		assert!(decrypted_wallet_seed.is_err());
	}
}
