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

use byteorder::{BigEndian, WriteBytesExt};
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use uuid::Uuid;

use crate::blake2::blake2b::{Blake2b, Blake2bResult};

use crate::{
	AcctPathMapping, Context, Error, NodeClient, OutputData, ScannedBlockInfo, TxLogEntry,
	WalletInitStatus,
};
use grin_core::core::Transaction;
use grin_core::ser;
use grin_keychain::{ChildNumber, ExtKeychain, Identifier, Keychain, SwitchCommitmentType};
use grin_store::{option_to_not_found, Store};
use grin_util::secp::constants::SECRET_KEY_SIZE;
use grin_util::secp::SecretKey;
use grin_util::ToHex;
use rand::rngs::mock::StepRng;
use rand::thread_rng;

pub const DB_DIR: &str = "db";
pub const TX_SAVE_DIR: &str = "saved_txs";

const OUTPUT_PREFIX: u8 = b'o';
const DERIV_PREFIX: u8 = b'd';
const CONFIRMED_HEIGHT_PREFIX: u8 = b'c';
const PRIVATE_TX_CONTEXT_PREFIX: u8 = b'p';
const TX_LOG_ENTRY_PREFIX: u8 = b't';
const TX_LOG_ID_PREFIX: u8 = b'i';
const ACCOUNT_PATH_MAPPING_PREFIX: u8 = b'a';
const LAST_SCANNED_BLOCK: u8 = b'l';
const LAST_SCANNED_KEY: &str = "LAST_SCANNED_KEY";
const WALLET_INIT_STATUS: u8 = b'w';
const WALLET_INIT_STATUS_KEY: &str = "WALLET_INIT_STATUS";

const DB_PREFIXES: [u8; 9] = [
	OUTPUT_PREFIX,
	DERIV_PREFIX,
	CONFIRMED_HEIGHT_PREFIX,
	PRIVATE_TX_CONTEXT_PREFIX,
	TX_LOG_ENTRY_PREFIX,
	TX_LOG_ID_PREFIX,
	ACCOUNT_PATH_MAPPING_PREFIX,
	LAST_SCANNED_BLOCK,
	WALLET_INIT_STATUS,
];

/// Helper to derive XOR keys for storing private transaction keys in the DB
/// (blind_xor_key, nonce_xor_key)
fn private_ctx_xor_keys<K>(
	keychain: &K,
	slate_id: &[u8],
) -> Result<([u8; SECRET_KEY_SIZE], [u8; SECRET_KEY_SIZE]), Error>
where
	K: Keychain,
{
	let root_key = keychain.derive_key(0, &K::root_key_id(), SwitchCommitmentType::Regular)?;

	// derive XOR values for storing secret values in DB
	// h(root_key|slate_id|"blind")
	let mut hasher = Blake2b::new(SECRET_KEY_SIZE);
	hasher.update(&root_key.0[..]);
	hasher.update(&slate_id[..]);
	hasher.update(&b"blind"[..]);
	let blind_xor_key = hasher.finalize();
	let mut ret_blind = [0; SECRET_KEY_SIZE];
	ret_blind.copy_from_slice(&blind_xor_key.as_bytes()[0..SECRET_KEY_SIZE]);

	// h(root_key|slate_id|"nonce")
	let mut hasher = Blake2b::new(SECRET_KEY_SIZE);
	hasher.update(&root_key.0[..]);
	hasher.update(&slate_id[..]);
	hasher.update(&b"nonce"[..]);
	let nonce_xor_key = hasher.finalize();
	let mut ret_nonce = [0; SECRET_KEY_SIZE];
	ret_nonce.copy_from_slice(&nonce_xor_key.as_bytes()[0..SECRET_KEY_SIZE]);

	Ok((ret_blind, ret_nonce))
}

/// Wallet backend. All functions here expect that the wallet instance
/// has instantiated itself or stored whatever credentials it needs.
pub struct WalletBackend<C, K>
where
	C: NodeClient,
	K: Keychain,
{
	db: Store,
	data_file_dir: String,
	/// Keychain
	pub keychain: Option<K>,
	/// Check value for XORed keychain seed
	pub master_checksum: Box<Option<Blake2bResult>>,
	/// Parent path to use by default for output operations
	parent_key_id: Identifier,
	/// wallet to node client
	w2n_client: C,
}

impl<C, K> WalletBackend<C, K>
where
	C: NodeClient,
	K: Keychain,
{
	/// Create new wallet backend.
	pub fn new(data_file_dir: &str, n_client: C) -> Result<Self, Error> {
		let db_path = Path::new(data_file_dir).join(DB_DIR);
		fs::create_dir_all(&db_path)?;

		let stored_tx_path = Path::new(data_file_dir).join(TX_SAVE_DIR);
		fs::create_dir_all(&stored_tx_path)?;

		let store = Store::new(
			db_path.to_str().unwrap(),
			None,
			Some(DB_DIR),
			DB_PREFIXES.to_vec(),
			None,
			None,
		)?;

		// Make sure default wallet derivation path always exists
		// as well as path (so it can be retrieved by batches to know where to store
		// completed transactions, for reference
		let default_account = AcctPathMapping {
			label: "default".to_owned(),
			path: WalletBackend::<C, K>::default_path(),
		};

		{
			let mut batch = store.batch()?;
			batch.put_ser(
				Some(ACCOUNT_PATH_MAPPING_PREFIX),
				default_account.label.as_bytes(),
				&default_account,
			)?;
			batch.commit()?;
		}

		let res = WalletBackend {
			db: store,
			data_file_dir: data_file_dir.to_owned(),
			keychain: None,
			master_checksum: Box::new(None),
			parent_key_id: WalletBackend::<C, K>::default_path(),
			w2n_client: n_client,
		};
		Ok(res)
	}

	/// Return the default parent wallet path, corresponding to the default account
	/// in the BIP32 spec. Parent is account 0 at level 2, child output identifiers
	/// are all at level 3.
	pub fn default_path() -> Identifier {
		ExtKeychain::derive_key_id(2, 0, 0, 0, 0)
	}

	/// Just test to see if database files exist in the current directory. If
	/// so, use a DB backend for all operations.
	pub fn exists(data_file_dir: &str) -> bool {
		let db_path = Path::new(data_file_dir).join(DB_DIR);
		db_path.exists()
	}

	/// Set the keychain, which should already be initialized
	/// Optionally return a token value used to XOR the stored
	/// key value
	pub fn set_keychain(
		&mut self,
		mut k: K,
		mask: bool,
		use_test_rng: bool,
	) -> Result<Option<SecretKey>, Error> {
		// store hash of master key, so it can be verified later after unmasking
		let root_key = k.derive_key(0, &K::root_key_id(), SwitchCommitmentType::Regular)?;
		let mut hasher = Blake2b::new(SECRET_KEY_SIZE);
		hasher.update(&root_key.0[..]);
		self.master_checksum = Box::new(Some(hasher.finalize()));

		let mask_value = {
			match mask {
				true => {
					// Random value that must be XORed against the stored wallet seed
					// before it is used
					let mask_value = match use_test_rng {
						true => {
							let mut test_rng = StepRng::new(1_234_567_890_u64, 1);
							SecretKey::new(&k.secp(), &mut test_rng)
						}
						false => SecretKey::new(&k.secp(), &mut thread_rng()),
					};
					k.mask_master_key(&mask_value)?;
					Some(mask_value)
				}
				false => None,
			}
		};

		self.keychain = Some(k);
		Ok(mask_value)
	}

	/// Close wallet by removing stored keychain.
	pub fn close(&mut self) -> Result<(), Error> {
		self.keychain = None;
		Ok(())
	}

	/// Return the keychain being used, cloned with XORed token value
	/// for temporary use
	/// Can optionally take a mask value
	pub fn keychain(&self, mask: Option<&SecretKey>) -> Result<K, Error> {
		match self.keychain.as_ref() {
			Some(k) => {
				let mut k_masked = k.clone();
				if let Some(m) = mask {
					k_masked.mask_master_key(m)?;
				}
				// Check if master seed is what is expected (especially if it's been xored)
				let root_key =
					k_masked.derive_key(0, &K::root_key_id(), SwitchCommitmentType::Regular)?;
				let mut hasher = Blake2b::new(SECRET_KEY_SIZE);
				hasher.update(&root_key.0[..]);
				if *self.master_checksum != Some(hasher.finalize()) {
					error!("Supplied keychain mask is invalid");
					return Err(Error::InvalidKeychainMask);
				}
				Ok(k_masked)
			}
			None => Err(Error::KeychainDoesntExist),
		}
	}

	/// Return the client being used to communicate with the node.
	pub fn w2n_client(&mut self) -> &mut C {
		&mut self.w2n_client
	}

	/// Return the version of the commit for caching if allowed.
	pub fn calc_commit_for_cache(
		&mut self,
		keychain_mask: Option<&SecretKey>,
		amount: u64,
		id: &Identifier,
	) -> Result<Option<String>, Error> {
		//TODO: Check if this is really necessary, it's the only thing
		//preventing removing the need for config in the wallet backend
		/*if self.config.no_commit_cache == Some(true) {
			Ok(None)
		} else {*/
		Ok(Some(
			self.keychain(keychain_mask)?
				.commit(amount, &id, SwitchCommitmentType::Regular)?
				.0
				.to_vec()
				.to_hex(), // TODO: proper support for different switch commitment schemes
		))
		/*}*/
	}

	/// Set parent key id by stored account name.
	pub fn set_parent_key_id_by_name(&mut self, label: &str) -> Result<(), Error> {
		let label = label.to_owned();
		let res = self.acct_path_iter()?.find(|l| l.label == label);
		if let Some(a) = res {
			self.set_parent_key_id(a.path);
			Ok(())
		} else {
			Err(Error::UnknownAccountLabel(label))
		}
	}

	/// The BIP32 path of the parent path to use for all output-related
	/// functions, essentially 'accounts' within a wallet.
	pub fn set_parent_key_id(&mut self, id: Identifier) {
		self.parent_key_id = id;
	}

	/// Get the parent path.
	pub fn parent_key_id(&mut self) -> Identifier {
		self.parent_key_id.clone()
	}

	/// Get output data by id.
	pub fn get(&self, id: &Identifier, mmr_index: &Option<u64>) -> Result<OutputData, Error> {
		let key = match mmr_index {
			Some(i) => to_key_u64(id.to_bytes(), *i),
			None => id.to_bytes().to_vec(),
		};
		option_to_not_found(self.db.get_ser(Some(OUTPUT_PREFIX), &key, None), || {
			format!("Key Id: {}", id)
		})
		.map_err(|e| e.into())
	}

	/// Iterate over all output data stored by the backend.
	pub fn iter(&self) -> Result<impl Iterator<Item = OutputData>, Error> {
		let protocol_version = self.db.protocol_version();
		let prefix_iter = self.db.iter(Some(OUTPUT_PREFIX), move |_, mut v| {
			ser::deserialize(
				&mut v,
				protocol_version,
				ser::DeserializationMode::default(),
			)
			.map_err(From::from)
		});
		let items: Vec<OutputData> = prefix_iter?.collect::<Result<Vec<_>, _>>()?;
		Ok(items.into_iter())
	}

	/// Get an (Optional) tx log entry by uuid.
	pub fn get_tx_log_entry(&self, u: &Uuid) -> Result<Option<TxLogEntry>, Error> {
		self.db
			.get_ser(Some(TX_LOG_ENTRY_PREFIX), u.as_bytes(), None)
			.map_err(|e| e.into())
	}

	/// Iterate over all tx log data stored by the backend.
	pub fn tx_log_iter(&self) -> Result<impl Iterator<Item = TxLogEntry>, Error> {
		let protocol_version = self.db.protocol_version();
		let prefix_iter = self.db.iter(Some(TX_LOG_ENTRY_PREFIX), move |_, mut v| {
			ser::deserialize(
				&mut v,
				protocol_version,
				ser::DeserializationMode::default(),
			)
			.map_err(From::from)
		});
		let items: Vec<TxLogEntry> = prefix_iter?.collect::<Result<Vec<_>, _>>()?;
		Ok(items.into_iter())
	}

	/// Retrieve the private context associated with a given slate id.
	pub fn get_private_context(
		&mut self,
		keychain_mask: Option<&SecretKey>,
		slate_id: &[u8],
	) -> Result<Context, Error> {
		let ctx_key = to_key_u64(slate_id, 0);
		let (blind_xor_key, nonce_xor_key) =
			private_ctx_xor_keys(&self.keychain(keychain_mask)?, slate_id)?;

		let mut ctx: Context = option_to_not_found(
			self.db
				.get_ser(Some(PRIVATE_TX_CONTEXT_PREFIX), &ctx_key, None),
			|| format!("Slate id: {:x?}", slate_id.to_vec()),
		)?;

		for i in 0..SECRET_KEY_SIZE {
			ctx.sec_key.0[i] ^= blind_xor_key[i];
			ctx.sec_nonce.0[i] ^= nonce_xor_key[i];
		}

		Ok(ctx)
	}

	/// Iterate over all stored account paths.
	pub fn acct_path_iter(&self) -> Result<impl Iterator<Item = AcctPathMapping>, Error> {
		let protocol_version = self.db.protocol_version();
		let prefix_iter = self
			.db
			.iter(Some(ACCOUNT_PATH_MAPPING_PREFIX), move |_, mut v| {
				ser::deserialize(
					&mut v,
					protocol_version,
					ser::DeserializationMode::default(),
				)
				.map_err(From::from)
			});
		let items: Vec<AcctPathMapping> = prefix_iter?.collect::<Result<Vec<_>, _>>()?;
		Ok(items.into_iter())
	}

	/// Gets an account path for a given label.
	pub fn get_acct_path(&self, label: String) -> Result<Option<AcctPathMapping>, Error> {
		self.db
			.get_ser(Some(ACCOUNT_PATH_MAPPING_PREFIX), label.as_bytes(), None)
			.map_err(|e| e.into())
	}

	/// Stores a transaction.
	pub fn store_tx(&self, uuid: &str, tx: &Transaction) -> Result<(), Error> {
		let filename = format!("{}.grintx", uuid);
		let path = Path::new(&self.data_file_dir)
			.join(TX_SAVE_DIR)
			.join(filename);
		let path_buf = Path::new(&path).to_path_buf();
		let mut stored_tx = File::create(path_buf)?;
		let tx_hex = ser::ser_vec(tx, ser::ProtocolVersion(1)).unwrap().to_hex();
		stored_tx.write_all(&tx_hex.as_bytes())?;
		stored_tx.sync_all()?;
		Ok(())
	}

	/// Retrieves a stored transaction.
	//TODO: Store content of .grintx file at TxLogEntry?
	pub fn get_stored_tx(&self, uuid: &str) -> Result<Option<Transaction>, Error> {
		let filename = format!("{}.grintx", uuid);
		let path = Path::new(&self.data_file_dir)
			.join(TX_SAVE_DIR)
			.join(filename);
		let tx_file = Path::new(&path).to_path_buf();
		let mut tx_f = File::open(tx_file)?;
		let mut content = String::new();
		tx_f.read_to_string(&mut content)?;
		let tx_bin = grin_util::from_hex(&content).unwrap();
		Ok(Some(
			ser::deserialize(
				&mut &tx_bin[..],
				ser::ProtocolVersion(1),
				ser::DeserializationMode::default(),
			)
			.unwrap(),
		))
	}

	/// Create a new write batch to update or remove output data.
	pub fn batch(
		&mut self,
		keychain_mask: Option<&SecretKey>,
	) -> Result<WalletBatch<'_, K>, Error> {
		Ok(WalletBatch {
			db: self.db.batch()?,
			keychain: Some(self.keychain(keychain_mask)?),
		})
	}

	/// Batch for use when keychain isn't available or required.
	pub fn batch_no_mask(&mut self) -> Result<WalletBatch<'_, K>, Error> {
		Ok(WalletBatch {
			db: self.db.batch()?,
			keychain: None,
		})
	}

	/// Return the current child index.
	pub fn current_child_index(&mut self, parent_key_id: &Identifier) -> Result<u32, Error> {
		let index = {
			let batch = self.db.batch()?;
			batch
				.get_ser(Some(DERIV_PREFIX), &parent_key_id.to_bytes(), None)?
				.unwrap_or_else(|| 0)
		};
		Ok(index)
	}

	/// Next child ID when we want to create a new output, based on current parent.
	pub fn next_child(&mut self, keychain_mask: Option<&SecretKey>) -> Result<Identifier, Error> {
		let parent_key_id = self.parent_key_id.clone();
		let mut deriv_idx = {
			let batch = self.db.batch()?;
			batch
				.get_ser(Some(DERIV_PREFIX), &self.parent_key_id.to_bytes(), None)?
				.unwrap_or_else(|| 0)
		};
		let mut return_path = self.parent_key_id.to_path();
		return_path.depth += 1;
		return_path.path[return_path.depth as usize - 1] = ChildNumber::from(deriv_idx);
		deriv_idx += 1;
		let mut batch = self.batch(keychain_mask)?;
		batch.save_child_index(&parent_key_id, deriv_idx)?;
		batch.commit()?;
		Ok(Identifier::from_path(&return_path))
	}

	/// Last verified height of outputs directly descending from the given parent key.
	pub fn last_confirmed_height(&mut self) -> Result<u64, Error> {
		let batch = self.db.batch()?;
		let last_confirmed_height = batch
			.get_ser(
				Some(CONFIRMED_HEIGHT_PREFIX),
				&self.parent_key_id.to_bytes(),
				None,
			)?
			.unwrap_or_else(|| 0);
		Ok(last_confirmed_height)
	}

	/// Last block scanned during scan or restore.
	pub fn last_scanned_block(&mut self) -> Result<ScannedBlockInfo, Error> {
		let batch = self.db.batch()?;
		let last_scanned_block = batch
			.get_ser(Some(LAST_SCANNED_BLOCK), LAST_SCANNED_KEY.as_bytes(), None)?
			.unwrap_or_else(|| ScannedBlockInfo {
				height: 0,
				hash: "".to_owned(),
				start_pmmr_index: 0,
				last_pmmr_index: 0,
			});
		Ok(last_scanned_block)
	}

	/// Flag whether the wallet needs a full UTXO scan on next update attempt.
	pub fn init_status(&mut self) -> Result<WalletInitStatus, Error> {
		let batch = self.db.batch()?;
		let status = batch
			.get_ser(
				Some(WALLET_INIT_STATUS),
				WALLET_INIT_STATUS_KEY.as_bytes(),
				None,
			)?
			.unwrap_or_else(|| WalletInitStatus::InitComplete);
		Ok(status)
	}
}

/// An atomic batch in which all changes can be committed all at once or
/// discarded on error.
pub struct WalletBatch<'a, K>
where
	K: Keychain,
{
	db: grin_store::Batch<'a>,
	/// Keychain
	keychain: Option<K>,
}

#[allow(missing_docs)]
impl<'a, K> WalletBatch<'a, K>
where
	K: Keychain,
{
	/// Return the keychain being used.
	pub fn keychain(&mut self) -> &mut K {
		self.keychain.as_mut().unwrap()
	}

	/// Add or update data about an output to the backend.
	pub fn save(&mut self, out: OutputData) -> Result<(), Error> {
		let key = match out.mmr_index {
			Some(i) => to_key_u64(out.key_id.to_bytes(), i),
			None => out.key_id.to_bytes().to_vec(),
		};
		self.db.put_ser(Some(OUTPUT_PREFIX), &key, &out)?;
		Ok(())
	}

	/// Gets output data by id
	pub fn get(&self, id: &Identifier, mmr_index: &Option<u64>) -> Result<OutputData, Error> {
		let key = match mmr_index {
			Some(i) => to_key_u64(id.to_bytes(), *i),
			None => id.to_bytes().to_vec(),
		};
		option_to_not_found(self.db.get_ser(Some(OUTPUT_PREFIX), &key, None), || {
			format!("Key ID: {}", id)
		})
		.map_err(|e| e.into())
	}

	/// Iterate over all output data stored by the backend.
	pub fn iter(&'a self) -> Result<impl Iterator<Item = OutputData> + 'a, Error> {
		let protocol_version = self.db.protocol_version();
		let prefix_iter = self.db.iter(Some(OUTPUT_PREFIX), move |_, mut v| {
			ser::deserialize(
				&mut v,
				protocol_version,
				ser::DeserializationMode::default(),
			)
			.map_err(From::from)
		});
		let items: Vec<OutputData> = prefix_iter?.collect::<Result<Vec<_>, _>>()?;
		Ok(items.into_iter())
	}

	/// Delete data about an output from the backend.
	pub fn delete(&mut self, id: &Identifier, mmr_index: &Option<u64>) -> Result<(), Error> {
		// Delete the output data.
		let key = match mmr_index {
			Some(i) => to_key_u64(id.to_bytes(), *i),
			None => id.to_bytes().to_vec(),
		};
		self.db.delete(Some(OUTPUT_PREFIX), &key)?;
		Ok(())
	}

	/// Save last stored child index of a given parent.
	pub fn save_child_index(&mut self, parent_id: &Identifier, child_n: u32) -> Result<(), Error> {
		self.db
			.put_ser(Some(DERIV_PREFIX), &parent_id.to_bytes(), &child_n)?;
		Ok(())
	}

	/// Save last confirmed height of outputs for a given parent.
	pub fn save_last_confirmed_height(
		&mut self,
		parent_key_id: &Identifier,
		height: u64,
	) -> Result<(), Error> {
		self.db.put_ser(
			Some(CONFIRMED_HEIGHT_PREFIX),
			&parent_key_id.to_bytes(),
			&height,
		)?;
		Ok(())
	}

	/// Save the last PMMR index that was scanned via a scan operation.
	pub fn save_last_scanned_block(&mut self, block_info: ScannedBlockInfo) -> Result<(), Error> {
		self.db.put_ser(
			Some(LAST_SCANNED_BLOCK),
			LAST_SCANNED_KEY.as_bytes(),
			&block_info,
		)?;
		Ok(())
	}

	/// Save flag indicating whether wallet needs a full UTXO scan.
	pub fn save_init_status(&mut self, value: WalletInitStatus) -> Result<(), Error> {
		self.db.put_ser(
			Some(WALLET_INIT_STATUS),
			WALLET_INIT_STATUS_KEY.as_bytes(),
			&value,
		)?;
		Ok(())
	}

	/// Get next transaction log entry for the parent.
	pub fn next_tx_log_id(&mut self, parent_key_id: &Identifier) -> Result<u32, Error> {
		let last_tx_log_id = self
			.db
			.get_ser(Some(TX_LOG_ID_PREFIX), &parent_key_id.to_bytes(), None)?
			.unwrap_or_else(|| 0);
		self.db.put_ser(
			Some(TX_LOG_ID_PREFIX),
			&parent_key_id.to_bytes(),
			&(last_tx_log_id + 1),
		)?;
		Ok(last_tx_log_id)
	}

	/// Iterate over transactions data stored by the backend.
	pub fn tx_log_iter(&'a self) -> Result<impl Iterator<Item = TxLogEntry> + 'a, Error> {
		let protocol_version = self.db.protocol_version();
		let prefix_iter = self.db.iter(Some(TX_LOG_ENTRY_PREFIX), move |_, mut v| {
			ser::deserialize(
				&mut v,
				protocol_version,
				ser::DeserializationMode::default(),
			)
			.map_err(From::from)
		});
		let items: Vec<TxLogEntry> = prefix_iter?.collect::<Result<Vec<_>, _>>()?;
		Ok(items.into_iter())
	}

	/// Save a transaction log entry.
	pub fn save_tx_log_entry(
		&mut self,
		tx_in: TxLogEntry,
		parent_id: &Identifier,
	) -> Result<(), Error> {
		let tx_log_key = to_key_u64(parent_id.to_bytes(), tx_in.id as u64);
		self.db
			.put_ser(Some(TX_LOG_ENTRY_PREFIX), &tx_log_key, &tx_in)?;
		Ok(())
	}

	/// Delete a transaction log entry.
	pub fn delete_tx_log_entry(&mut self, tx_id: u32, parent_id: &Identifier) -> Result<(), Error> {
		let tx_log_key = to_key_u64(parent_id.to_bytes(), tx_id as u64);
		self.db.delete(Some(TX_LOG_ENTRY_PREFIX), &tx_log_key)?;
		Ok(())
	}

	/// Save an account label -> path mapping.
	pub fn save_acct_path(&mut self, mapping: AcctPathMapping) -> Result<(), Error> {
		self.db.put_ser(
			Some(ACCOUNT_PATH_MAPPING_PREFIX),
			mapping.label.as_bytes(),
			&mapping,
		)?;
		Ok(())
	}

	/// Iterate over account names stored in backend.
	pub fn acct_path_iter(&'a self) -> Result<impl Iterator<Item = AcctPathMapping> + 'a, Error> {
		let protocol_version = self.db.protocol_version();
		let prefix_iter = self
			.db
			.iter(Some(ACCOUNT_PATH_MAPPING_PREFIX), move |_, mut v| {
				ser::deserialize(
					&mut v,
					protocol_version,
					ser::DeserializationMode::default(),
				)
				.map_err(From::from)
			});
		let items: Vec<AcctPathMapping> = prefix_iter?.collect::<Result<Vec<_>, _>>()?;
		Ok(items.into_iter())
	}

	/// Save an output as locked in the backend.
	pub fn lock_output(&mut self, out: &mut OutputData) -> Result<(), Error> {
		out.lock();
		self.save(out.clone())
	}

	/// Save the private context associated with a slate id.
	pub fn save_private_context(&mut self, slate_id: &[u8], ctx: &Context) -> Result<(), Error> {
		let ctx_key = to_key_u64(slate_id, 0);
		let (blind_xor_key, nonce_xor_key) = private_ctx_xor_keys(self.keychain(), slate_id)?;

		let mut s_ctx = ctx.clone();
		for i in 0..SECRET_KEY_SIZE {
			s_ctx.sec_key.0[i] ^= blind_xor_key[i];
			s_ctx.sec_nonce.0[i] ^= nonce_xor_key[i];
		}

		self.db
			.put_ser(Some(PRIVATE_TX_CONTEXT_PREFIX), &ctx_key, &s_ctx)?;
		Ok(())
	}

	/// Delete the private context associated with the slate id.
	pub fn delete_private_context(&mut self, slate_id: &[u8]) -> Result<(), Error> {
		let ctx_key = to_key_u64(slate_id, 0);
		self.db
			.delete(Some(PRIVATE_TX_CONTEXT_PREFIX), &ctx_key)
			.map_err(|e| e.into())
	}

	/// Write the wallet data to backend file.
	pub fn commit(self) -> Result<(), Error> {
		self.db.commit()?;
		Ok(())
	}
}

/// Build a db key from a byte vector identifier and numeric identifier
fn to_key_u64<K: AsRef<[u8]>>(k: K, val: u64) -> Vec<u8> {
	let mut res = k.as_ref().to_vec();
	res.write_u64::<BigEndian>(val).unwrap();
	res
}
