// Copyright 2021 The Grin Develope;
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

//! Generic implementation of owner API functions

use uuid::Uuid;

use crate::api_impl::foreign::finalize_tx as foreign_finalize;
use crate::grin_core::core::hash::Hashed;
use crate::grin_core::core::{FeeFields, Output, OutputFeatures, Transaction};
use crate::grin_core::libtx::proof;
use crate::grin_keychain::ViewKey;
use crate::grin_util::secp::{key::SecretKey, pedersen::Commitment};
use crate::grin_util::Mutex;
use crate::grin_util::ToHex;
use crate::util::{OnionV3Address, OnionV3AddressError};

use crate::api_impl::owner_updater::StatusMessage;
use crate::grin_keychain::{BlindingFactor, Identifier, Keychain, SwitchCommitmentType};
use crate::internal::{keys, scan, selection, tx, updater};
use crate::slate::{PaymentInfo, Slate, SlateState};
use crate::types::{AcctPathMapping, NodeClient, TxLogEntry, WalletBackend, WalletInfo};
use crate::Error;
use crate::{
	address,
	mwixnet::{create_onion, ComSignature, Hop, MixnetReqCreationParams, SwapReq},
	wallet_lock, BuiltOutput, InitTxArgs, IssueInvoiceTxArgs, NodeHeightResult,
	OutputCommitMapping, PaymentProof, RetrieveTxQueryArgs, ScannedBlockInfo, Slatepack,
	SlatepackAddress, Slatepacker, SlatepackerArgs, TxLogEntryType, ViewWallet, WalletInitStatus,
	WalletInst, WalletLCProvider,
};

use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::SecretKey as DalekSecretKey;
use ed25519_dalek::Verifier;
use x25519_dalek::{PublicKey as xPublicKey, StaticSecret};

use std::convert::{TryFrom, TryInto};
use std::sync::mpsc::Sender;
use std::sync::Arc;

/// List of accounts
pub fn accounts<'a, T: ?Sized, C, K>(w: &mut T) -> Result<Vec<AcctPathMapping>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	keys::accounts(&mut *w)
}

/// new account path
pub fn create_account_path<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	label: &str,
) -> Result<Identifier, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	keys::new_acct_path(&mut *w, keychain_mask, label)
}

/// set active account
pub fn set_active_account<'a, T: ?Sized, C, K>(w: &mut T, label: &str) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	w.set_parent_key_id_by_name(label)
}

/// Hash of the wallet root public key
pub fn get_rewind_hash<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
) -> Result<String, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	let keychain = w.keychain(keychain_mask)?;
	let root_public_key = keychain.public_root_key();
	let rewind_hash = ViewKey::rewind_hash(keychain.secp(), root_public_key).to_hex();
	Ok(rewind_hash)
}

/// Retrieve the slatepack address for the current parent key at
/// the given index
pub fn get_slatepack_address<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	index: u32,
) -> Result<SlatepackAddress, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	let parent_key_id = w.parent_key_id();
	let k = w.keychain(keychain_mask)?;
	let sec_addr_key = address::address_from_derivation_path(&k, &parent_key_id, index)?;
	SlatepackAddress::try_from(&sec_addr_key)
}

/// Retrieve the decryption key for the current parent key
/// the given index
pub fn get_slatepack_secret_key<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	index: u32,
) -> Result<DalekSecretKey, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	let parent_key_id = w.parent_key_id();
	let k = w.keychain(keychain_mask)?;
	let sec_addr_key = address::address_from_derivation_path(&k, &parent_key_id, index)?;
	let d_skey = match DalekSecretKey::from_bytes(&sec_addr_key.0) {
		Ok(k) => k,
		Err(e) => {
			return Err(OnionV3AddressError::InvalidPrivateKey(format!(
				"Unable to create secret key: {}",
				e
			))
			.into());
		}
	};
	Ok(d_skey)
}

/// Create a slatepack message from the given slate
pub fn create_slatepack_message<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	sender_index: Option<u32>,
	recipients: Vec<SlatepackAddress>,
) -> Result<String, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let sender = match sender_index {
		Some(i) => Some(get_slatepack_address(wallet_inst, keychain_mask, i)?),
		None => None,
	};
	let packer = Slatepacker::new(SlatepackerArgs {
		sender,
		recipients,
		dec_key: None,
	});
	let slatepack = packer.create_slatepack(slate)?;
	packer.armor_slatepack(&slatepack)
}

/// Unpack a slate from the given slatepack message,
/// optionally decrypting
pub fn slate_from_slatepack_message<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	slatepack: String,
	secret_indices: Vec<u32>,
) -> Result<Slate, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if secret_indices.is_empty() {
		let packer = Slatepacker::new(SlatepackerArgs {
			sender: None,
			recipients: vec![],
			dec_key: None,
		});
		let slatepack = packer.deser_slatepack(slatepack.as_bytes(), true)?;
		return packer.get_slate(&slatepack);
	} else {
		for index in secret_indices {
			let dec_key = Some(get_slatepack_secret_key(
				wallet_inst.clone(),
				keychain_mask,
				index,
			)?);
			let packer = Slatepacker::new(SlatepackerArgs {
				sender: None,
				recipients: vec![],
				dec_key: (&dec_key).as_ref(),
			});
			let res = packer.deser_slatepack(slatepack.as_bytes(), true);
			let slatepack = match res {
				Ok(sp) => sp,
				Err(_) => {
					continue;
				}
			};
			return packer.get_slate(&slatepack);
		}
		return Err(Error::SlatepackDecryption(
			"Could not decrypt slatepack with any provided index on the address derivation path"
				.to_owned(),
		)
		.into());
	}
}

/// Decode a slatepack message, to allow viewing
/// Will decrypt if possible, otherwise will return
/// undecrypted slatepack
pub fn decode_slatepack_message<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	slatepack: String,
	secret_indices: Vec<u32>,
) -> Result<Slatepack, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let packer = Slatepacker::new(SlatepackerArgs {
		sender: None,
		recipients: vec![],
		dec_key: None,
	});
	if secret_indices.is_empty() {
		packer.deser_slatepack(slatepack.as_bytes(), false)
	} else {
		for index in secret_indices {
			let dec_key = Some(get_slatepack_secret_key(
				wallet_inst.clone(),
				keychain_mask,
				index,
			)?);
			let packer = Slatepacker::new(SlatepackerArgs {
				sender: None,
				recipients: vec![],
				dec_key: (&dec_key).as_ref(),
			});
			let res = packer.deser_slatepack(slatepack.as_bytes(), true);
			let slatepack = match res {
				Ok(sp) => sp,
				Err(_) => {
					continue;
				}
			};
			return Ok(slatepack);
		}
		packer.deser_slatepack(slatepack.as_bytes(), false)
	}
}

/// retrieve outputs
pub fn retrieve_outputs<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	include_spent: bool,
	refresh_from_node: bool,
	tx_id: Option<u32>,
) -> Result<(bool, Vec<OutputCommitMapping>), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let validated = if refresh_from_node {
		update_wallet_state(
			wallet_inst.clone(),
			keychain_mask,
			status_send_channel,
			false,
		)?
	} else {
		false
	};

	wallet_lock!(wallet_inst, w);
	let parent_key_id = w.parent_key_id();

	Ok((
		validated,
		updater::retrieve_outputs(
			&mut **w,
			keychain_mask,
			include_spent,
			tx_id,
			Some(&parent_key_id),
		)?,
	))
}

/// Retrieve txs
pub fn retrieve_txs<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	refresh_from_node: bool,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
	query_args: Option<RetrieveTxQueryArgs>,
) -> Result<(bool, Vec<TxLogEntry>), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let validated = if refresh_from_node {
		update_wallet_state(
			wallet_inst.clone(),
			keychain_mask,
			status_send_channel,
			false,
		)?
	} else {
		false
	};

	wallet_lock!(wallet_inst, w);
	let parent_key_id = w.parent_key_id();
	let txs = updater::retrieve_txs(
		&mut **w,
		tx_id,
		tx_slate_id,
		query_args,
		Some(&parent_key_id),
		false,
	)?;

	Ok((validated, txs))
}

/// Retrieve summary info
pub fn retrieve_summary_info<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	refresh_from_node: bool,
	minimum_confirmations: u64,
) -> Result<(bool, WalletInfo), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let validated = if refresh_from_node {
		update_wallet_state(
			wallet_inst.clone(),
			keychain_mask,
			status_send_channel,
			false,
		)?
	} else {
		false
	};

	wallet_lock!(wallet_inst, w);
	let parent_key_id = w.parent_key_id();
	let wallet_info = updater::retrieve_info(&mut **w, &parent_key_id, minimum_confirmations)?;
	Ok((validated, wallet_info))
}

/// Retrieve payment proof
pub fn retrieve_payment_proof<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	refresh_from_node: bool,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
) -> Result<PaymentProof, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if tx_id.is_none() && tx_slate_id.is_none() {
		return Err(Error::PaymentProofRetrieval(
			"Transaction ID or Slate UUID must be specified".to_owned(),
		));
	}
	if refresh_from_node {
		update_wallet_state(
			wallet_inst.clone(),
			keychain_mask,
			status_send_channel,
			false,
		)?
	} else {
		false
	};
	let txs = retrieve_txs(
		wallet_inst.clone(),
		keychain_mask,
		status_send_channel,
		refresh_from_node,
		tx_id,
		tx_slate_id,
		None,
	)?;
	if txs.1.len() != 1 {
		return Err(Error::PaymentProofRetrieval(
			"Transaction doesn't exist".to_owned(),
		));
	}
	// Pull out all needed fields, returning an error if they're not present
	let tx = txs.1[0].clone();
	let proof = match tx.payment_proof {
		Some(p) => p,
		None => {
			return Err(Error::PaymentProofRetrieval(
				"Transaction does not contain a payment proof".to_owned(),
			));
		}
	};
	let amount = if tx.amount_credited >= tx.amount_debited {
		tx.amount_credited - tx.amount_debited
	} else {
		let fee = match tx.fee {
			Some(f) => f.fee(), // apply fee mask past HF4
			None => 0,
		};
		tx.amount_debited - tx.amount_credited - fee
	};
	let excess = match tx.kernel_excess {
		Some(e) => e,
		None => {
			return Err(Error::PaymentProofRetrieval(
				"Transaction does not contain kernel excess".to_owned(),
			));
		}
	};
	let r_sig = match proof.receiver_signature {
		Some(e) => e,
		None => {
			return Err(Error::PaymentProofRetrieval(
				"Proof does not contain receiver signature ".to_owned(),
			));
		}
	};
	let s_sig = match proof.sender_signature {
		Some(e) => e,
		None => {
			return Err(Error::PaymentProofRetrieval(
				"Proof does not contain sender signature ".to_owned(),
			));
		}
	};
	Ok(PaymentProof {
		amount: amount,
		excess: excess,
		recipient_address: SlatepackAddress::new(&proof.receiver_address),
		recipient_sig: r_sig,
		sender_address: SlatepackAddress::new(&proof.sender_address),
		sender_sig: s_sig,
	})
}

/// Initiate tx as sender
pub fn init_send_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	args: InitTxArgs,
	use_test_rng: bool,
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let parent_key_id = match &args.src_acct_name {
		Some(d) => {
			let pm = w.get_acct_path(d.clone())?;
			match pm {
				Some(p) => p.path,
				None => w.parent_key_id(),
			}
		}
		None => w.parent_key_id(),
	};

	let mut slate = tx::new_tx_slate(
		&mut *w,
		args.amount,
		false,
		2,
		use_test_rng,
		args.ttl_blocks,
	)?;

	if let Some(v) = args.target_slate_version {
		slate.version_info.version = v;
	};

	// if we just want to estimate, don't save a context, just send the results
	// back
	if let Some(true) = args.estimate_only {
		let (total, fee) = tx::estimate_send_tx(
			&mut *w,
			keychain_mask,
			args.amount,
			args.amount_includes_fee.unwrap_or(false),
			args.minimum_confirmations,
			args.max_outputs as usize,
			args.num_change_outputs as usize,
			args.selection_strategy_is_use_all,
			&parent_key_id,
		)?;
		slate.amount = total;
		slate.fee_fields = fee.try_into().unwrap();
		return Ok(slate);
	}

	let height = w.w2n_client().get_chain_tip()?.0;
	let mut context = if args.late_lock.unwrap_or(false) {
		tx::create_late_lock_context(
			&mut *w,
			keychain_mask,
			&mut slate,
			height,
			&args,
			&parent_key_id,
			use_test_rng,
		)?
	} else {
		tx::add_inputs_to_slate(
			&mut *w,
			keychain_mask,
			&mut slate,
			height,
			args.minimum_confirmations,
			args.max_outputs as usize,
			args.num_change_outputs as usize,
			args.selection_strategy_is_use_all,
			&parent_key_id,
			true,
			use_test_rng,
			args.amount_includes_fee.unwrap_or(false),
		)?
	};

	// Payment Proof, add addresses to slate and save address
	// TODO: Note we only use single derivation path for now,
	// probably want to allow sender to specify which one
	let deriv_path = 0u32;

	if let Some(a) = args.payment_proof_recipient_address {
		let k = w.keychain(keychain_mask)?;

		let sec_addr_key = address::address_from_derivation_path(&k, &parent_key_id, deriv_path)?;
		let sender_address = OnionV3Address::from_private(&sec_addr_key.0)?;

		slate.payment_proof = Some(PaymentInfo {
			sender_address: sender_address.to_ed25519()?,
			receiver_address: a.pub_key,
			receiver_signature: None,
		});

		context.payment_proof_derivation_index = Some(deriv_path);
	}

	// Save the aggsig context in our DB for when we
	// recieve the transaction back
	{
		let mut batch = w.batch(keychain_mask)?;
		batch.save_private_context(slate.id.as_bytes(), &context)?;
		batch.commit()?;
	}

	slate.compact()?;

	Ok(slate)
}

/// Initiate a transaction as the recipient (invoicing)
pub fn issue_invoice_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	args: IssueInvoiceTxArgs,
	use_test_rng: bool,
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let parent_key_id = match args.dest_acct_name {
		Some(d) => {
			let pm = w.get_acct_path(d)?;
			match pm {
				Some(p) => p.path,
				None => w.parent_key_id(),
			}
		}
		None => w.parent_key_id(),
	};

	let mut slate = tx::new_tx_slate(&mut *w, args.amount, true, 2, use_test_rng, None)?;
	let height = w.w2n_client().get_chain_tip()?.0;
	let context = tx::add_output_to_slate(
		&mut *w,
		keychain_mask,
		&mut slate,
		height,
		&parent_key_id,
		true,
		use_test_rng,
	)?;

	if let Some(v) = args.target_slate_version {
		slate.version_info.version = v;
	};

	// Save the aggsig context in our DB for when we
	// recieve the transaction back
	{
		let mut batch = w.batch(keychain_mask)?;
		batch.save_private_context(slate.id.as_bytes(), &context)?;
		batch.commit()?;
	}

	slate.compact()?;

	Ok(slate)
}

/// Receive an invoice tx, essentially adding inputs to whatever
/// output was specified
pub fn process_invoice_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	args: InitTxArgs,
	use_test_rng: bool,
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut ret_slate = slate.clone();
	check_ttl(w, &ret_slate)?;
	let parent_key_id = match args.src_acct_name {
		Some(d) => {
			let pm = w.get_acct_path(d)?;
			match pm {
				Some(p) => p.path,
				None => w.parent_key_id(),
			}
		}
		None => w.parent_key_id(),
	};
	// Don't do this multiple times
	let tx = updater::retrieve_txs(
		&mut *w,
		None,
		Some(ret_slate.id),
		None,
		Some(&parent_key_id),
		use_test_rng,
	)?;
	for t in &tx {
		if t.tx_type == TxLogEntryType::TxSent {
			return Err(Error::TransactionAlreadyReceived(ret_slate.id.to_string()));
		}
		if t.tx_type == TxLogEntryType::TxSentCancelled {
			return Err(Error::TransactionWasCancelled(ret_slate.id.to_string()));
		}
	}

	let height = w.w2n_client().get_chain_tip()?.0;

	// update ttl if desired
	if let Some(b) = args.ttl_blocks {
		ret_slate.ttl_cutoff_height = height + b;
	}

	// if this is compact mode, we need to create the transaction now
	ret_slate.tx = Some(Slate::empty_transaction());

	// if self sending, make sure to store 'initiator' keys
	let context_res = w.get_private_context(keychain_mask, slate.id.as_bytes());

	let mut context = tx::add_inputs_to_slate(
		&mut *w,
		keychain_mask,
		&mut ret_slate,
		height,
		args.minimum_confirmations,
		args.max_outputs as usize,
		args.num_change_outputs as usize,
		args.selection_strategy_is_use_all,
		&parent_key_id,
		false,
		use_test_rng,
		false,
	)?;

	let keychain = w.keychain(keychain_mask)?;

	// Add our contribution to the offset
	if context_res.is_ok() {
		// Self sending: don't correct for inputs and outputs
		// here, as we will do it during finalization.
		let mut tmp_context = context.clone();
		tmp_context.input_ids.clear();
		tmp_context.output_ids.clear();
		ret_slate.adjust_offset(&keychain, &tmp_context)?;
	} else {
		ret_slate.adjust_offset(&keychain, &context)?;
	}

	// needs to be stored as we're removing sig data for return trip. this needs to be present
	// when locking transaction context and updating tx log with excess later
	context.calculated_excess = Some(ret_slate.calc_excess(keychain.secp())?);

	// if self-sending, merge contexts
	if let Ok(c) = context_res {
		context.initial_sec_key = c.initial_sec_key;
		context.initial_sec_nonce = c.initial_sec_nonce;
		context.fee = c.fee;
		context.amount = c.amount;
		for o in c.output_ids.iter() {
			context.output_ids.push(o.clone());
		}
		for i in c.input_ids.iter() {
			context.input_ids.push(i.clone());
		}
	}

	selection::repopulate_tx(&mut *w, keychain_mask, &mut ret_slate, &context, false)?;

	// Save the aggsig context in our DB for when we
	// recieve the transaction back
	{
		let mut batch = w.batch(keychain_mask)?;
		batch.save_private_context(slate.id.as_bytes(), &context)?;
		batch.commit()?;
	}

	// Can remove amount as well as other sig data now
	ret_slate.amount = 0;
	ret_slate.remove_other_sigdata(&keychain, &context.sec_nonce, &context.sec_key)?;

	ret_slate.state = SlateState::Invoice2;
	Ok(ret_slate)
}

/// Lock sender outputs
pub fn tx_lock_outputs<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let context = w.get_private_context(keychain_mask, slate.id.as_bytes())?;
	let mut excess_override = None;

	let mut sl = slate.clone();

	if sl.tx == None {
		sl.tx = Some(Slate::empty_transaction());
		selection::repopulate_tx(&mut *w, keychain_mask, &mut sl, &context, true)?;
	}

	if slate.participant_data.len() == 1 {
		// purely for invoice workflow, payer needs the excess back temporarily for storage
		excess_override = context.calculated_excess;
	}

	let height = w.w2n_client().get_chain_tip()?.0;
	selection::lock_tx_context(
		&mut *w,
		keychain_mask,
		&sl,
		height,
		&context,
		excess_override,
	)
}

/// Finalize slate
pub fn finalize_tx<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	foreign_finalize(w, keychain_mask, slate, false)
}

/// cancel tx
pub fn cancel_tx<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	if !update_wallet_state(
		wallet_inst.clone(),
		keychain_mask,
		status_send_channel,
		false,
	)? {
		return Err(Error::TransactionCancellationError(
			"Can't contact running Grin node. Not Cancelling.",
		));
	}
	wallet_lock!(wallet_inst, w);
	let parent_key_id = w.parent_key_id();
	tx::cancel_tx(&mut **w, keychain_mask, &parent_key_id, tx_id, tx_slate_id)
}

/// get stored tx
/// crashes if stored tx has total fees exceeding 2^40 nanogrin
pub fn get_stored_tx<'a, T: ?Sized, C, K>(
	w: &T,
	tx_id: Option<u32>,
	slate_id: Option<&Uuid>,
) -> Result<Option<Slate>, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut uuid = None;
	if let Some(i) = tx_id {
		let tx = w.tx_log_iter().find(|t| t.id == i);
		if let Some(t) = tx {
			uuid = t.tx_slate_id;
		}
	}
	if uuid.is_none() {
		if let Some(sid) = slate_id {
			uuid = Some(sid.to_owned());
		}
	}
	let id = match uuid {
		Some(u) => u,
		None => {
			return Err(Error::StoredTx(
				"Both the provided Transaction Id and Slate UUID are invalid.".to_owned(),
			));
		}
	};
	let tx_res = w.get_stored_tx(&format!("{}", id))?;
	match tx_res {
		Some(tx) => {
			let mut slate = Slate::blank(2, false);
			slate.tx = Some(tx.clone());
			slate.fee_fields = tx.aggregate_fee_fields().unwrap(); // apply fee mask past HF4
			slate.id = id;
			slate.offset = tx.offset;
			slate.state = SlateState::Standard3;
			Ok(Some(slate))
		}
		None => Ok(None),
	}
}

/// Posts a transaction to the chain
/// take a client impl instead of wallet so as not to have to lock the wallet
pub fn post_tx<'a, C>(client: &C, tx: &Transaction, fluff: bool) -> Result<(), Error>
where
	C: NodeClient + 'a,
{
	let res = client.post_tx(tx, fluff);
	if let Err(e) = res {
		error!("api: post_tx: failed with error: {}", e);
		Err(e)
	} else {
		debug!(
			"api: post_tx: successfully posted tx: {}, fluff? {}",
			tx.hash(),
			fluff
		);
		Ok(())
	}
}

/// Scan outputs with the rewind hash of a third-party wallet.
/// Help to retrieve outputs information that belongs it
pub fn scan_rewind_hash<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	rewind_hash: String,
	start_height: Option<u64>,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<ViewWallet, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let is_hex = rewind_hash.chars().all(|c| c.is_ascii_hexdigit());
	let rewind_hash = rewind_hash.to_lowercase();
	if !(is_hex && rewind_hash.len() == 64) {
		let msg = format!("Invalid Rewind Hash");
		return Err(Error::RewindHash(msg));
	}

	let tip = {
		wallet_lock!(wallet_inst, w);
		w.w2n_client().get_chain_tip()?
	};

	let start_height = match start_height {
		Some(h) => h,
		None => 1,
	};

	let info = scan::scan_rewind_hash(
		wallet_inst,
		rewind_hash,
		start_height,
		tip.0,
		status_send_channel,
	)?;
	Ok(info)
}

/// check repair
/// Accepts a wallet inst instead of a raw wallet so it can
/// lock as little as possible
pub fn scan<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	start_height: Option<u64>,
	delete_unconfirmed: bool,
	status_send_channel: &Option<Sender<StatusMessage>>,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	update_outputs(wallet_inst.clone(), keychain_mask, true)?;
	let tip = {
		wallet_lock!(wallet_inst, w);
		w.w2n_client().get_chain_tip()?
	};

	let start_height = match start_height {
		Some(h) => h,
		None => 1,
	};

	let mut info = scan::scan(
		wallet_inst.clone(),
		keychain_mask,
		delete_unconfirmed,
		start_height,
		tip.0,
		status_send_channel,
	)?;
	info.hash = tip.1;

	wallet_lock!(wallet_inst, w);
	let mut batch = w.batch(keychain_mask)?;
	batch.save_last_scanned_block(info)?;
	batch.commit()?;

	Ok(())
}

/// node height
pub fn node_height<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
) -> Result<NodeHeightResult, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let res = {
		wallet_lock!(wallet_inst, w);
		w.w2n_client().get_chain_tip()
	};
	match res {
		Ok(r) => Ok(NodeHeightResult {
			height: r.0,
			header_hash: r.1,
			updated_from_node: true,
		}),
		Err(_) => {
			let outputs = retrieve_outputs(wallet_inst, keychain_mask, &None, true, false, None)?;
			let height = match outputs.1.iter().map(|m| m.output.height).max() {
				Some(height) => height,
				None => 0,
			};
			Ok(NodeHeightResult {
				height,
				header_hash: "".to_owned(),
				updated_from_node: false,
			})
		}
	}
}

/// Experimental, wrap the entire definition of how a wallet's state is updated
pub fn update_wallet_state<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	status_send_channel: &Option<Sender<StatusMessage>>,
	update_all: bool,
) -> Result<bool, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let parent_key_id = {
		wallet_lock!(wallet_inst, w);
		w.parent_key_id()
	};
	let client = {
		wallet_lock!(wallet_inst, w);
		w.w2n_client().clone()
	};

	// Step 1: Update outputs and transactions purely based on UTXO state
	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::UpdatingOutputs(
			"Updating outputs from node".to_owned(),
		));
	}
	let mut result = update_outputs(wallet_inst.clone(), keychain_mask, update_all)?;

	if !result {
		if let Some(ref s) = status_send_channel {
			let _ = s.send(StatusMessage::UpdateWarning(
				"Updater Thread unable to contact node".to_owned(),
			));
		}
		return Ok(result);
	}

	if let Some(ref s) = status_send_channel {
		let _ = s.send(StatusMessage::UpdatingTransactions(
			"Updating transactions".to_owned(),
		));
	}

	// Step 2: Update outstanding transactions with no change outputs by kernel
	let mut txs = {
		wallet_lock!(wallet_inst, w);
		updater::retrieve_txs(&mut **w, None, None, None, Some(&parent_key_id), true)?
	};
	result = update_txs_via_kernel(wallet_inst.clone(), keychain_mask, &mut txs)?;
	if !result {
		if let Some(ref s) = status_send_channel {
			let _ = s.send(StatusMessage::UpdateWarning(
				"Updater Thread unable to contact node".to_owned(),
			));
		}
		return Ok(result);
	}

	// Step 3: Scan back a bit on the chain
	let res = client.get_chain_tip();
	// if we can't get the tip, don't continue
	let tip = match res {
		Ok(t) => t,
		Err(_) => {
			if let Some(ref s) = status_send_channel {
				let _ = s.send(StatusMessage::UpdateWarning(
					"Updater Thread unable to contact node".to_owned(),
				));
			}
			return Ok(false);
		}
	};

	// Check if this is a restored wallet that needs a full scan
	let last_scanned_block = {
		wallet_lock!(wallet_inst, w);
		match w.init_status()? {
			WalletInitStatus::InitNeedsScanning => ScannedBlockInfo {
				height: 0,
				hash: "".to_owned(),
				start_pmmr_index: 0,
				last_pmmr_index: 0,
			},
			WalletInitStatus::InitNoScanning => ScannedBlockInfo {
				height: tip.clone().0,
				hash: tip.clone().1,
				start_pmmr_index: 0,
				last_pmmr_index: 0,
			},
			WalletInitStatus::InitComplete => w.last_scanned_block()?,
		}
	};

	let start_index = last_scanned_block.height.saturating_sub(100);

	if last_scanned_block.height == 0 {
		let msg = "This wallet has not been scanned against the current chain. Beginning full scan... (this first scan may take a while, but subsequent scans will be much quicker)".to_string();
		if let Some(ref s) = status_send_channel {
			let _ = s.send(StatusMessage::FullScanWarn(msg));
		}
	}

	let mut info = scan::scan(
		wallet_inst.clone(),
		keychain_mask,
		false,
		start_index,
		tip.0,
		status_send_channel,
	)?;

	info.hash = tip.1;

	{
		wallet_lock!(wallet_inst, w);
		let mut batch = w.batch(keychain_mask)?;
		batch.save_last_scanned_block(info)?;
		// init considered complete after first successful update
		batch.save_init_status(WalletInitStatus::InitComplete)?;
		batch.commit()?;
	}

	// Step 5: Cancel any transactions with an expired TTL
	for tx in txs {
		if let Some(e) = tx.ttl_cutoff_height {
			if tip.0 >= e {
				wallet_lock!(wallet_inst, w);
				let parent_key_id = w.parent_key_id();
				tx::cancel_tx(&mut **w, keychain_mask, &parent_key_id, Some(tx.id), None)?;
			}
		}
	}

	Ok(result)
}

/// Check TTL
pub fn check_ttl<'a, T: ?Sized, C, K>(w: &mut T, slate: &Slate) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Refuse if TTL is expired
	let last_confirmed_height = w.last_confirmed_height()?;
	if slate.ttl_cutoff_height != 0 {
		if last_confirmed_height >= slate.ttl_cutoff_height {
			return Err(Error::TransactionExpired);
		}
	}
	Ok(())
}

/// Verify/validate arbitrary payment proof
/// Returns (whether this wallet is the sender, whether this wallet is the recipient)
pub fn verify_payment_proof<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	proof: &PaymentProof,
) -> Result<(bool, bool), Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let sender_pubkey = proof.sender_address.pub_key;
	let msg = tx::payment_proof_message(proof.amount, &proof.excess, sender_pubkey)?;

	let (mut client, parent_key_id, keychain) = {
		wallet_lock!(wallet_inst, w);
		(
			w.w2n_client().clone(),
			w.parent_key_id(),
			w.keychain(keychain_mask)?,
		)
	};

	// Check kernel exists
	match client.get_kernel(&proof.excess, None, None) {
		Err(e) => {
			return Err(Error::PaymentProof(format!(
				"Error retrieving kernel from chain: {}",
				e
			)));
		}
		Ok(None) => {
			return Err(Error::PaymentProof(format!(
				"Transaction kernel with excess {:?} not found on chain",
				proof.excess
			)));
		}
		Ok(Some(_)) => {}
	};

	// Check Sigs
	let recipient_pubkey = proof.recipient_address.pub_key;
	if recipient_pubkey.verify(&msg, &proof.recipient_sig).is_err() {
		return Err(Error::PaymentProof(
			"Invalid recipient signature".to_owned(),
		));
	};

	let sender_pubkey = proof.sender_address.pub_key;
	if sender_pubkey.verify(&msg, &proof.sender_sig).is_err() {
		return Err(Error::PaymentProof("Invalid sender signature".to_owned()));
	};

	// for now, simple test as to whether one of the addresses belongs to this wallet
	let sec_key = address::address_from_derivation_path(&keychain, &parent_key_id, 0)?;
	let d_skey = match DalekSecretKey::from_bytes(&sec_key.0) {
		Ok(k) => k,
		Err(e) => {
			return Err(Error::ED25519Key(format!("{}", e)));
		}
	};
	let my_address_pubkey: DalekPublicKey = (&d_skey).into();

	let sender_mine = my_address_pubkey == sender_pubkey;
	let recipient_mine = my_address_pubkey == recipient_pubkey;

	Ok((sender_mine, recipient_mine))
}

/// Attempt to update outputs in wallet, return whether it was successful
fn update_outputs<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	update_all: bool,
) -> Result<bool, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	wallet_lock!(wallet_inst, w);
	let parent_key_id = w.parent_key_id();
	match updater::refresh_outputs(&mut **w, keychain_mask, &parent_key_id, update_all) {
		Ok(_) => Ok(true),
		Err(e) => {
			if let Error::InvalidKeychainMask = e {
				return Err(e);
			}
			Ok(false)
		}
	}
}

/// Update transactions that need to be validated via kernel lookup
fn update_txs_via_kernel<'a, L, C, K>(
	wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<&SecretKey>,
	txs: &mut Vec<TxLogEntry>,
) -> Result<bool, Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let parent_key_id = {
		wallet_lock!(wallet_inst, w);
		w.parent_key_id()
	};

	let mut client = {
		wallet_lock!(wallet_inst, w);
		w.w2n_client().clone()
	};

	let height = match client.get_chain_tip() {
		Ok(h) => h.0,
		Err(_) => return Ok(false),
	};

	for tx in txs.iter_mut() {
		if tx.confirmed {
			continue;
		}
		if tx.amount_debited != 0 && tx.amount_credited != 0 {
			continue;
		}
		if let Some(e) = tx.kernel_excess {
			let res = client.get_kernel(&e, tx.kernel_lookup_min_height, Some(height));
			let kernel = match res {
				Ok(k) => k,
				Err(_) => return Ok(false),
			};
			if let Some(k) = kernel {
				debug!("Kernel Retrieved: {:?}", k);
				wallet_lock!(wallet_inst, w);
				let mut batch = w.batch(keychain_mask)?;
				tx.confirmed = true;
				tx.update_confirmation_ts();
				batch.save_tx_log_entry(tx.clone(), &parent_key_id)?;
				batch.commit()?;
			}
		} else {
			warn!("Attempted to update via kernel excess for transaction {:?}, but kernel excess was not stored", tx.tx_slate_id);
		}
	}
	Ok(true)
}

/// Builds an output for the wallet's next available key
pub fn build_output<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	features: OutputFeatures,
	amount: u64,
) -> Result<BuiltOutput, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let k = w.keychain(keychain_mask)?;

	let key_id = keys::next_available_key(&mut *w, keychain_mask)?;

	let blind = k.derive_key(amount, &key_id, SwitchCommitmentType::Regular)?;
	let commit = k.secp().commit(amount, blind.clone())?;

	let proof_builder = proof::ProofBuilder::new(&k);
	let proof = proof::create(
		&k,
		&proof_builder,
		amount,
		&key_id,
		SwitchCommitmentType::Regular,
		commit,
		None,
	)?;

	let output = Output::new(features, commit, proof);

	Ok(BuiltOutput {
		blind: BlindingFactor::from_secret_key(blind),
		key_id: key_id,
		output: output,
	})
}

/// Create MXMixnet request
pub fn create_mwixnet_req<'a, T: ?Sized, C, K>(
	w: &mut T,
	keychain_mask: Option<&SecretKey>,
	params: &MixnetReqCreationParams,
	commitment: &Commitment,
	lock_output: bool,
	use_test_rng: bool,
) -> Result<SwapReq, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let parent_key_id = w.parent_key_id();
	let keychain = w.keychain(keychain_mask)?;
	let outputs = updater::retrieve_outputs(w, keychain_mask, false, None, Some(&parent_key_id))?;

	let mut output = None;
	for o in &outputs {
		if o.commit == *commitment {
			output = Some(o.output.clone());
			break;
		}
	}

	if output.is_none() {
		return Err(Error::GenericError(String::from("output not found")));
	}

	let amount = output.clone().unwrap().value;
	let input_blind = keychain.derive_key(
		amount,
		&output.clone().unwrap().key_id,
		SwitchCommitmentType::Regular,
	)?;

	let mut server_pubkeys = vec![];
	for i in 0..params.server_keys.len() {
		server_pubkeys.push(xPublicKey::from(&StaticSecret::from(
			params.server_keys[i].0,
		)));
	}

	let fee = grin_core::libtx::tx_fee(1, 1, 1);
	let new_amount = amount - (fee * server_pubkeys.len() as u64);
	let new_output = build_output(w, keychain_mask, OutputFeatures::Plain, new_amount)?;
	let secp = keychain.secp();

	let mut blind_sum = new_output
		.blind
		.split(&BlindingFactor::from_secret_key(input_blind.clone()), &secp)?;

	let hops = server_pubkeys
		.iter()
		.enumerate()
		.map(|(i, &p)| {
			if (i + 1) == server_pubkeys.len() {
				Hop {
					server_pubkey: p.clone(),
					excess: blind_sum.secret_key(&secp).unwrap(),
					fee: FeeFields::from(fee as u32),
					rangeproof: Some(new_output.output.proof.clone()),
				}
			} else {
				let hop_excess;
				if use_test_rng {
					hop_excess = BlindingFactor::zero();
				} else {
					hop_excess = BlindingFactor::rand(&secp);
				}
				blind_sum = blind_sum.split(&hop_excess, &secp).unwrap();
				Hop {
					server_pubkey: p.clone(),
					excess: hop_excess.secret_key(&secp).unwrap(),
					fee: FeeFields::from(fee as u32),
					rangeproof: None,
				}
			}
		})
		.collect();

	let onion = create_onion(&commitment, &hops, use_test_rng).unwrap();
	let comsig = ComSignature::sign(
		amount,
		&input_blind,
		&onion.serialize().unwrap(),
		use_test_rng,
	)
	.unwrap();

	// Lock output if requested
	if lock_output {
		let mut batch = w.batch(keychain_mask)?;
		let mut update_output = batch.get(&output.as_ref().unwrap().key_id, &None)?;
		update_output.lock();
		batch.lock_output(&mut update_output)?;
		batch.commit()?;
	}

	Ok(SwapReq { comsig, onion })
}
