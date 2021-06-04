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

//! Transaction building functions

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;
use uuid::Uuid;

use crate::grin_core::consensus::valid_header_version;
use crate::grin_core::core::HeaderVersion;
use crate::grin_keychain::{Identifier, Keychain, SwitchCommitmentType};
use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::secp::pedersen;
use crate::grin_util::Mutex;
use crate::internal::{selection, updater};
use crate::slate::{Slate, TxFlow};
use crate::types::{Context, NodeClient, StoredProofInfo, TxLogEntryType, WalletBackend};
use crate::util::OnionV3Address;
use crate::InitTxArgs;
use crate::{address, Error, ErrorKind};
use ed25519_dalek::Keypair as DalekKeypair;
use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::SecretKey as DalekSecretKey;
use ed25519_dalek::Signature as DalekSignature;
use ed25519_dalek::{Signer, Verifier};
use grin_wallet_util::grin_core::core::FeeFields;

// static for incrementing test UUIDs
lazy_static! {
	static ref SLATE_COUNTER: Mutex<u8> = Mutex::new(0);
}

/// Creates a new slate for a transaction, can be called by anyone involved in
/// the transaction (sender(s), receiver(s))
pub fn new_tx_slate<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	amount: u64,
	tx_flow: TxFlow,
	num_participants: u8,
	use_test_rng: bool,
	ttl_blocks: Option<u64>,
) -> Result<Slate, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let current_height = wallet.w2n_client().get_chain_tip()?.0;
	let mut slate = Slate::blank(num_participants, tx_flow);
	if let Some(b) = ttl_blocks {
		slate.ttl_cutoff_height = current_height + b;
	}
	if use_test_rng {
		{
			let sc = SLATE_COUNTER.lock();
			let bytes = [4, 54, 67, 12, 43, 2, 98, 76, 32, 50, 87, 5, 1, 33, 43, *sc];
			slate.id = Uuid::from_slice(&bytes).unwrap();
		}
		*SLATE_COUNTER.lock() += 1;
	}
	slate.amount = amount;

	if valid_header_version(current_height, HeaderVersion(1)) {
		slate.version_info.block_header_version = 1;
	}

	if valid_header_version(current_height, HeaderVersion(2)) {
		slate.version_info.block_header_version = 2;
	}

	if valid_header_version(current_height, HeaderVersion(3)) {
		slate.version_info.block_header_version = 3;
	}

	// Set the features explicitly to 0 here.
	// This will generate a Plain kernel (rather than a HeightLocked kernel).
	slate.kernel_features = 0;

	Ok(slate)
}

/// Estimates locked amount and fee for the transaction without creating one
pub fn estimate_send_tx<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	amount: u64,
	minimum_confirmations: u64,
	max_outputs: usize,
	num_change_outputs: usize,
	selection_strategy_is_use_all: bool,
	parent_key_id: &Identifier,
) -> Result<
	(
		u64, // total
		u64, // fee
	),
	Error,
>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// Get lock height
	let current_height = wallet.w2n_client().get_chain_tip()?.0;
	// ensure outputs we're selecting are up to date
	updater::refresh_outputs(wallet, keychain_mask, parent_key_id, false)?;

	// Sender selects outputs into a new slate and save our corresponding keys in
	// a transaction context. The secret key in our transaction context will be
	// randomly selected. This returns the public slate, and a closure that locks
	// our inputs and outputs once we're convinced the transaction exchange went
	// according to plan
	// This function is just a big helper to do all of that, in theory
	// this process can be split up in any way
	let (_coins, total, _amount, fee) = selection::select_coins_and_fee(
		wallet,
		amount,
		current_height,
		minimum_confirmations,
		max_outputs,
		num_change_outputs,
		selection_strategy_is_use_all,
		parent_key_id,
	)?;
	Ok((total, fee))
}

/// Add inputs to the slate (effectively becoming the sender)
pub fn add_inputs_to_slate<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	current_height: u64,
	minimum_confirmations: u64,
	max_outputs: usize,
	num_change_outputs: usize,
	selection_strategy_is_use_all: bool,
	parent_key_id: &Identifier,
	is_initiator: bool,
	is_multisig: bool,
	use_test_rng: bool,
) -> Result<Context, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// sender should always refresh outputs
	updater::refresh_outputs(wallet, keychain_mask, parent_key_id, false)?;

	// Sender selects outputs into a new slate and save our corresponding keys in
	// a transaction context. The secret key in our transaction context will be
	// randomly selected. This returns the public slate, and a closure that locks
	// our inputs and outputs once we're convinced the transaction exchange went
	// according to plan
	// This function is just a big helper to do all of that, in theory
	// this process can be split up in any way
	let mut context = selection::build_send_tx(
		wallet,
		&wallet.keychain(keychain_mask)?,
		keychain_mask,
		slate,
		current_height,
		minimum_confirmations,
		max_outputs,
		num_change_outputs,
		selection_strategy_is_use_all,
		None,
		parent_key_id.clone(),
		use_test_rng,
		is_initiator,
	)?;

	if is_multisig {
		// calculate partial commit to the amount
		// used with receiver partial commit to calculate tau_one and tau_two in
		// multisig bulletproof step 1
		let k = wallet.keychain(keychain_mask)?;
		let key_id = slate.create_multisig_id();
		let partial_commit = k.commit(slate.amount, &key_id, SwitchCommitmentType::Regular)?;
		context.partial_commit = Some(partial_commit);
	}

	// Generate a kernel offset and subtract from our context's secret key. Store
	// the offset in the slate's transaction kernel, and adds our public key
	// information to the slate
	slate.fill_round_1(&wallet.keychain(keychain_mask)?, &mut context)?;

	context.initial_sec_key = context.sec_key.clone();

	if !is_initiator {
		// perform partial sig
		slate.fill_round_2(
			&wallet.keychain(keychain_mask)?,
			&context.sec_key,
			&context.sec_nonce,
		)?;
	}

	Ok(context)
}

/// Add receiver output to the slate
pub fn add_output_to_slate<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	current_height: u64,
	parent_key_id: &Identifier,
	is_initiator: bool,
	use_test_rng: bool,
) -> Result<Context, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let keychain = wallet.keychain(keychain_mask)?;
	// create an output using the amount in the slate
	let (_, mut context, mut tx) = selection::build_recipient_output(
		wallet,
		keychain_mask,
		slate,
		current_height,
		parent_key_id.clone(),
		use_test_rng,
		is_initiator,
	)?;

	// fill public keys
	slate.fill_round_1(&keychain, &mut context)?;

	context.initial_sec_key = context.sec_key.clone();

	let is_multisig = slate
		.participant_data
		.iter()
		.fold(false, |t, d| t | d.part_commit.is_some());

	if !is_initiator {
		// perform partial sig
		slate.fill_round_2(&keychain, &context.sec_key, &context.sec_nonce)?;
		// update excess in stored transaction
		let mut batch = wallet.batch(keychain_mask)?;
		tx.kernel_excess = Some(slate.calc_excess(keychain.secp())?);
		if is_multisig {
			batch.save_private_context(slate.id.as_bytes().as_ref(), &context)?;
		}
		batch.save_tx_log_entry(tx.clone(), &parent_key_id)?;
		batch.commit()?;
	}

	Ok(context)
}

/// Create context, without adding inputs to slate
pub fn create_late_lock_context<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	current_height: u64,
	init_tx_args: &InitTxArgs,
	parent_key_id: &Identifier,
	use_test_rng: bool,
) -> Result<Context, Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// sender should always refresh outputs
	updater::refresh_outputs(wallet, keychain_mask, parent_key_id, false)?;

	// we're just going to run a selection to get the potential fee,
	// but this won't be locked
	let (_coins, _total, _amount, fee) = selection::select_coins_and_fee(
		wallet,
		init_tx_args.amount,
		current_height,
		init_tx_args.minimum_confirmations,
		init_tx_args.max_outputs as usize,
		init_tx_args.num_change_outputs as usize,
		init_tx_args.selection_strategy_is_use_all,
		&parent_key_id,
	)?;
	slate.fee_fields = FeeFields::new(0, fee)?;

	let keychain = wallet.keychain(keychain_mask)?;

	// Create our own private context
	let mut context = Context::new(keychain.secp(), &parent_key_id, use_test_rng, true);
	context.fee = Some(slate.fee_fields);
	context.amount = slate.amount;
	context.late_lock_args = Some(init_tx_args.clone());

	if init_tx_args.is_multisig.unwrap_or(false) {
		// calculate partial commit to the amount
		// used with receiver partial commit to calculate tau_one and tau_two in
		// multisig bulletproof step 1
		let k = wallet.keychain(keychain_mask)?;
		let key_id = slate.create_multisig_id();
		let partial_commit = k.commit(slate.amount, &key_id, SwitchCommitmentType::Regular)?;
		context.partial_commit = Some(partial_commit);
	}

	// Generate a blinding factor for the tx and add
	//  public key info to the slate
	slate.fill_round_1(&wallet.keychain(keychain_mask)?, &mut context)?;

	Ok(context)
}

/// Complete a transaction
pub fn complete_tx<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	context: &Context,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// when self sending invoice tx, use initiator nonce to finalize
	let (sec_key, sec_nonce) = {
		if context.initial_sec_key != context.sec_key
			&& context.initial_sec_nonce != context.sec_nonce
		{
			(
				context.initial_sec_key.clone(),
				context.initial_sec_nonce.clone(),
			)
		} else {
			(context.sec_key.clone(), context.sec_nonce.clone())
		}
	};
	slate.fill_round_2(&wallet.keychain(keychain_mask)?, &sec_key, &sec_nonce)?;

	// Final transaction can be built by anyone at this stage
	trace!("Slate to finalize is: {}", slate);
	slate.finalize(&wallet.keychain(keychain_mask)?)?;
	Ok(())
}

/// Rollback outputs associated with a transaction in the wallet
pub fn cancel_tx<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	parent_key_id: &Identifier,
	tx_id: Option<u32>,
	tx_slate_id: Option<Uuid>,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let mut tx_id_string = String::new();
	if let Some(tx_id) = tx_id {
		tx_id_string = tx_id.to_string();
	} else if let Some(tx_slate_id) = tx_slate_id {
		tx_id_string = tx_slate_id.to_string();
	}
	let tx_vec = updater::retrieve_txs(wallet, tx_id, tx_slate_id, Some(&parent_key_id), false)?;
	if tx_vec.len() != 1 {
		return Err(ErrorKind::TransactionDoesntExist(tx_id_string).into());
	}
	let tx = tx_vec[0].clone();
	match tx.tx_type {
		TxLogEntryType::TxSent | TxLogEntryType::TxReceived | TxLogEntryType::TxReverted => {}
		_ => return Err(ErrorKind::TransactionNotCancellable(tx_id_string).into()),
	}
	if tx.confirmed {
		return Err(ErrorKind::TransactionNotCancellable(tx_id_string).into());
	}
	// get outputs associated with tx
	let res = updater::retrieve_outputs(
		wallet,
		keychain_mask,
		false,
		Some(tx.id),
		Some(&parent_key_id),
	)?;
	let outputs = res.iter().map(|m| m.output.clone()).collect();
	updater::cancel_tx_and_outputs(wallet, keychain_mask, tx, outputs, parent_key_id)?;
	Ok(())
}

/// Update the stored transaction (this update needs to happen when the TX is finalised)
pub fn update_stored_tx<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	context: &Context,
	slate: &Slate,
	is_invoiced: bool,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// finalize command
	let tx_vec = updater::retrieve_txs(wallet, None, Some(slate.id), None, false)?;
	let mut tx = None;
	// don't want to assume this is the right tx, in case of self-sending
	for t in tx_vec {
		if t.tx_type == TxLogEntryType::TxSent && !is_invoiced {
			tx = Some(t);
			break;
		}
		if t.tx_type == TxLogEntryType::TxReceived && is_invoiced {
			tx = Some(t);
			break;
		}
	}
	let mut tx = match tx {
		Some(t) => t,
		None => return Err(ErrorKind::TransactionDoesntExist(slate.id.to_string()).into()),
	};
	let parent_key = tx.parent_key_id.clone();
	{
		let keychain = wallet.keychain(keychain_mask)?;
		tx.kernel_excess = Some(slate.calc_excess(keychain.secp())?);
	}

	if let Some(ref p) = slate.clone().payment_proof {
		let derivation_index = match context.payment_proof_derivation_index {
			Some(i) => i,
			None => 0,
		};
		let keychain = wallet.keychain(keychain_mask)?;
		let parent_key_id = wallet.parent_key_id();
		let excess = slate.calc_excess(keychain.secp())?;
		let sender_key =
			address::address_from_derivation_path(&keychain, &parent_key_id, derivation_index)?;
		let sender_address = OnionV3Address::from_private(&sender_key.0)?;
		let sig =
			create_payment_proof_signature(slate.amount, &excess, p.sender_address, sender_key)?;
		tx.payment_proof = Some(StoredProofInfo {
			receiver_address: p.receiver_address,
			receiver_signature: p.receiver_signature,
			sender_address_path: derivation_index,
			sender_address: sender_address.to_ed25519()?,
			sender_signature: Some(sig),
		})
	}

	wallet.store_tx(&format!("{}", tx.tx_slate_id.unwrap()), slate.tx_or_err()?)?;

	let mut batch = wallet.batch(keychain_mask)?;
	batch.save_tx_log_entry(tx, &parent_key)?;
	batch.commit()?;
	Ok(())
}

pub fn payment_proof_message(
	amount: u64,
	kernel_commitment: &pedersen::Commitment,
	sender_address: DalekPublicKey,
) -> Result<Vec<u8>, Error> {
	let mut msg = Vec::new();
	msg.write_u64::<BigEndian>(amount)?;
	msg.append(&mut kernel_commitment.0.to_vec());
	msg.append(&mut sender_address.to_bytes().to_vec());
	Ok(msg)
}

pub fn _decode_payment_proof_message(
	msg: &[u8],
) -> Result<(u64, pedersen::Commitment, DalekPublicKey), Error> {
	let mut rdr = Cursor::new(msg);
	let amount = rdr.read_u64::<BigEndian>()?;
	let mut commit_bytes = [0u8; 33];
	for i in 0..33 {
		commit_bytes[i] = rdr.read_u8()?;
	}
	let mut sender_address_bytes = [0u8; 32];
	for i in 0..32 {
		sender_address_bytes[i] = rdr.read_u8()?;
	}

	Ok((
		amount,
		pedersen::Commitment::from_vec(commit_bytes.to_vec()),
		DalekPublicKey::from_bytes(&sender_address_bytes).unwrap(),
	))
}

/// create a payment proof
pub fn create_payment_proof_signature(
	amount: u64,
	kernel_commitment: &pedersen::Commitment,
	sender_address: DalekPublicKey,
	sec_key: SecretKey,
) -> Result<DalekSignature, Error> {
	let msg = payment_proof_message(amount, kernel_commitment, sender_address)?;
	let d_skey = match DalekSecretKey::from_bytes(&sec_key.0) {
		Ok(k) => k,
		Err(e) => {
			return Err(ErrorKind::ED25519Key(format!("{}", e)).into());
		}
	};
	let pub_key: DalekPublicKey = (&d_skey).into();
	let keypair = DalekKeypair {
		public: pub_key,
		secret: d_skey,
	};
	Ok(keypair.sign(&msg))
}

/// Verify all aspects of a completed payment proof on the current slate
pub fn verify_slate_payment_proof<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	parent_key_id: &Identifier,
	context: &Context,
	slate: &Slate,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	let tx_vec = updater::retrieve_txs(wallet, None, Some(slate.id), Some(parent_key_id), false)?;
	if tx_vec.is_empty() {
		return Err(ErrorKind::PaymentProof(
			"TxLogEntry with original proof info not found (is account correct?)".to_owned(),
		)
		.into());
	}

	let orig_proof_info = tx_vec[0].clone().payment_proof;

	if orig_proof_info.is_some() && slate.payment_proof.is_none() {
		return Err(ErrorKind::PaymentProof(
			"Expected Payment Proof for this Transaction is not present".to_owned(),
		)
		.into());
	}

	if let Some(ref p) = slate.clone().payment_proof {
		let orig_proof_info = match orig_proof_info {
			Some(p) => p.clone(),
			None => {
				return Err(ErrorKind::PaymentProof(
					"Original proof info not stored in tx".to_owned(),
				)
				.into());
			}
		};
		let keychain = wallet.keychain(keychain_mask)?;
		let index = match context.payment_proof_derivation_index {
			Some(i) => i,
			None => {
				return Err(ErrorKind::PaymentProof(
					"Payment proof derivation index required".to_owned(),
				)
				.into());
			}
		};
		let orig_sender_sk =
			address::address_from_derivation_path(&keychain, parent_key_id, index)?;
		let orig_sender_address = OnionV3Address::from_private(&orig_sender_sk.0)?;
		if p.sender_address != orig_sender_address.to_ed25519()? {
			return Err(ErrorKind::PaymentProof(
				"Sender address on slate does not match original sender address".to_owned(),
			)
			.into());
		}

		if orig_proof_info.receiver_address != p.receiver_address {
			return Err(ErrorKind::PaymentProof(
				"Recipient address on slate does not match original recipient address".to_owned(),
			)
			.into());
		}
		let msg = payment_proof_message(
			slate.amount,
			&slate.calc_excess(&keychain.secp())?,
			orig_sender_address.to_ed25519()?,
		)?;
		let sig = match p.receiver_signature {
			Some(s) => s,
			None => {
				return Err(ErrorKind::PaymentProof(
					"Recipient did not provide requested proof signature".to_owned(),
				)
				.into());
			}
		};

		if p.receiver_address.verify(&msg, &sig).is_err() {
			return Err(ErrorKind::PaymentProof("Invalid proof signature".to_owned()).into());
		};
	}
	Ok(())
}

#[cfg(test)]
mod test {
	use super::*;
	use rand::rngs::mock::StepRng;

	use crate::grin_core::core::{FeeFields, KernelFeatures};
	use crate::grin_core::libtx::{build, ProofBuilder};
	use crate::grin_keychain::{
		BlindSum, BlindingFactor, ExtKeychain, ExtKeychainPath, Keychain, SwitchCommitmentType,
	};
	use crate::grin_util::{secp, static_secp_instance};

	#[test]
	// demonstrate that input.commitment == referenced output.commitment
	// based on the public key and amount begin spent
	fn output_commitment_equals_input_commitment_on_spend() {
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let builder = ProofBuilder::new(&keychain);
		let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();

		let tx1 = build::transaction(
			KernelFeatures::Plain {
				fee: FeeFields::zero(),
			},
			&[build::output(105, key_id1.clone())],
			&keychain,
			&builder,
		)
		.unwrap();
		let tx2 = build::transaction(
			KernelFeatures::Plain {
				fee: FeeFields::zero(),
			},
			&[build::input(105, key_id1.clone())],
			&keychain,
			&builder,
		)
		.unwrap();

		let inputs: Vec<_> = tx2.inputs().into();
		assert_eq!(tx1.outputs()[0].commitment(), inputs[0].commitment());
	}

	#[test]
	fn payment_proof_construction() {
		let secp_inst = static_secp_instance();
		let secp = secp_inst.lock();
		let mut test_rng = StepRng::new(1_234_567_890_u64, 1);
		let sec_key = secp::key::SecretKey::new(&secp, &mut test_rng);
		let d_skey = DalekSecretKey::from_bytes(&sec_key.0).unwrap();

		let address: DalekPublicKey = (&d_skey).into();

		let kernel_excess = {
			ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
			let keychain = ExtKeychain::from_random_seed(true).unwrap();
			let switch = SwitchCommitmentType::Regular;
			let id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
			let id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0);
			let skey1 = keychain.derive_key(0, &id1, switch).unwrap();
			let skey2 = keychain.derive_key(0, &id2, switch).unwrap();
			let blinding_factor = keychain
				.blind_sum(
					&BlindSum::new()
						.sub_blinding_factor(BlindingFactor::from_secret_key(skey1))
						.add_blinding_factor(BlindingFactor::from_secret_key(skey2)),
				)
				.unwrap();
			keychain
				.secp()
				.commit(0, blinding_factor.secret_key(&keychain.secp()).unwrap())
				.unwrap()
		};

		let amount = 1_234_567_890_u64;
		let msg = payment_proof_message(amount, &kernel_excess, address).unwrap();
		println!("payment proof message is (len {}): {:?}", msg.len(), msg);

		let decoded = _decode_payment_proof_message(&msg).unwrap();
		assert_eq!(decoded.0, amount);
		assert_eq!(decoded.1, kernel_excess);
		assert_eq!(decoded.2, address);

		let sig = create_payment_proof_signature(amount, &kernel_excess, address, sec_key).unwrap();

		assert!(address.verify(&msg, &sig).is_ok());
	}
}
