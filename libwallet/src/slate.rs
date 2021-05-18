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

//! Functions for building partial transactions to be passed
//! around during an interactive wallet exchange

use crate::error::{Error, ErrorKind};
use crate::grin_core::core::amount_to_hr_string;
use crate::grin_core::core::transaction::{
	FeeFields, Input, Inputs, KernelFeatures, NRDRelativeHeight, Output, OutputFeatures,
	Transaction, TxKernel, Weighting,
};
use crate::grin_core::libtx::{aggsig, build, proof::ProofBuild, tx_fee};
use crate::grin_core::map_vec;
use crate::grin_keychain::{BlindSum, BlindingFactor, Keychain, SwitchCommitmentType};
use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::grin_util::secp::pedersen::Commitment;
use crate::grin_util::secp::Signature;
use crate::grin_util::{secp, static_secp_instance};
use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::Signature as DalekSignature;
use serde::ser::{Serialize, Serializer};
use serde_json;
use std::fmt;
use uuid::Uuid;

use crate::slate_versions::v4::{
	CommitsV4, KernelFeaturesArgsV4, OutputFeaturesV4, ParticipantDataV4, PaymentInfoV4,
	SlateStateV4, SlateV4, VersionCompatInfoV4,
};
use crate::slate_versions::VersionedSlate;
use crate::slate_versions::{CURRENT_SLATE_VERSION, GRIN_BLOCK_HEADER_VERSION};
use crate::Context;

#[derive(Debug, Clone)]
pub struct PaymentInfo {
	/// Sender address
	pub sender_address: DalekPublicKey,
	/// Receiver address
	pub receiver_address: DalekPublicKey,
	/// Receiver signature
	pub receiver_signature: Option<DalekSignature>,
}

/// Public data for each participant in the slate
#[derive(Debug, Clone)]
pub struct ParticipantData {
	/// Public key corresponding to private blinding factor
	pub public_blind_excess: PublicKey,
	/// Public key corresponding to private nonce
	pub public_nonce: PublicKey,
	/// Public partial signature
	pub part_sig: Option<Signature>,
}

impl ParticipantData {
	/// A helper to return whether this participant
	/// has completed round 1 and round 2;
	/// Round 1 has to be completed before instantiation of this struct
	/// anyhow, and for each participant consists of:
	/// -Inputs added to transaction
	/// -Outputs added to transaction
	/// -Public signature nonce chosen and added
	/// -Public contribution to blinding factor chosen and added
	/// Round 2 can only be completed after all participants have
	/// performed round 1, and adds:
	/// -Part sig is filled out
	pub fn is_complete(&self) -> bool {
		self.part_sig.is_some()
	}
}

/// A 'Slate' is passed around to all parties to build up all of the public
/// transaction data needed to create a finalized transaction. Callers can pass
/// the slate around by whatever means they choose, (but we can provide some
/// binary or JSON serialization helpers here).

#[derive(Debug, Clone)]
pub struct Slate {
	/// Versioning info
	pub version_info: VersionCompatInfo,
	/// The number of participants intended to take part in this transaction
	pub num_participants: u8,
	/// Unique transaction ID, selected by sender
	pub id: Uuid,
	/// Slate state
	pub state: SlateState,
	/// The core transaction data:
	/// inputs, outputs, kernels, kernel offset
	/// Optional as of V4 to allow for a compact
	/// transaction initiation
	pub tx: Option<Transaction>,
	/// base amount (excluding fee)
	pub amount: u64,
	/// fee amount and shift
	pub fee_fields: FeeFields,
	/// TTL, the block height at which wallets
	/// should refuse to process the transaction and unlock all
	/// associated outputs
	pub ttl_cutoff_height: u64,
	/// Kernel Features flag -
	/// 	0: plain
	/// 	1: coinbase (invalid)
	/// 	2: height_locked
	/// 	3: NRD
	pub kernel_features: u8,
	/// Offset, needed when posting of transasction is deferred
	pub offset: BlindingFactor,
	/// Participant data, each participant in the transaction will
	/// insert their public data here. For now, 0 is sender and 1
	/// is receiver, though this will change for multi-party
	pub participant_data: Vec<ParticipantData>,
	/// Payment Proof
	pub payment_proof: Option<PaymentInfo>,
	/// Kernel features arguments
	pub kernel_features_args: Option<KernelFeaturesArgs>,
}

impl fmt::Display for Slate {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", serde_json::to_string_pretty(&self).unwrap())
	}
}

/// Slate state definition
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlateState {
	/// Unknown, coming from earlier slate versions
	Unknown,
	/// Standard flow, freshly init
	Standard1,
	/// Standard flow, return journey
	Standard2,
	/// Standard flow, ready for transaction posting
	Standard3,
	/// Invoice flow, freshly init
	Invoice1,
	///Invoice flow, return journey
	Invoice2,
	/// Invoice flow, ready for tranasction posting
	Invoice3,
}

impl fmt::Display for SlateState {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let res = match self {
			SlateState::Unknown => "UN",
			SlateState::Standard1 => "S1",
			SlateState::Standard2 => "S2",
			SlateState::Standard3 => "S3",
			SlateState::Invoice1 => "I1",
			SlateState::Invoice2 => "I2",
			SlateState::Invoice3 => "I3",
		};
		write!(f, "{}", res)
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Kernel features arguments definition
pub struct KernelFeaturesArgs {
	/// Lock height, for HeightLocked (also NRD relative lock height)
	pub lock_height: u64,
}

impl Default for KernelFeaturesArgs {
	fn default() -> KernelFeaturesArgs {
		KernelFeaturesArgs { lock_height: 0 }
	}
}

/// Versioning and compatibility info about this slate
#[derive(Debug, Clone)]
pub struct VersionCompatInfo {
	/// The current version of the slate format
	pub version: u16,
	/// The grin block header version this slate is intended for
	pub block_header_version: u16,
}

impl Slate {
	/// Return the transaction, throwing an error if it doesn't exist
	/// to be used at points in the code where the existence of a transaction
	/// is assumed
	pub fn tx_or_err(&self) -> Result<&Transaction, Error> {
		match &self.tx {
			Some(t) => Ok(t),
			None => Err(ErrorKind::SlateTransactionRequired.into()),
		}
	}

	/// As above, but return mutable reference
	pub fn tx_or_err_mut(&mut self) -> Result<&mut Transaction, Error> {
		match &mut self.tx {
			Some(t) => Ok(t),
			None => Err(ErrorKind::SlateTransactionRequired.into()),
		}
	}

	/// number of participants
	pub fn num_participants(&self) -> u8 {
		match self.num_participants {
			0 => 2,
			n => n,
		}
	}

	/// Recieve a slate, upgrade it to the latest version internally
	/// Throw error if this can't be done
	pub fn deserialize_upgrade(slate_json: &str) -> Result<Slate, Error> {
		let v_slate: VersionedSlate =
			serde_json::from_str(slate_json).map_err(|_| ErrorKind::SlateVersionParse)?;
		Slate::upgrade(v_slate)
	}

	/// Upgrade a versioned slate
	pub fn upgrade(v_slate: VersionedSlate) -> Result<Slate, Error> {
		let v4: SlateV4 = match v_slate {
			VersionedSlate::V4(s) => s,
		};
		Ok(v4.into())
	}
	/// Compact the slate for initial sending, storing the excess + offset explicit
	/// and removing my input/output data
	/// This info must be stored in the context for repopulation later
	pub fn compact(&mut self) -> Result<(), Error> {
		self.tx = None;
		Ok(())
	}

	/// Build a new empty transaction.
	/// Wallet currently only supports tx with "features and commit" inputs.
	pub fn empty_transaction() -> Transaction {
		let mut tx = Transaction::empty();
		tx.body = tx.body.replace_inputs(Inputs::FeaturesAndCommit(vec![]));
		tx
	}

	/// Create a new slate
	pub fn blank(num_participants: u8, is_invoice: bool) -> Slate {
		let np = match num_participants {
			0 => 2,
			n => n,
		};
		let state = match is_invoice {
			true => SlateState::Invoice1,
			false => SlateState::Standard1,
		};
		Slate {
			num_participants: np, // assume 2 if not present
			id: Uuid::new_v4(),
			state,
			tx: Some(Slate::empty_transaction()),
			amount: 0,
			fee_fields: FeeFields::zero(),
			ttl_cutoff_height: 0,
			kernel_features: 0,
			offset: BlindingFactor::zero(),
			participant_data: vec![],
			version_info: VersionCompatInfo {
				version: CURRENT_SLATE_VERSION,
				block_header_version: GRIN_BLOCK_HEADER_VERSION,
			},
			payment_proof: None,
			kernel_features_args: None,
		}
	}
	/// Removes any signature data that isn't mine, for compacting
	/// slates for a return journey
	pub fn remove_other_sigdata<K>(
		&mut self,
		keychain: &K,
		sec_nonce: &SecretKey,
		sec_key: &SecretKey,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		let pub_nonce = PublicKey::from_secret_key(keychain.secp(), &sec_nonce)?;
		let pub_key = PublicKey::from_secret_key(keychain.secp(), &sec_key)?;
		self.participant_data = self
			.participant_data
			.clone()
			.into_iter()
			.filter(|v| v.public_nonce == pub_nonce && v.public_blind_excess == pub_key)
			.collect();
		Ok(())
	}

	/// Adds selected inputs and outputs to the slate's transaction
	/// Returns blinding factor
	pub fn add_transaction_elements<K, B>(
		&mut self,
		keychain: &K,
		builder: &B,
		elems: Vec<Box<build::Append<K, B>>>,
	) -> Result<BlindingFactor, Error>
	where
		K: Keychain,
		B: ProofBuild,
	{
		self.update_kernel()?;
		if elems.is_empty() {
			return Ok(BlindingFactor::zero());
		}
		let (tx, blind) =
			build::partial_transaction(self.tx_or_err()?.clone(), &elems, keychain, builder)?;
		self.tx = Some(tx);
		Ok(blind)
	}

	/// Update the tx kernel based on kernel features derived from the current slate.
	/// The fee may change as we build a transaction and we need to
	/// update the tx kernel to reflect this during the tx building process.
	pub fn update_kernel(&mut self) -> Result<(), Error> {
		self.tx = Some(
			self.tx_or_err()?
				.clone()
				.replace_kernel(TxKernel::with_features(self.kernel_features()?)),
		);
		Ok(())
	}

	/// Completes callers part of round 1, adding public key info
	/// to the slate
	pub fn fill_round_1<K>(&mut self, keychain: &K, context: &mut Context) -> Result<(), Error>
	where
		K: Keychain,
	{
		self.add_participant_info(keychain, context, None)
	}

	// Build kernel features based on variant and associated data.
	// 0: plain
	// 1: coinbase (invalid)
	// 2: height_locked (with associated lock_height)
	// 3: NRD (with associated relative_height)
	// Any other value is invalid.
	fn kernel_features(&self) -> Result<KernelFeatures, Error> {
		match self.kernel_features {
			0 => Ok(KernelFeatures::Plain {
				fee: self.fee_fields,
			}),
			1 => Err(ErrorKind::InvalidKernelFeatures(1).into()),
			2 => Ok(KernelFeatures::HeightLocked {
				fee: self.fee_fields,
				lock_height: match &self.kernel_features_args {
					Some(a) => a.lock_height,
					None => {
						return Err(ErrorKind::KernelFeaturesMissing(format!("lock_height")).into())
					}
				},
			}),
			3 => Ok(KernelFeatures::NoRecentDuplicate {
				fee: self.fee_fields,
				relative_height: match &self.kernel_features_args {
					Some(a) => NRDRelativeHeight::new(a.lock_height)?,
					None => {
						return Err(ErrorKind::KernelFeaturesMissing(format!("lock_height")).into())
					}
				},
			}),
			n => Err(ErrorKind::UnknownKernelFeatures(n).into()),
		}
	}

	/// This is the msg that we will sign as part of the tx kernel.
	pub fn msg_to_sign(&self) -> Result<secp::Message, Error> {
		let msg = self.kernel_features()?.kernel_sig_msg()?;
		Ok(msg)
	}

	/// Completes caller's part of round 2, completing signatures
	pub fn fill_round_2<K>(
		&mut self,
		keychain: &K,
		sec_key: &SecretKey,
		sec_nonce: &SecretKey,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		// TODO: Note we're unable to verify fees in this instance
		// Left here is a reminder that we no longer check fees
		// self.check_fees()?;

		self.verify_part_sigs(keychain.secp())?;
		let sig_part = aggsig::calculate_partial_sig(
			keychain.secp(),
			sec_key,
			sec_nonce,
			None,
			&self.pub_nonce_sum(keychain.secp())?,
			Some(&self.pub_blind_sum(keychain.secp())?),
			&self.msg_to_sign()?,
		)?;
		let pub_excess = PublicKey::from_secret_key(keychain.secp(), &sec_key)?;
		let pub_nonce = PublicKey::from_secret_key(keychain.secp(), &sec_nonce)?;
		for i in 0..self.num_participants() as usize {
			// find my entry
			if self.participant_data[i].public_blind_excess == pub_excess
				&& self.participant_data[i].public_nonce == pub_nonce
			{
				self.participant_data[i].part_sig = Some(sig_part);
				break;
			}
		}
		Ok(())
	}

	/// Creates the final signature, callable by either the sender or recipient
	/// (after phase 3: sender confirmation)
	pub fn finalize<K>(&mut self, keychain: &K) -> Result<(), Error>
	where
		K: Keychain,
	{
		let final_sig = self.finalize_signature(keychain.secp())?;
		self.finalize_transaction(keychain, &final_sig)
	}

	/// Return the sum of public nonces
	pub fn pub_nonce_sum(&self, secp: &secp::Secp256k1) -> Result<PublicKey, Error> {
		let pub_nonces: Vec<&PublicKey> = self
			.participant_data
			.iter()
			.map(|p| &p.public_nonce)
			.collect();
		if pub_nonces.len() == 0 {
			return Err(ErrorKind::Commit(format!("Participant nonces cannot be empty")).into());
		}
		match PublicKey::from_combination(secp, pub_nonces) {
			Ok(k) => Ok(k),
			Err(e) => Err(ErrorKind::Secp(e).into()),
		}
	}

	/// Return the sum of public blinding factors
	pub fn pub_blind_sum(&self, secp: &secp::Secp256k1) -> Result<PublicKey, Error> {
		let pub_blinds: Vec<&PublicKey> = self
			.participant_data
			.iter()
			.map(|p| &p.public_blind_excess)
			.collect();
		if pub_blinds.len() == 0 {
			return Err(
				ErrorKind::Commit(format!("Participant Blind sums cannot be empty")).into(),
			);
		}
		match PublicKey::from_combination(secp, pub_blinds) {
			Ok(k) => Ok(k),
			Err(e) => Err(ErrorKind::Secp(e).into()),
		}
	}

	/// Return vector of all partial sigs
	fn part_sigs(&self) -> Vec<&Signature> {
		self.participant_data
			.iter()
			.filter(|p| p.part_sig.is_some())
			.map(|p| p.part_sig.as_ref().unwrap())
			.collect()
	}

	/// Adds participants public keys to the slate data
	/// and saves participant's transaction context
	/// sec_key can be overridden to replace the blinding
	/// factor (by whoever split the offset)
	pub fn add_participant_info<K>(
		&mut self,
		keychain: &K,
		context: &Context,
		part_sig: Option<Signature>,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		// Add our public key and nonce to the slate
		let pub_key = PublicKey::from_secret_key(keychain.secp(), &context.sec_key)?;
		let pub_nonce = PublicKey::from_secret_key(keychain.secp(), &context.sec_nonce)?;
		let mut part_sig = part_sig;

		// Remove if already here and replace
		self.participant_data = self
			.participant_data
			.clone()
			.into_iter()
			.filter(|v| {
				if v.public_nonce == pub_nonce
					&& v.public_blind_excess == pub_key
					&& part_sig == None
				{
					part_sig = v.part_sig
				}
				v.public_nonce != pub_nonce || v.public_blind_excess != pub_key
			})
			.collect();

		self.participant_data.push(ParticipantData {
			public_blind_excess: pub_key,
			public_nonce: pub_nonce,
			part_sig: part_sig,
		});
		Ok(())
	}

	/// Add our contribution to the offset based on the excess, inputs and outputs
	pub fn adjust_offset<K: Keychain>(
		&mut self,
		keychain: &K,
		context: &Context,
	) -> Result<(), Error> {
		let mut sum = BlindSum::new()
			.add_blinding_factor(self.offset.clone())
			.sub_blinding_factor(BlindingFactor::from_secret_key(
				context.initial_sec_key.clone(),
			));
		for (id, _, amount) in &context.input_ids {
			sum = sum.sub_blinding_factor(BlindingFactor::from_secret_key(keychain.derive_key(
				*amount,
				id,
				SwitchCommitmentType::Regular,
			)?));
		}
		for (id, _, amount) in &context.output_ids {
			sum = sum.add_blinding_factor(BlindingFactor::from_secret_key(keychain.derive_key(
				*amount,
				id,
				SwitchCommitmentType::Regular,
			)?));
		}
		self.offset = keychain.blind_sum(&sum)?;

		Ok(())
	}

	/// Checks the fees in the transaction in the given slate are valid
	fn check_fees(&self) -> Result<(), Error> {
		let tx = self.tx_or_err()?;
		// double check the fee amount included in the partial tx
		// we don't necessarily want to just trust the sender
		// we could just overwrite the fee here (but we won't) due to the sig
		let fee = tx_fee(tx.inputs().len(), tx.outputs().len(), tx.kernels().len());

		if fee > tx.fee() {
			// apply fee mask past HF4
			return Err(
				ErrorKind::Fee(format!("Fee Dispute Error: {}, {}", tx.fee(), fee,)).into(),
			);
		}

		if fee > self.amount + self.fee_fields.fee() {
			let reason = format!(
				"Rejected the transfer because transaction fee ({}) exceeds received amount ({}).",
				amount_to_hr_string(fee, false),
				amount_to_hr_string(self.amount + self.fee_fields.fee(), false)
			);
			info!("{}", reason);
			return Err(ErrorKind::Fee(reason).into());
		}

		Ok(())
	}

	/// Verifies all of the partial signatures in the Slate are valid
	fn verify_part_sigs(&self, secp: &secp::Secp256k1) -> Result<(), Error> {
		// collect public nonces
		for p in self.participant_data.iter() {
			if p.is_complete() {
				aggsig::verify_partial_sig(
					secp,
					p.part_sig.as_ref().unwrap(),
					&self.pub_nonce_sum(secp)?,
					None,
					&p.public_blind_excess,
					Some(&self.pub_blind_sum(secp)?),
					&self.msg_to_sign()?,
				)?;
			}
		}
		Ok(())
	}

	/// This should be callable by either the sender or receiver
	/// once phase 3 is done
	///
	/// Receive Part 3 of interactive transactions from sender, Sender
	/// Confirmation Return Ok/Error
	/// -Receiver receives sS
	/// -Receiver verifies sender's sig, by verifying that
	/// kS * G + e *xS * G = sS* G
	/// -Receiver calculates final sig as s=(sS+sR, kS * G+kR * G)
	/// -Receiver puts into TX kernel:
	///
	/// Signature S
	/// pubkey xR * G+xS * G
	/// fee (= M)
	///
	/// Returns completed transaction ready for posting to the chain

	fn finalize_signature(&mut self, secp: &secp::Secp256k1) -> Result<Signature, Error> {
		self.verify_part_sigs(secp)?;

		let part_sigs = self.part_sigs();
		let pub_nonce_sum = self.pub_nonce_sum(secp)?;
		let final_pubkey = self.pub_blind_sum(secp)?;
		// get the final signature
		let final_sig = aggsig::add_signatures(secp, part_sigs, &pub_nonce_sum)?;

		// Calculate the final public key (for our own sanity check)

		// Check our final sig verifies
		aggsig::verify_completed_sig(
			secp,
			&final_sig,
			&final_pubkey,
			Some(&final_pubkey),
			&self.msg_to_sign()?,
		)?;

		Ok(final_sig)
	}

	/// Calculate the excess
	pub fn calc_excess(&self, secp: &secp::Secp256k1) -> Result<Commitment, Error> {
		let sum = self.pub_blind_sum(secp)?;
		Ok(Commitment::from_pubkey(secp, &sum)?)
	}

	/// builds a final transaction after the aggregated sig exchange
	fn finalize_transaction<K>(
		&mut self,
		keychain: &K,
		final_sig: &secp::Signature,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		self.check_fees()?;
		// build the final excess based on final tx and offset
		let final_excess = self.calc_excess(keychain.secp())?;

		debug!("Final Tx excess: {:?}", final_excess);

		let final_tx = self.tx_or_err()?;

		// update the tx kernel to reflect the offset excess and sig
		assert_eq!(final_tx.kernels().len(), 1);

		let mut kernel = final_tx.kernels()[0];
		kernel.excess = final_excess;
		kernel.excess_sig = final_sig.clone();

		let final_tx = final_tx.clone().replace_kernel(kernel);

		// confirm the kernel verifies successfully before proceeding
		debug!("Validating final transaction");
		trace!(
			"Final tx: {}",
			serde_json::to_string_pretty(&final_tx).unwrap()
		);
		final_tx.kernels()[0].verify()?;

		// confirm the overall transaction is valid (including the updated kernel)
		// accounting for tx weight limits
		if let Err(e) = final_tx.validate(Weighting::AsTransaction) {
			error!("Error with final tx validation: {}", e);
			Err(e.into())
		} else {
			// replace our slate tx with the new one with updated kernel
			self.tx = Some(final_tx);

			Ok(())
		}
	}
}

impl Serialize for Slate {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let v4 = SlateV4::from(self);
		v4.serialize(serializer)
	}
}
// Current slate version to versioned conversions

// Slate to versioned
impl From<Slate> for SlateV4 {
	fn from(slate: Slate) -> SlateV4 {
		let Slate {
			num_participants: num_parts,
			id,
			state,
			tx: _,
			amount,
			fee_fields,
			kernel_features,
			ttl_cutoff_height: ttl,
			offset: off,
			participant_data,
			version_info,
			payment_proof,
			kernel_features_args,
		} = slate.clone();
		let participant_data = map_vec!(participant_data, |data| ParticipantDataV4::from(data));
		let ver = VersionCompatInfoV4::from(&version_info);
		let payment_proof = match payment_proof {
			Some(p) => Some(PaymentInfoV4::from(&p)),
			None => None,
		};
		let feat_args = match kernel_features_args {
			Some(a) => Some(KernelFeaturesArgsV4::from(&a)),
			None => None,
		};
		let sta = SlateStateV4::from(&state);
		SlateV4 {
			num_parts,
			id,
			sta,
			coms: (&slate).into(),
			amt: amount,
			fee: fee_fields,
			feat: kernel_features,
			ttl,
			off,
			sigs: participant_data,
			ver,
			proof: payment_proof,
			feat_args,
		}
	}
}

impl From<&Slate> for SlateV4 {
	fn from(slate: &Slate) -> SlateV4 {
		let Slate {
			num_participants: num_parts,
			id,
			state,
			tx: _,
			amount,
			fee_fields,
			kernel_features,
			ttl_cutoff_height: ttl,
			offset,
			participant_data,
			version_info,
			payment_proof,
			kernel_features_args,
		} = slate;
		let num_parts = *num_parts;
		let id = *id;
		let amount = *amount;
		let fee_fields = *fee_fields;
		let feat = *kernel_features;
		let ttl = *ttl;
		let off = offset.clone();
		let participant_data = map_vec!(participant_data, |data| ParticipantDataV4::from(data));
		let ver = VersionCompatInfoV4::from(version_info);
		let payment_proof = match payment_proof {
			Some(p) => Some(PaymentInfoV4::from(p)),
			None => None,
		};
		let sta = SlateStateV4::from(state);
		let feat_args = match kernel_features_args {
			Some(a) => Some(KernelFeaturesArgsV4::from(a)),
			None => None,
		};
		SlateV4 {
			num_parts,
			id,
			sta,
			coms: slate.into(),
			amt: amount,
			fee: fee_fields,
			feat,
			ttl,
			off,
			sigs: participant_data,
			ver,
			proof: payment_proof,
			feat_args,
		}
	}
}

impl From<&Slate> for Option<Vec<CommitsV4>> {
	fn from(slate: &Slate) -> Self {
		match slate.tx {
			None => None,
			Some(ref tx) => {
				let mut ret_vec = vec![];
				match tx.inputs() {
					Inputs::CommitOnly(_) => panic!("commit only inputs unsupported"),
					Inputs::FeaturesAndCommit(ref inputs) => {
						for input in inputs {
							ret_vec.push(input.into());
						}
					}
				}
				for output in tx.outputs() {
					ret_vec.push(output.into());
				}
				Some(ret_vec)
			}
		}
	}
}

impl From<&ParticipantData> for ParticipantDataV4 {
	fn from(data: &ParticipantData) -> ParticipantDataV4 {
		let ParticipantData {
			public_blind_excess,
			public_nonce,
			part_sig,
		} = data;
		let public_blind_excess = *public_blind_excess;
		let public_nonce = *public_nonce;
		let part_sig = *part_sig;
		ParticipantDataV4 {
			xs: public_blind_excess,
			nonce: public_nonce,
			part: part_sig,
		}
	}
}

impl From<&SlateState> for SlateStateV4 {
	fn from(data: &SlateState) -> SlateStateV4 {
		match data {
			SlateState::Unknown => SlateStateV4::Unknown,
			SlateState::Standard1 => SlateStateV4::Standard1,
			SlateState::Standard2 => SlateStateV4::Standard2,
			SlateState::Standard3 => SlateStateV4::Standard3,
			SlateState::Invoice1 => SlateStateV4::Invoice1,
			SlateState::Invoice2 => SlateStateV4::Invoice2,
			SlateState::Invoice3 => SlateStateV4::Invoice3,
		}
	}
}

impl From<&KernelFeaturesArgs> for KernelFeaturesArgsV4 {
	fn from(data: &KernelFeaturesArgs) -> KernelFeaturesArgsV4 {
		let KernelFeaturesArgs { lock_height } = data;
		let lock_hgt = *lock_height;
		KernelFeaturesArgsV4 { lock_hgt }
	}
}

impl From<&VersionCompatInfo> for VersionCompatInfoV4 {
	fn from(data: &VersionCompatInfo) -> VersionCompatInfoV4 {
		let VersionCompatInfo {
			version,
			block_header_version,
		} = data;
		let version = *version;
		let block_header_version = *block_header_version;
		VersionCompatInfoV4 {
			version,
			block_header_version,
		}
	}
}

impl From<&PaymentInfo> for PaymentInfoV4 {
	fn from(data: &PaymentInfo) -> PaymentInfoV4 {
		let PaymentInfo {
			sender_address,
			receiver_address,
			receiver_signature,
		} = data;
		let sender_address = *sender_address;
		let receiver_address = *receiver_address;
		let receiver_signature = *receiver_signature;
		PaymentInfoV4 {
			saddr: sender_address,
			raddr: receiver_address,
			rsig: receiver_signature,
		}
	}
}

impl From<OutputFeatures> for OutputFeaturesV4 {
	fn from(of: OutputFeatures) -> OutputFeaturesV4 {
		let index = match of {
			OutputFeatures::Plain => 0,
			OutputFeatures::Coinbase => 1,
			OutputFeatures::Multisig => 2,
		};
		OutputFeaturesV4(index)
	}
}

// Versioned to current slate
impl From<SlateV4> for Slate {
	fn from(slate: SlateV4) -> Slate {
		let SlateV4 {
			num_parts: num_participants,
			id,
			sta,
			coms: _,
			amt: amount,
			fee: fee_fields,
			feat: kernel_features,
			ttl: ttl_cutoff_height,
			off: offset,
			sigs: participant_data,
			ver,
			proof: payment_proof,
			feat_args,
		} = slate.clone();
		let participant_data = map_vec!(participant_data, |data| ParticipantData::from(data));
		let version_info = VersionCompatInfo::from(&ver);
		let payment_proof = match &payment_proof {
			Some(p) => Some(PaymentInfo::from(p)),
			None => None,
		};
		let kernel_features_args = match &feat_args {
			Some(a) => Some(KernelFeaturesArgs::from(a)),
			None => None,
		};
		let state = SlateState::from(&sta);
		Slate {
			num_participants,
			id,
			state,
			tx: (&slate).into(),
			amount,
			fee_fields,
			kernel_features,
			ttl_cutoff_height,
			offset,
			participant_data,
			version_info,
			payment_proof,
			kernel_features_args,
		}
	}
}

pub fn tx_from_slate_v4(slate: &SlateV4) -> Option<Transaction> {
	let coms = match slate.coms.as_ref() {
		Some(c) => c,
		None => return None,
	};
	let secp = static_secp_instance();
	let secp = secp.lock();
	let mut calc_slate = Slate::blank(2, false);
	calc_slate.fee_fields = slate.fee;
	for d in slate.sigs.iter() {
		calc_slate.participant_data.push(ParticipantData {
			public_blind_excess: d.xs,
			public_nonce: d.nonce,
			part_sig: d.part,
		});
	}
	let excess = match calc_slate.calc_excess(&secp) {
		Ok(e) => e,
		Err(_) => Commitment::from_vec(vec![0]),
	};
	let excess_sig = match calc_slate.finalize_signature(&secp) {
		Ok(s) => s,
		Err(_) => Signature::from_raw_data(&[0; 64]).unwrap(),
	};
	let kernel = TxKernel {
		features: match slate.feat {
			0 => KernelFeatures::Plain { fee: slate.fee },
			1 => KernelFeatures::HeightLocked {
				fee: slate.fee,
				lock_height: match slate.feat_args.as_ref() {
					Some(a) => a.lock_hgt,
					None => 0,
				},
			},
			_ => KernelFeatures::Plain { fee: slate.fee },
		},
		excess,
		excess_sig,
	};
	let mut tx = Slate::empty_transaction().with_kernel(kernel);

	let mut outputs = vec![];
	let mut inputs = vec![];

	for c in coms.iter() {
		match &c.p {
			Some(p) => {
				outputs.push(Output::new(c.f.into(), c.c, p.clone()));
			}
			None => {
				inputs.push(Input {
					features: c.f.into(),
					commit: c.c,
				});
			}
		}
	}

	tx.body = tx
		.body
		.replace_inputs(inputs.as_slice().into())
		.replace_outputs(outputs.as_slice());
	tx.offset = slate.off.clone();
	Some(tx)
}

// Node's Transaction object and lock height to SlateV4 `coms`
impl From<&SlateV4> for Option<Transaction> {
	fn from(slate: &SlateV4) -> Option<Transaction> {
		tx_from_slate_v4(slate)
	}
}

impl From<&ParticipantDataV4> for ParticipantData {
	fn from(data: &ParticipantDataV4) -> ParticipantData {
		let ParticipantDataV4 {
			xs: public_blind_excess,
			nonce: public_nonce,
			part: part_sig,
		} = data;
		let public_blind_excess = *public_blind_excess;
		let public_nonce = *public_nonce;
		let part_sig = *part_sig;
		ParticipantData {
			public_blind_excess,
			public_nonce,
			part_sig,
		}
	}
}

impl From<&KernelFeaturesArgsV4> for KernelFeaturesArgs {
	fn from(data: &KernelFeaturesArgsV4) -> KernelFeaturesArgs {
		let KernelFeaturesArgsV4 { lock_hgt } = data;
		let lock_height = *lock_hgt;
		KernelFeaturesArgs { lock_height }
	}
}

impl From<&SlateStateV4> for SlateState {
	fn from(data: &SlateStateV4) -> SlateState {
		match data {
			SlateStateV4::Unknown => SlateState::Unknown,
			SlateStateV4::Standard1 => SlateState::Standard1,
			SlateStateV4::Standard2 => SlateState::Standard2,
			SlateStateV4::Standard3 => SlateState::Standard3,
			SlateStateV4::Invoice1 => SlateState::Invoice1,
			SlateStateV4::Invoice2 => SlateState::Invoice2,
			SlateStateV4::Invoice3 => SlateState::Invoice3,
		}
	}
}

impl From<&VersionCompatInfoV4> for VersionCompatInfo {
	fn from(data: &VersionCompatInfoV4) -> VersionCompatInfo {
		let VersionCompatInfoV4 {
			version,
			block_header_version,
		} = data;
		let version = *version;
		let block_header_version = *block_header_version;
		VersionCompatInfo {
			version,
			block_header_version,
		}
	}
}

impl From<&PaymentInfoV4> for PaymentInfo {
	fn from(data: &PaymentInfoV4) -> PaymentInfo {
		let PaymentInfoV4 {
			saddr: sender_address,
			raddr: receiver_address,
			rsig: receiver_signature,
		} = data;
		let sender_address = *sender_address;
		let receiver_address = *receiver_address;
		let receiver_signature = *receiver_signature;
		PaymentInfo {
			sender_address,
			receiver_address,
			receiver_signature,
		}
	}
}

impl From<OutputFeaturesV4> for OutputFeatures {
	fn from(of: OutputFeaturesV4) -> OutputFeatures {
		match of.0 {
			1 => OutputFeatures::Coinbase,
			0 | _ => OutputFeatures::Plain,
		}
	}
}
