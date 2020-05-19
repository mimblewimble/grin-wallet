// Copyright 2019 The Grin Developers
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
	Input, KernelFeatures, Output, OutputFeatures, Transaction, TransactionBody, TxKernel,
	Weighting,
};
use crate::grin_core::core::verifier_cache::LruVerifierCache;
use crate::grin_core::libtx::{aggsig, build, proof::ProofBuild, tx_fee};
use crate::grin_core::map_vec;
use crate::grin_keychain::{BlindSum, BlindingFactor, Keychain};
use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::grin_util::secp::pedersen::Commitment;
use crate::grin_util::secp::Signature;
use crate::grin_util::{secp, static_secp_instance, RwLock};
use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::Signature as DalekSignature;
use rand::rngs::mock::StepRng;
use rand::thread_rng;
use serde::ser::{Serialize, Serializer};
use serde_json;
use std::fmt;
use std::sync::Arc;
use uuid::Uuid;

use crate::slate_versions::v4::{
	CoinbaseV4, CommitsV4, InputV4, KernelFeaturesArgsV4, OutputFeaturesV4, OutputV4,
	ParticipantDataV4, PaymentInfoV4, SlateStateV4, SlateV4, TransactionBodyV4, TransactionV4,
	TxKernelV4, VersionCompatInfoV4,
};
use crate::slate_versions::VersionedSlate;
use crate::slate_versions::{CURRENT_SLATE_VERSION, GRIN_BLOCK_HEADER_VERSION};
use crate::types::CbData;

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
	/// fee amount
	pub fee: u64,
	/// TTL, the block height at which wallets
	/// should refuse to process the transaction and unlock all
	/// associated outputs
	pub ttl_cutoff_height: u64,
	/// Kernel Features flag, if any
	pub kernel_features: u8,
	/// Offset, needed when posting of tranasction is deferred
	pub offset: BlindingFactor,
	/// Participant data, each participant in the transaction will
	/// insert their public data here. For now, 0 is sender and 1
	/// is receiver, though this will change for multi-party
	pub participant_data: Vec<ParticipantData>,
	/// Payment Proof
	pub payment_proof: Option<PaymentInfo>,
	/// Kernel features arguments
	pub kernel_features_args: Option<KernelFeaturesArgs>,
	//TODO: Remove post HF3
	/// participant ID, only stored for compatibility with V3 slates
	/// not serialized anywhere
	pub participant_id: Option<PublicKey>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
/// Kernel features arguments definition
pub struct KernelFeaturesArgs {
	/// Lock height, for HeightLocked
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
	/// Whether the slate started life as a compact slate
	pub fn is_compact(&self) -> bool {
		self.version_info.version >= 4
	}

	/// number of participants
	pub fn num_participants(&self) -> u8 {
		match self.num_participants {
			0 => 2,
			n => n,
		}
	}

	/// Compact the slate for initial sending, storing the excess + offset explicit
	/// and removing my input/output data
	/// This info must be stored in the context for repopulation later
	pub fn compact(&mut self) -> Result<(), Error> {
		self.tx = None;
		Ok(())
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
			VersionedSlate::V3(s) => SlateV4::from(s),
		};
		Ok(v4.into())
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
			tx: Some(Transaction::empty()),
			amount: 0,
			fee: 0,
			ttl_cutoff_height: 0,
			kernel_features: 0,
			offset: BlindingFactor::zero(),
			participant_data: vec![],
			version_info: VersionCompatInfo {
				version: CURRENT_SLATE_VERSION,
				block_header_version: GRIN_BLOCK_HEADER_VERSION,
			},
			payment_proof: None,
			participant_id: None,
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
			build::partial_transaction(self.tx_or_err()?.clone(), elems, keychain, builder)?;
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
	pub fn fill_round_1<K>(
		&mut self,
		keychain: &K,
		sec_key: &mut SecretKey,
		sec_nonce: &SecretKey,
		use_test_rng: bool,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		// Whoever does this first generates the offset
		// TODO: Remove HF3
		if self.participant_data.is_empty() && !self.is_compact() {
			self.generate_offset(keychain, sec_key, use_test_rng)?;
		}
		// Always choose my part of the offset, and subtract from my excess
		if self.is_compact() {
			self.generate_offset(keychain, sec_key, use_test_rng)?;
		}
		self.add_participant_info(keychain, &sec_key, &sec_nonce, None)?;
		Ok(())
	}

	// Construct the appropriate kernel features based on our fee and lock_height.
	// If lock_height is 0 then its a plain kernel, otherwise its a height locked kernel.
	fn kernel_features(&self) -> Result<KernelFeatures, Error> {
		match self.kernel_features {
			0 => Ok(KernelFeatures::Plain { fee: self.fee }),
			1 => Ok(KernelFeatures::HeightLocked {
				fee: self.fee,
				lock_height: match &self.kernel_features_args {
					Some(a) => a.lock_height,
					None => {
						return Err(ErrorKind::KernelFeaturesMissing(format!("lock_height")).into())
					}
				},
			}),
			n => return Err(ErrorKind::UnknownKernelFeatures(n).into()),
		}
	}

	// This is the msg that we will sign as part of the tx kernel.
	fn msg_to_sign(&self) -> Result<secp::Message, Error> {
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
		if !self.is_compact() {
			self.check_fees()?;
		}

		self.verify_part_sigs(keychain.secp())?;
		let sig_part = aggsig::calculate_partial_sig(
			keychain.secp(),
			sec_key,
			sec_nonce,
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
	fn pub_nonce_sum(&self, secp: &secp::Secp256k1) -> Result<PublicKey, Error> {
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
	fn pub_blind_sum(&self, secp: &secp::Secp256k1) -> Result<PublicKey, Error> {
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
		sec_key: &SecretKey,
		sec_nonce: &SecretKey,
		part_sig: Option<Signature>,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		// Add our public key and nonce to the slate
		let pub_key = PublicKey::from_secret_key(keychain.secp(), &sec_key)?;
		let pub_nonce = PublicKey::from_secret_key(keychain.secp(), &sec_nonce)?;
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
		self.participant_id = Some(pub_key);
		Ok(())
	}

	/// Somebody involved needs to generate an offset with their private key
	/// For now, we'll have the transaction initiator be responsible for it
	/// Return offset private key for the participant to use later in the
	/// transaction
	pub fn generate_offset<K>(
		&mut self,
		keychain: &K,
		sec_key: &mut SecretKey,
		use_test_rng: bool,
	) -> Result<(), Error>
	where
		K: Keychain,
	{
		// Generate a random kernel offset here
		// and subtract it from the blind_sum so we create
		// the aggsig context with the "split" key
		let my_offset = match use_test_rng {
			false => {
				BlindingFactor::from_secret_key(SecretKey::new(&keychain.secp(), &mut thread_rng()))
			}
			true => {
				// allow for consistent test results
				let mut test_rng = StepRng::new(1_234_567_890_u64, 1);
				BlindingFactor::from_secret_key(SecretKey::new(&keychain.secp(), &mut test_rng))
			}
		};

		if self.is_compact() {
			let total_offset = keychain.blind_sum(
				&BlindSum::new()
					.add_blinding_factor(self.offset.clone())
					.add_blinding_factor(my_offset.clone()),
			)?;
			self.offset = total_offset;
		} else {
			//TODO: Remove HF3
			self.tx_or_err_mut()?.offset = my_offset.clone();
			self.offset = my_offset.clone();
		};

		let adjusted_offset = keychain.blind_sum(
			&BlindSum::new()
				.add_blinding_factor(BlindingFactor::from_secret_key(sec_key.clone()))
				.sub_blinding_factor(my_offset),
		)?;
		*sec_key = adjusted_offset.secret_key(&keychain.secp())?;

		Ok(())
	}

	/// Checks the fees in the transaction in the given slate are valid
	fn check_fees(&self) -> Result<(), Error> {
		let tx = self.tx_or_err()?;
		// double check the fee amount included in the partial tx
		// we don't necessarily want to just trust the sender
		// we could just overwrite the fee here (but we won't) due to the sig
		let fee = tx_fee(
			tx.inputs().len(),
			tx.outputs().len(),
			tx.kernels().len(),
			None,
		);

		if fee > tx.fee() {
			return Err(
				ErrorKind::Fee(format!("Fee Dispute Error: {}, {}", tx.fee(), fee,)).into(),
			);
		}

		if fee > self.amount + self.fee {
			let reason = format!(
				"Rejected the transfer because transaction fee ({}) exceeds received amount ({}).",
				amount_to_hr_string(fee, false),
				amount_to_hr_string(self.amount + self.fee, false)
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

		let final_tx = self.tx_or_err_mut()?;

		// update the tx kernel to reflect the offset excess and sig
		assert_eq!(final_tx.kernels().len(), 1);
		final_tx.kernels_mut()[0].excess = final_excess.clone();
		final_tx.kernels_mut()[0].excess_sig = final_sig.clone();

		// confirm the kernel verifies successfully before proceeding
		debug!("Validating final transaction");
		trace!(
			"Final tx: {}",
			serde_json::to_string_pretty(final_tx).unwrap()
		);
		final_tx.kernels()[0].verify()?;

		// confirm the overall transaction is valid (including the updated kernel)
		// accounting for tx weight limits
		let verifier_cache = Arc::new(RwLock::new(LruVerifierCache::new()));
		if let Err(e) = final_tx.validate(Weighting::AsTransaction, verifier_cache) {
			error!("Error with final tx validation: {}", e);
			Err(e.into())
		} else {
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

// Coinbase data to versioned.
impl From<CbData> for CoinbaseV4 {
	fn from(cb: CbData) -> CoinbaseV4 {
		CoinbaseV4 {
			output: OutputV4::from(&cb.output),
			kernel: TxKernelV4::from(&cb.kernel),
			key_id: cb.key_id,
		}
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
			fee,
			kernel_features,
			ttl_cutoff_height: ttl,
			offset: off,
			participant_data,
			version_info,
			payment_proof,
			participant_id: _participant_id,
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
			fee,
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
			fee,
			kernel_features,
			ttl_cutoff_height: ttl,
			offset,
			participant_data,
			version_info,
			payment_proof,
			participant_id: _participant_id,
			kernel_features_args,
		} = slate;
		let num_parts = *num_parts;
		let id = *id;
		let amount = *amount;
		let fee = *fee;
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
			fee,
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

// Node's Transaction object and lock height to SlateV4 `coms`
impl From<&Slate> for Option<Vec<CommitsV4>> {
	fn from(slate: &Slate) -> Option<Vec<CommitsV4>> {
		let mut ret_vec = vec![];
		let (ins, outs) = match slate.tx.as_ref() {
			Some(t) => (t.body.inputs.clone(), t.body.outputs.clone()),
			None => return None,
		};
		for i in ins.iter() {
			ret_vec.push(CommitsV4 {
				f: i.features.into(),
				c: i.commit,
				p: None,
			});
		}
		for o in outs.iter() {
			ret_vec.push(CommitsV4 {
				f: o.features.into(),
				c: o.commit,
				p: Some(o.proof),
			});
		}
		Some(ret_vec)
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
		};
		OutputFeaturesV4(index)
	}
}

impl From<Transaction> for TransactionV4 {
	fn from(tx: Transaction) -> TransactionV4 {
		let Transaction { offset, body } = tx;
		let body = TransactionBodyV4::from(&body);
		TransactionV4 { offset, body }
	}
}

impl From<&Transaction> for TransactionV4 {
	fn from(tx: &Transaction) -> TransactionV4 {
		let Transaction { offset, body } = tx;
		let offset = offset.clone();
		let body = TransactionBodyV4::from(body);
		TransactionV4 { offset, body }
	}
}

impl From<&TransactionBody> for TransactionBodyV4 {
	fn from(body: &TransactionBody) -> TransactionBodyV4 {
		let TransactionBody {
			inputs,
			outputs,
			kernels,
		} = body;

		let inputs = map_vec!(inputs, |inp| InputV4::from(inp));
		let outputs = map_vec!(outputs, |out| OutputV4::from(out));
		let kernels = map_vec!(kernels, |kern| TxKernelV4::from(kern));
		TransactionBodyV4 {
			ins: inputs,
			outs: outputs,
			kers: kernels,
		}
	}
}

impl From<&Input> for InputV4 {
	fn from(input: &Input) -> InputV4 {
		let Input { features, commit } = *input;
		InputV4 {
			features: features.into(),
			commit,
		}
	}
}

impl From<&Output> for OutputV4 {
	fn from(output: &Output) -> OutputV4 {
		let Output {
			features,
			commit,
			proof,
		} = *output;
		OutputV4 {
			features: features.into(),
			com: commit,
			prf: proof,
		}
	}
}

impl From<&TxKernel> for TxKernelV4 {
	fn from(kernel: &TxKernel) -> TxKernelV4 {
		let (features, fee, lock_height) = match kernel.features {
			KernelFeatures::Plain { fee } => (CompatKernelFeatures::Plain, fee, 0),
			KernelFeatures::Coinbase => (CompatKernelFeatures::Coinbase, 0, 0),
			KernelFeatures::HeightLocked { fee, lock_height } => {
				(CompatKernelFeatures::HeightLocked, fee, lock_height)
			}
		};
		TxKernelV4 {
			features,
			fee,
			lock_height,
			excess: kernel.excess,
			excess_sig: kernel.excess_sig,
		}
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
			fee,
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
			fee,
			kernel_features,
			ttl_cutoff_height,
			offset,
			participant_data,
			version_info,
			payment_proof,
			participant_id: None,
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
	calc_slate.fee = slate.fee;
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
	let mut tx = Transaction::empty();
	tx.body.kernels.push(kernel);
	for c in coms.iter() {
		match &c.p {
			Some(p) => tx.body.outputs.push(Output {
				features: c.f.into(),
				commit: c.c,
				proof: p.clone(),
			}),
			None => tx.body.inputs.push(Input {
				features: c.f.into(),
				commit: c.c,
			}),
		}
	}
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

impl From<TransactionV4> for Transaction {
	fn from(tx: TransactionV4) -> Transaction {
		let TransactionV4 { offset, body } = tx;
		let body = TransactionBody::from(&body);
		Transaction { offset, body }
	}
}

impl From<&TransactionBodyV4> for TransactionBody {
	fn from(body: &TransactionBodyV4) -> TransactionBody {
		let TransactionBodyV4 { ins, outs, kers } = body;

		let inputs = map_vec!(ins, |inp| Input::from(inp));
		let outputs = map_vec!(outs, |out| Output::from(out));
		let kernels = map_vec!(kers, |kern| TxKernel::from(kern));
		TransactionBody {
			inputs,
			outputs,
			kernels,
		}
	}
}

impl From<&InputV4> for Input {
	fn from(input: &InputV4) -> Input {
		let InputV4 { features, commit } = *input;
		Input {
			features: features.into(),
			commit,
		}
	}
}

impl From<&OutputV4> for Output {
	fn from(output: &OutputV4) -> Output {
		let OutputV4 {
			features,
			com: commit,
			prf: proof,
		} = *output;
		Output {
			features: features.into(),
			commit,
			proof,
		}
	}
}

impl From<&TxKernelV4> for TxKernel {
	fn from(kernel: &TxKernelV4) -> TxKernel {
		let (fee, lock_height) = (kernel.fee, kernel.lock_height);
		let features = match kernel.features {
			CompatKernelFeatures::Plain => KernelFeatures::Plain { fee },
			CompatKernelFeatures::Coinbase => KernelFeatures::Coinbase,
			CompatKernelFeatures::HeightLocked => KernelFeatures::HeightLocked { fee, lock_height },
		};
		TxKernel {
			features,
			excess: kernel.excess,
			excess_sig: kernel.excess_sig,
		}
	}
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum CompatKernelFeatures {
	Plain,
	Coinbase,
	HeightLocked,
}
