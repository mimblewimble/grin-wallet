// Copyright 2023 The Grin Developers
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

//! Contract-specific payment proof setup.

use crate::backend::WalletBackend;
use crate::contract::types::ProofArgs;
use crate::grin_keychain::Keychain;
use crate::grin_util::secp::key::{PublicKey, SecretKey};
use crate::grin_util::secp::Secp256k1;
use crate::payment_proof::{sender_nonce_tweak, EarlyPaymentProof};
use crate::slate::{PaymentProofType, Slate};
use crate::types::{Context, NodeClient};
use crate::{address, Error};

/// Commit the payer nonce to the sender-nonce proof fields.
pub(super) fn commit_sender_nonce(
	slate: &Slate,
	context: &mut Context,
	secp: &Secp256k1,
) -> Result<(), Error> {
	if context.get_net_change()? >= 0 {
		return Ok(());
	}
	let payment_proof = match slate.payment_proof.as_ref() {
		Some(proof) if proof.proof_type == PaymentProofType::SenderNonce => proof,
		_ => return Ok(()),
	};
	if !slate.is_first_invoice_round() {
		return Err(Error::PaymentProofValidation(
			"Sender nonce proofs require the first invoice signing round".into(),
		));
	}
	let sender_address = payment_proof
		.sender_address
		.ok_or(Error::NoSenderAddressProvided)?;
	let proof = EarlyPaymentProof::from_slate(slate, 0, Some(sender_address))?;
	if let Some(base_public) = context.sender_public_nonce.as_ref() {
		let mut expected = base_public.clone();
		expected.add_exp_assign(secp, &sender_nonce_tweak(secp, base_public, &proof)?)?;
		if PublicKey::from_secret_key(secp, &context.sec_nonce)? != expected {
			return Err(Error::PaymentProofValidation(
				"Sender nonce proof details changed".into(),
			));
		}
	} else {
		let base_public = PublicKey::from_secret_key(secp, &context.sec_nonce)?;
		context
			.sec_nonce
			.add_assign(secp, &sender_nonce_tweak(secp, &base_public, &proof)?)?;
		context.sender_public_nonce = Some(base_public);
	}
	Ok(())
}

/// Add the receiver's proof data to a contract slate.
pub(super) fn add_payment_proof<C, K>(
	wallet: &mut WalletBackend<C, K>,
	keychain_mask: Option<&SecretKey>,
	slate: &mut Slate,
	context: &Context,
	proof_args: &ProofArgs,
) -> Result<(), Error>
where
	C: NodeClient,
	K: Keychain,
{
	let keychain = wallet.keychain(keychain_mask)?;
	let participant_index = slate.find_index_matching_context(&keychain, context)?;
	let derivation_index = context.payment_proof_derivation_index.unwrap_or(0);
	let receiver_key =
		address::address_from_derivation_path(&keychain, &context.parent_key_id, derivation_index)?;
	slate.add_payment_proof_data(
		participant_index,
		proof_args.proof_type,
		proof_args
			.sender_address
			.ok_or(Error::NoSenderAddressProvided)?,
		&receiver_key,
		proof_args.memo.clone(),
	)
}
