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

//! Experimental early payment proof functionality, currently only used
//! with contracts. Can move outside of this module if early proofs are adopted
//! by legacy transactions

use crate::contract::types::ProofArgs;
use crate::grin_core::ser as grin_ser;
use crate::grin_core::ser::{Writeable, Writer};
use crate::grin_keychain::Keychain;
use crate::grin_util::secp::key::PublicKey;
use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::static_secp_instance;
use crate::slate::{PaymentMemo, Slate};
use crate::types::{Context, NodeClient, TxLogEntryType, WalletBackend};
use crate::{Error, OutputData, OutputStatus, TxLogEntry};
use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::Signature as DalekSignature;

#[derive(Debug, Clone)]
struct InvoiceProof {
	proof_type: u8,
	amount: u64,
	receiver_public_nonce: PublicKey,
	receiver_public_excess: PublicKey,
	sender_address: DalekPublicKey,
	timestamp: i64,
	memo: Option<PaymentMemo>,
}

impl Writeable for InvoiceProof {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), grin_ser::Error> {
		writer.write_u8(1)?;
		//TODO: Should be 7 bytes
		writer.write_u64(self.amount)?;
		{
			let static_secp = static_secp_instance();
			let static_secp = static_secp.lock();
			writer
				.write_fixed_bytes(self.receiver_public_nonce.serialize_vec(&static_secp, true))?;
			writer.write_fixed_bytes(
				self.receiver_public_excess
					.serialize_vec(&static_secp, true),
			)?;
		}
		writer.write_i64(self.timestamp)?;
		match &self.memo {
			Some(s) => {
				writer.write_u8(s.memo_type)?;
				writer.write_fixed_bytes(&s.memo.to_vec())?;
			}
			None => {
				writer.write_u8(0)?;
				writer.write_fixed_bytes([0u8; 32].to_vec())?;
			}
		}
		Ok(())
	}
}

impl InvoiceProof {
	pub fn from_slate(
		slate: &Slate,
		participant_index: usize,
		sender_address: Option<DalekPublicKey>,
	) -> Result<Self, Error> {
		// Sender address is either provided or in slate (or error)
		let sender_address = match sender_address {
			Some(a) => a,
			None => {
				if let Some(ref p) = slate.payment_proof {
					if let Some(a) = p.sender_address {
						a
					} else {
						return Err(Error::NoSenderAddressProvided);
					}
				} else {
					return Err(Error::NoSenderAddressProvided);
				}
			}
		};

		let memo = match slate.payment_proof.as_ref() {
			Some(p) => p.memo.clone(),
			None => None,
		};

		Ok(Self {
			proof_type: 1u8,
			amount: slate.amount,
			receiver_public_nonce: slate.participant_data[participant_index].public_nonce,
			receiver_public_excess: slate.participant_data[participant_index].public_blind_excess,
			sender_address,
			timestamp: 0,
			memo,
		})
	}

	/*pub fn sign() -> DalekSignature {

	}*/
}

pub fn add_payment_proof<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	context: &Context,
	proof_args: &ProofArgs,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	// TODO: Just generating invoice (type 1) for now
	generate_invoice_signature(wallet, keychain_mask, slate, context, proof_args)
}

/// Generates a signature for proof type 'Invoice'
pub fn generate_invoice_signature<'a, T: ?Sized, C, K>(
	wallet: &mut T,
	keychain_mask: Option<&SecretKey>,
	slate: &Slate,
	context: &Context,
	proof_args: &ProofArgs,
) -> Result<(), Error>
where
	T: WalletBackend<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	//TODO: Hardcoded 1
	let sig_data = InvoiceProof::from_slate(&slate, 1, proof_args.sender_address)?;
	let mut sig_data_bin = Vec::new();
	let _ =
		grin_ser::serialize_default(&mut sig_data_bin, &sig_data).expect("serialization failed");

	error!("SIG DATA: {:?}", sig_data);
	error!("SIG DATA BIN: {:?}", sig_data_bin);
	Ok(())
}
