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

//! Types specific to the wallet api, mostly argument serialization

use crate::grin_core::core::Output;
use crate::grin_core::libtx::secp_ser;
use crate::grin_keychain::{BlindingFactor, Identifier};
use crate::grin_util::secp::pedersen;
use crate::slate_versions::ser as dalek_ser;
use crate::slate_versions::SlateVersion;
use crate::types::OutputData;
use crate::SlatepackAddress;

use chrono::prelude::*;
use ed25519_dalek::Signature as DalekSignature;

pub use crate::mwixnet::{Hop, MixnetReqCreationParams, SwapReq};

/// Type for storing amounts (in nanogrins).
/// Serializes as a string but can deserialize from a string or u64.
#[derive(Serialize, Deserialize)]
pub struct Amount(#[serde(with = "secp_ser::string_or_u64")] pub u64);

/// V2 Init / Send TX API Args
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitTxArgs {
	/// The human readable account name from which to draw outputs
	/// for the transaction, overriding whatever the active account is as set via the
	/// [`set_active_account`](../grin_wallet_api/owner/struct.Owner.html#method.set_active_account) method.
	pub src_acct_name: Option<String>,
	#[serde(with = "secp_ser::string_or_u64")]
	/// The amount to send, in nanogrins. (`1 G = 1_000_000_000nG`)
	pub amount: u64,
	/// Does the amount include the fee, or will fees be spent in addition to the amount?
	pub amount_includes_fee: Option<bool>,
	#[serde(with = "secp_ser::string_or_u64")]
	/// The minimum number of confirmations an output
	/// should have in order to be included in the transaction.
	pub minimum_confirmations: u64,
	/// By default, the wallet selects as many inputs as possible in a
	/// transaction, to reduce the Output set and the fees. The wallet will attempt to spend
	/// include up to `max_outputs` in a transaction, however if this is not enough to cover
	/// the whole amount, the wallet will include more outputs. This parameter should be considered
	/// a soft limit.
	pub max_outputs: u32,
	/// The target number of change outputs to create in the transaction.
	/// The actual number created will be `num_change_outputs` + whatever remainder is needed.
	pub num_change_outputs: u32,
	/// If `true`, attempt to use up as many outputs as
	/// possible to create the transaction, up the 'soft limit' of `max_outputs`. This helps
	/// to reduce the size of the UTXO set and the amount of data stored in the wallet, and
	/// minimizes fees. This will generally result in many inputs and a large change output(s),
	/// usually much larger than the amount being sent. If `false`, the transaction will include
	/// as many outputs as are needed to meet the amount, (and no more) starting with the smallest
	/// value outputs.
	pub selection_strategy_is_use_all: bool,
	/// Optionally set the output target slate version (acceptable
	/// down to the minimum slate version compatible with the current. If `None` the slate
	/// is generated with the latest version.
	pub target_slate_version: Option<u16>,
	/// Number of blocks from current after which TX should be ignored
	#[serde(with = "secp_ser::opt_string_or_u64")]
	#[serde(default)]
	pub ttl_blocks: Option<u64>,
	/// If set, require a payment proof for the particular recipient
	#[serde(default)]
	pub payment_proof_recipient_address: Option<SlatepackAddress>,
	/// If true, just return an estimate of the resulting slate, containing fees and amounts
	/// locked without actually locking outputs or creating the transaction. Note if this is set to
	/// 'true', the amount field in the slate will contain the total amount locked, not the provided
	/// transaction amount
	pub estimate_only: Option<bool>,
	/// EXPERIMENTAL: if flagged, create the transaction as late-locked, i.e. don't select actual
	/// inputs until just before finalization
	#[serde(default)]
	pub late_lock: Option<bool>,
	/// Sender arguments. If present, the underlying function will also attempt to send the
	/// transaction to a destination and optionally finalize the result
	pub send_args: Option<InitTxSendArgs>,
}

/// Send TX API Args, for convenience functionality that inits the transaction and sends
/// in one go
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitTxSendArgs {
	/// The destination, contents will depend on the particular method
	pub dest: String,
	/// Whether to post the transaction if the send and finalize were successful
	pub post_tx: bool,
	/// Whether to use dandelion when posting. If false, skip the dandelion relay
	pub fluff: bool,
	/// If set, skip the Slatepack TOR send attempt
	pub skip_tor: bool,
}

impl Default for InitTxArgs {
	fn default() -> InitTxArgs {
		InitTxArgs {
			src_acct_name: None,
			amount: 0,
			amount_includes_fee: None,
			minimum_confirmations: 10,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			target_slate_version: None,
			ttl_blocks: None,
			estimate_only: Some(false),
			payment_proof_recipient_address: None,
			late_lock: Some(false),
			send_args: None,
		}
	}
}

/// V2 Issue Invoice Tx Args
#[derive(Clone, Serialize, Deserialize)]
pub struct IssueInvoiceTxArgs {
	/// The human readable account name to which the received funds should be added
	/// overriding whatever the active account is as set via the
	/// [`set_active_account`](../grin_wallet_api/owner/struct.Owner.html#method.set_active_account) method.
	pub dest_acct_name: Option<String>,
	/// The invoice amount in nanogrins. (`1 G = 1_000_000_000nG`)
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount: u64,
	/// Optionally set the output target slate version (acceptable
	/// down to the minimum slate version compatible with the current. If `None` the slate
	/// is generated with the latest version.
	pub target_slate_version: Option<u16>,
}

impl Default for IssueInvoiceTxArgs {
	fn default() -> IssueInvoiceTxArgs {
		IssueInvoiceTxArgs {
			dest_acct_name: None,
			amount: 0,
			target_slate_version: None,
		}
	}
}

/// Sort tx retrieval order
#[derive(Clone, Serialize, Deserialize)]
pub enum RetrieveTxQuerySortOrder {
	/// Ascending
	Asc,
	/// Descending
	Desc,
}

/// Valid sort fields for a transaction list retrieval query
#[derive(Clone, Serialize, Deserialize)]
pub enum RetrieveTxQuerySortField {
	/// Transaction Id
	Id,
	/// Creation Timestamp
	CreationTimestamp,
	/// Confirmation Timestamp
	ConfirmationTimestamp,
	/// TotalAmount (AmountCredited-AmountDebited)
	TotalAmount,
	/// Amount Credited
	AmountCredited,
	/// Amount Debited
	AmountDebited,
}

/// Retrieve Transaction List Pagination Arguments
#[derive(Clone, Serialize, Deserialize)]
pub struct RetrieveTxQueryArgs {
	/// Retrieve transactions with an id higher than or equal to the given
	/// If None, consider items from the first transaction and later
	pub min_id: Option<u32>,
	/// Retrieve tranactions with an id less than or equal to the given
	/// If None, consider items from the last transaction and earlier
	pub max_id: Option<u32>,
	/// The maximum number of transactions to return
	/// if both `before_id_inc` and `after_id_inc` are supplied, this will apply
	/// to the before and earlier set
	pub limit: Option<u32>,
	/// whether to exclude cancelled transactions in the returned set
	pub exclude_cancelled: Option<bool>,
	/// whether to only consider outstanding transactions
	pub include_outstanding_only: Option<bool>,
	/// whether to only consider confirmed-only transactions
	pub include_confirmed_only: Option<bool>,
	/// whether to only consider sent transactions
	pub include_sent_only: Option<bool>,
	/// whether to only consider received transactions
	pub include_received_only: Option<bool>,
	/// whether to only consider coinbase transactions
	pub include_coinbase_only: Option<bool>,
	/// whether to only consider reverted transactions
	pub include_reverted_only: Option<bool>,
	/// lower bound on the total amount (amount_credited - amount_debited), inclusive
	#[serde(with = "secp_ser::opt_string_or_u64")]
	#[serde(default)]
	pub min_amount: Option<u64>,
	/// higher bound on the total amount (amount_credited - amount_debited), inclusive
	#[serde(with = "secp_ser::opt_string_or_u64")]
	#[serde(default)]
	pub max_amount: Option<u64>,
	/// lower bound on the creation timestamp, inclusive
	pub min_creation_timestamp: Option<DateTime<Utc>>,
	/// higher bound on on the creation timestamp, inclusive
	pub max_creation_timestamp: Option<DateTime<Utc>>,
	/// lower bound on the confirmation timestamp, inclusive
	pub min_confirmed_timestamp: Option<DateTime<Utc>>,
	/// higher bound on the confirmation timestamp, inclusive
	pub max_confirmed_timestamp: Option<DateTime<Utc>>,
	/// Field within the tranasction list on which to sort
	/// defaults to ID if not present
	pub sort_field: Option<RetrieveTxQuerySortField>,
	/// Sort order, defaults to ASC if not present (earliest is first)
	pub sort_order: Option<RetrieveTxQuerySortOrder>,
}

impl Default for RetrieveTxQueryArgs {
	fn default() -> Self {
		Self {
			min_id: None,
			max_id: None,
			limit: None,
			exclude_cancelled: Some(false),
			include_outstanding_only: Some(false),
			include_confirmed_only: Some(false),
			include_sent_only: Some(false),
			include_received_only: Some(false),
			include_coinbase_only: Some(false),
			include_reverted_only: Some(false),
			min_amount: None,
			max_amount: None,
			min_creation_timestamp: None,
			max_creation_timestamp: None,
			min_confirmed_timestamp: None,
			max_confirmed_timestamp: None,
			sort_field: Some(RetrieveTxQuerySortField::Id),
			sort_order: Some(RetrieveTxQuerySortOrder::Asc),
		}
	}
}

/// Fees in block to use for coinbase amount calculation
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockFees {
	/// fees
	#[serde(with = "secp_ser::string_or_u64")]
	pub fees: u64,
	/// height
	#[serde(with = "secp_ser::string_or_u64")]
	pub height: u64,
	/// key id
	pub key_id: Option<Identifier>,
}

impl BlockFees {
	/// return key id
	pub fn key_id(&self) -> Option<Identifier> {
		self.key_id.clone()
	}
}

/// Map Outputdata to commits
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutputCommitMapping {
	/// Output Data
	pub output: OutputData,
	/// The commit
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub commit: pedersen::Commitment,
}

/// Node height result
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeHeightResult {
	/// Last known height
	#[serde(with = "secp_ser::string_or_u64")]
	pub height: u64,
	/// Hash
	pub header_hash: String,
	/// Whether this height was updated from the node
	pub updated_from_node: bool,
}

/// Version request result
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VersionInfo {
	/// API version
	pub foreign_api_version: u16,
	/// Slate version
	pub supported_slate_versions: Vec<SlateVersion>,
}

/// Packaged Payment Proof
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PaymentProof {
	/// Amount
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount: u64,
	/// Kernel Excess
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub excess: pedersen::Commitment,
	/// Recipient Wallet Address
	pub recipient_address: SlatepackAddress,
	/// Recipient Signature
	#[serde(with = "dalek_ser::dalek_sig_serde")]
	pub recipient_sig: DalekSignature,
	/// Sender Wallet Address
	pub sender_address: SlatepackAddress,
	/// Sender Signature
	#[serde(with = "dalek_ser::dalek_sig_serde")]
	pub sender_sig: DalekSignature,
}

/// Build output result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuiltOutput {
	/// Blinding Factor
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::blind_from_hex"
	)]
	pub blind: BlindingFactor,
	/// Key Identifier
	pub key_id: Identifier,
	/// Output
	pub output: Output,
}
