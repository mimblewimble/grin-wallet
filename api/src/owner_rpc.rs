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

//! JSON-RPC Stub generation for the Owner API
use grin_wallet_libwallet::RetrieveTxQueryArgs;
use libwallet::mwixnet::SwapReq;
use uuid::Uuid;

use crate::config::{TorConfig, WalletConfig};
use crate::core::core::OutputFeatures;
use crate::core::global;
use crate::keychain::{Identifier, Keychain};
use crate::libwallet::{
	mwixnet::MixnetReqCreationParams, AcctPathMapping, Amount, BuiltOutput, Error, InitTxArgs,
	IssueInvoiceTxArgs, NodeClient, NodeHeightResult, OutputCommitMapping, PaymentProof, Slate,
	SlateVersion, Slatepack, SlatepackAddress, StatusMessage, TxLogEntry, VersionedSlate,
	ViewWallet, WalletInfo, WalletLCProvider,
};
use crate::util::logger::LoggingConfig;
use crate::util::secp::key::{PublicKey, SecretKey};
use crate::util::secp::pedersen::Commitment;
use crate::util::{from_hex, static_secp_instance, Mutex, ZeroingString};
use crate::{ECDHPubkey, Ed25519SecretKey, Owner, Token};
use easy_jsonrpc_mw;
use grin_wallet_util::OnionV3Address;
use rand::thread_rng;
use std::convert::TryFrom;
use std::sync::Arc;
use std::time::Duration;

/// Public definition used to generate Owner jsonrpc api.
/// Secure version containing wallet lifecycle functions. All calls to this API must be encrypted.
/// See [`init_secure_api`](#tymethod.init_secure_api) for details of secret derivation
/// and encryption.

#[easy_jsonrpc_mw::rpc]
pub trait OwnerRpc {
	/**
	Networked version of [Owner::accounts](struct.Owner.html#method.accounts).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "accounts",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				{
					"label": "default",
					"path": "0200000000000000000000000000000000"
				}
			]
		},
		"id": 1
	}
	# "#
	# , 4, false, false, false, false);
	```
	*/
	fn accounts(&self, token: Token) -> Result<Vec<AcctPathMapping>, Error>;

	/**
	Networked version of [Owner::create_account_path](struct.Owner.html#method.create_account_path).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_account_path",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"label": "account1"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": "0200000001000000000000000000000000"
		},
		"id": 1
	}
	# "#
	# , 4, false, false, false, false);
	```
	 */
	fn create_account_path(&self, token: Token, label: &String) -> Result<Identifier, Error>;

	/**
	Networked version of [Owner::set_active_account](struct.Owner.html#method.set_active_account).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "set_active_account",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"label": "default"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		},
		"id": 1
	}
	# "#
	# , 4, false, false, false, false);
	```
	 */
	fn set_active_account(&self, token: Token, label: &String) -> Result<(), Error>;

	/**
	Networked version of [Owner::retrieve_outputs](struct.Owner.html#method.retrieve_outputs).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_outputs",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"include_spent": false,
			"refresh_from_node": true,
			"tx_id": null
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				true,
				[
					{
						"commit": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
						"output": {
							"commit": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
							"height": "1",
							"is_coinbase": true,
							"key_id": "0300000000000000000000000000000000",
							"lock_height": "4",
							"mmr_index": null,
							"n_child": 0,
							"root_key_id": "0200000000000000000000000000000000",
							"status": "Unspent",
							"tx_log_entry": 0,
							"value": "60000000000"
						}
					},
					{
						"commit": "087df32304c5d4ae8b2af0bc31e700019d722910ef87dd4eec3197b80b207e3045",
						"output": {
							"commit": "087df32304c5d4ae8b2af0bc31e700019d722910ef87dd4eec3197b80b207e3045",
							"height": "2",
							"is_coinbase": true,
							"key_id": "0300000000000000000000000100000000",
							"lock_height": "5",
							"mmr_index": null,
							"n_child": 1,
							"root_key_id": "0200000000000000000000000000000000",
							"status": "Unspent",
							"tx_log_entry": 1,
							"value": "60000000000"
						}
					}
				]
			]
		}
	}
	# "#
	# , 2, false, false, false, false);
	```
	*/

	fn retrieve_outputs(
		&self,
		token: Token,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), Error>;

	/**
	Networked version of [Owner::retrieve_txs](struct.Owner.html#method.retrieve_txs).

	# Json rpc example

	```
		# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "retrieve_txs",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"refresh_from_node": true,
				"tx_id": null,
				"tx_slate_id": null
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
		"id": 1,
		"jsonrpc": "2.0",
	  "result": {
		"Ok": [
		  true,
		  [
			{
			  "amount_credited": "60000000000",
			  "amount_debited": "0",
			  "confirmation_ts": "2019-01-15T16:01:26Z",
			  "confirmed": true,
			  "creation_ts": "2019-01-15T16:01:26Z",
			  "fee": null,
			  "id": 0,
			  "kernel_excess": "0838e19c490038b10f051c9c190a9b1f96d59bbd242f5d3143f50630deb74342ed",
			  "kernel_lookup_min_height": 1,
			  "num_inputs": 0,
			  "num_outputs": 1,
			  "parent_key_id": "0200000000000000000000000000000000",
			  "stored_tx": null,
			  "ttl_cutoff_height": null,
			  "tx_slate_id": null,
			  "payment_proof": null,
			  "reverted_after": null,
			  "tx_type": "ConfirmedCoinbase"
			},
			{
			  "amount_credited": "60000000000",
			  "amount_debited": "0",
			  "confirmation_ts": "2019-01-15T16:01:26Z",
			  "confirmed": true,
			  "creation_ts": "2019-01-15T16:01:26Z",
			  "fee": null,
			  "id": 1,
			  "kernel_excess": "08cd9d890c0b6a004f700aa5939a1ce0488fe2a11fa33cf096b50732ceab0be1df",
			  "kernel_lookup_min_height": 2,
			  "num_inputs": 0,
			  "num_outputs": 1,
			  "parent_key_id": "0200000000000000000000000000000000",
			  "stored_tx": null,
			  "ttl_cutoff_height": null,
			  "payment_proof": null,
			  "reverted_after": null,
			  "tx_slate_id": null,
			  "tx_type": "ConfirmedCoinbase"
			}
		  ]
		]
	  }
	}
	# "#
	# , 2, false, false, false, false);
	```
	*/

	fn retrieve_txs(
		&self,
		token: Token,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), Error>;

	/**
	Networked version of [Owner::retrieve_txs](struct.Owner.html#method.retrieve_txs), which passes only the `tx_query_args`
	parameter. See  (../grin_wallet_libwallet/types.struct.RetrieveTxQueryArgs.html)

	```
		# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "query_txs",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"refresh_from_node": true,
				"query": {
					"min_id": 0,
					"max_id": 100,
					"min_amount": "0",
					"max_amount": "60000000000",
					"sort_field": "Id",
					"sort_order": "Asc"
				}
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
		"id": 1,
		"jsonrpc": "2.0",
	  "result": {
		"Ok": [
		  true,
		  [
			{
			  "amount_credited": "60000000000",
			  "amount_debited": "0",
			  "confirmation_ts": "2019-01-15T16:01:26Z",
			  "confirmed": true,
			  "creation_ts": "2019-01-15T16:01:26Z",
			  "fee": null,
			  "id": 0,
			  "kernel_excess": "0838e19c490038b10f051c9c190a9b1f96d59bbd242f5d3143f50630deb74342ed",
			  "kernel_lookup_min_height": 1,
			  "num_inputs": 0,
			  "num_outputs": 1,
			  "parent_key_id": "0200000000000000000000000000000000",
			  "stored_tx": null,
			  "ttl_cutoff_height": null,
			  "tx_slate_id": null,
			  "payment_proof": null,
			  "reverted_after": null,
			  "tx_type": "ConfirmedCoinbase"
			},
			{
			  "amount_credited": "60000000000",
			  "amount_debited": "0",
			  "confirmation_ts": "2019-01-15T16:01:26Z",
			  "confirmed": true,
			  "creation_ts": "2019-01-15T16:01:26Z",
			  "fee": null,
			  "id": 1,
			  "kernel_excess": "08cd9d890c0b6a004f700aa5939a1ce0488fe2a11fa33cf096b50732ceab0be1df",
			  "kernel_lookup_min_height": 2,
			  "num_inputs": 0,
			  "num_outputs": 1,
			  "parent_key_id": "0200000000000000000000000000000000",
			  "stored_tx": null,
			  "ttl_cutoff_height": null,
			  "payment_proof": null,
			  "reverted_after": null,
			  "tx_slate_id": null,
			  "tx_type": "ConfirmedCoinbase"
			}
		  ]
		]
	  }
	}
	# "#
	# , 2, false, false, false, false);
	```

	*/

	fn query_txs(
		&self,
		token: Token,
		refresh_from_node: bool,
		query: RetrieveTxQueryArgs,
	) -> Result<(bool, Vec<TxLogEntry>), Error>;

	/**
	Networked version of [Owner::retrieve_summary_info](struct.Owner.html#method.retrieve_summary_info).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_summary_info",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"refresh_from_node": true,
			"minimum_confirmations": 1
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
	"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				true,
				{
					"amount_awaiting_confirmation": "0",
					"amount_awaiting_finalization": "0",
					"amount_currently_spendable": "60000000000",
					"amount_immature": "180000000000",
					"amount_locked": "0",
					"amount_reverted": "0",
					"last_confirmed_height": "4",
					"minimum_confirmations": "1",
					"total": "240000000000"
				}
			]
		}
	}
	# "#
	# , 4, false, false, false, false);
	```
	 */

	fn retrieve_summary_info(
		&self,
		token: Token,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), Error>;

	/**
	;Networked version of [Owner::init_send_tx](struct.Owner.html#method.init_send_tx).

	```
		# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "init_send_tx",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"args": {
					"src_acct_name": null,
					"amount": "6000000000",
					"minimum_confirmations": 2,
					"max_outputs": 500,
					"num_change_outputs": 1,
					"selection_strategy_is_use_all": true,
					"target_slate_version": null,
					"payment_proof_recipient_address": "tgrin1xtxavwfgs48ckf3gk8wwgcndmn0nt4tvkl8a7ltyejjcy2mc6nfs9gm2lp",
					"ttl_blocks": null,
					"send_args": null
				}
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
		"id": 1,
			"jsonrpc": "2.0",
			"result": {
				"Ok": {
					"amt": "6000000000",
					"fee": "23000000",
					"id": "0436430c-2b02-624c-2032-570501212b00",
					"proof": {
						"raddr": "32cdd63928854f8b2628b1dce4626ddcdf35d56cb7cfdf7d64cca5822b78d4d3",
						"saddr": "32cdd63928854f8b2628b1dce4626ddcdf35d56cb7cfdf7d64cca5822b78d4d3"
					},
					"sigs": [
						{
							"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
							"xs": "02e89cce4499ac1e9bb498dab9e3fab93cc40cd3d26c04a0292e00f4bf272499ec"
						}
					],
					"sta": "S1",
					"ver": "4:2"
				}
			}
		}
		# "#
		# , 4, false, false, false, false);
	```
	*/

	fn init_send_tx(&self, token: Token, args: InitTxArgs) -> Result<VersionedSlate, Error>;

	/**
	;Networked version of [Owner::issue_invoice_tx](struct.Owner.html#method.issue_invoice_tx).

	```
		# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "issue_invoice_tx",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"args": {
					"amount": "6000000000",
					"dest_acct_name": null,
					"target_slate_version": null
				}
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
			"id": 1,
			"jsonrpc": "2.0",
			"result": {
				"Ok": {
					"amt": "6000000000",
					"id": "0436430c-2b02-624c-2032-570501212b00",
					"sigs": [
						{
							"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
							"xs": "02e89cce4499ac1e9bb498dab9e3fab93cc40cd3d26c04a0292e00f4bf272499ec"
						}
					],
					"sta": "I1",
					"ver": "4:2"
				}
			}
		}
		# "#
		# , 4, false, false, false, false);
	```
	*/

	fn issue_invoice_tx(
		&self,
		token: Token,
		args: IssueInvoiceTxArgs,
	) -> Result<VersionedSlate, Error>;

	/**
	;Networked version of [Owner::process_invoice_tx](struct.Owner.html#method.process_invoice_tx).

	```
		# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "process_invoice_tx",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"slate": {
					"amt": "6000000000",
					"id": "0436430c-2b02-624c-2032-570501212b00",
					"off": "d202964900000000d302964900000000d402964900000000d502964900000000",
					"sigs": [
						{
							"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
							"xs": "028e95921cc0d5be5922362265d352c9bdabe51a9e1502a3f0d4a10387f1893f40"
						}
					],
					"sta": "I1",
					"ver": "4:2"
				},
				"args": {
					"src_acct_name": null,
					"amount": "0",
					"minimum_confirmations": 2,
					"max_outputs": 500,
					"num_change_outputs": 1,
					"selection_strategy_is_use_all": true,
					"target_slate_version": null,
					"payment_proof_recipient_address": null,
					"ttl_blocks": null,
					"send_args": null
				}
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"coms": [
					{
						"c": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
						"f": 1
					},
					{
						"c": "087e4e373ef2ab9921ba53e05f384b717789ddb4ad18a8f2057c9338bd639e02a5",
						"p": "28875d797af7cb6c63eba070e0a79af57ea0a434d7d34801a02bc85624ae14a4a13519164737c7154b6222a9d6da33b8c52ef7dc4dc58aea3c776b7907e474450a52f3ccc017f66e2ce9f97a45733d6ed90a223e7d1a67802d393834cc9e4103c27bb7d63abc2753a5b54bcc48751c63b6accde16a37678338452bc985d24fb6af405a9166c0ca750f1cdedc5c0996c56f199722df3844b822de96480fac6e706dab6241d0338d7914a10a0e83406d0689224a3286e8c579c50882ce96123aecc6aa667c27abf1ce894e0c6282fc81e5fba51d498af16c5b0c39b45faf3f0cd7140dccae7d8d45330ec7895ce0c90e2490877311b9dfe157c05c6206f929ffef0da1a8d807077712a80670dfb9ac38ca565d47acf7e93bd09f418f20f10c9e87f6f4421fa889e522c33475f98ddff87a36eb0a0b445a8679628e163ae56bf3cfc39a5a5867d3e31e1e9d373a6b3924d7d895d5140e4bf00c0cbf7f343c12dc2b2c6b01769a588cc1ef1178fbf3bd645e25bf5c458c4af79884329b7ed80e08868121baeb39b11814f2dd8dddbb7114382e65378e2c6f1e837ace9a980acb965629f9f1525f60efb54301a7540a9105bf33eac1be37e1add96801f1c62857be0ac38ac370e0722764c59517960056bafe6fdd388eb78c98954f3f966d44e8f060366617844eff416625f8609b44263efc10e4f2f4fb22ceae5c16d4105e477a49511b4ac37aefac17e5532ee1ccb1654eb0bf17b32415561f02c2b07462f2c5aa7846ef21cfb30548c6bfe4d762333a199be183d7d9fa1ae6c9b4730965f741183d75ac0610efcf48d0039514011816f421a7a1a4c7c1bbc2ba8b522178cff367b4c704d343fac3a2662b50211556b630b5620244587d2f90941ef1edf8e44fa97d35daaa58d16fff3f57c6e6fa618f511dc770704d831a1f49630ec9da6f33f551923c"
					}
				],
				"fee": "23000000",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"off": "16672e6b4e2a6851b27641d8b5c32fcee83abbd516ceb9af5f0e8b6aad8d26a5",
				"sigs": [
					{
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bdac2d36fe4c972de75f4e462004de9ca3e8c77d4dae5344d210beea9ad138c45",
						"xs": "02e3c128e436510500616fef3f9a22b15ca015f407c8c5cf96c9059163c873828f"
					}
				],
				"sta": "I2",
				"ver": "4:2"
			}
		}
	}
	# "#
	# , 4, false, false, false, false);
	```
	*/

	fn process_invoice_tx(
		&self,
		token: Token,
		slate: VersionedSlate,
		args: InitTxArgs,
	) -> Result<VersionedSlate, Error>;

	/**
	Networked version of [Owner::tx_lock_outputs](struct.Owner.html#method.tx_lock_outputs).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "tx_lock_outputs",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"slate": {
				"ver": "4:2",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"sta": "S1",
				"off": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"amt": "60000000000",
				"fee": "7000000",
				"sigs": [
					{
						"xs": "030152d2d72e2dba7c6086ad49a219d9ff0dfe0fd993dcaea22e058c210033ce93",
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					}
				]
			}
		}
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 5 ,true, false, false, false);

	```
	 */
	fn tx_lock_outputs(&self, token: Token, slate: VersionedSlate) -> Result<(), Error>;

	/**
	Networked version of [Owner::finalize_tx](struct.Owner.html#method.finalize_tx).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "finalize_tx",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"slate":
			{
				"ver": "4:2",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"sta": "S2",
				"off": "6c6a69136154775488782121887bb3c32787a8320551fdb9732ec2d333fe54ee",
				"sigs": [
					{
						"xs": "02e3c128e436510500616fef3f9a22b15ca015f407c8c5cf96c9059163c873828f",
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841be7bf31d80494f5e4a3d656649b1610c61a268f9cafcfc604b5d9f25efb2aa3c5"
					}
				],
				"coms": [
					{
						"c": "099b48cfb1f80a2347dc89818449e68e76a3c6817a532a8e9ef2b4a5ccf4363850",
						"p": "29701ceae262cac77b79b868c883a292e61e6de8192b868edcd1300b0973d91396b156ace6bd673402a303de10ddd8a5e6b7f17ba6557a574a672bd04cc273ab04ed8e2ca80bac483345c0ec843f521814ce1301ec9adc38956a12b4d948acce71295a4f52bcdeb8a1c9f2d6b2da5d731262a5e9c0276ef904df9ef8d48001420cd59f75a2f1ae5c7a1c7c6b9f140e7613e52ef9e249f29f9340b7efb80699e460164324616f98fd4cde3db52497c919e95222fffeacb7e65deca7e368a80ce713c19de7da5369726228ee336f5bd494538c12ccbffeb1b9bfd5fc8906d1c64245b516f103fa96d9c56975837652c1e0fa5803d7ccf1147d8f927e36da717f7ad79471dbe192f5f50f87a79fc3fe030dba569b634b92d2cf307993cce545633af263897cd7e6ebf4dcafb176d07358bdc38d03e45a49dfa9c8c6517cd68d167ffbf6c3b4de0e2dd21909cbad4c467b84e5700be473a39ac59c669d7c155c4bcab9b8026eea3431c779cd277e4922d2b9742e1f6678cbe869ec3b5b7ef4132ddb6cdd06cf27dbeb28be72b949fa897610e48e3a0d789fd2eea75abc97b3dc7e00e5c8b3d24e40c6f24112adb72352b89a2bef0599345338e9e76202a3c46efa6370952b2aca41aadbae0ea32531acafcdab6dd066d769ebf50cf4f3c0a59d2d5fa79600a207b9417c623f76ad05e8cccfcd4038f9448bc40f127ca7c0d372e46074e334fe49f5a956ec0056f4da601e6af80eb1a6c4951054869e665b296d8c14f344ca2dc5fdd5df4a3652536365a1615ad9b422165c77bf8fe65a835c8e0c41e070014eb66ef8c525204e990b3a3d663c1e42221b496895c37a2f0c1bf05e91235409c3fe3d89a9a79d6c78609ab18a463311911f71fa37bb73b15fcd38143d1404fd2ce81004dc7ff89cf1115dcc0c35ce1c1bf9941586fb959770f2618ccb7118a7"
					}
				]
			}
		}
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"Ok": {
				"coms": [
					{
						"c": "087df32304c5d4ae8b2af0bc31e700019d722910ef87dd4eec3197b80b207e3045",
						"f": 1
					},
					{
						"c": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
						"f": 1
					},
					{
						"c": "099b48cfb1f80a2347dc89818449e68e76a3c6817a532a8e9ef2b4a5ccf4363850",
						"p": "29701ceae262cac77b79b868c883a292e61e6de8192b868edcd1300b0973d91396b156ace6bd673402a303de10ddd8a5e6b7f17ba6557a574a672bd04cc273ab04ed8e2ca80bac483345c0ec843f521814ce1301ec9adc38956a12b4d948acce71295a4f52bcdeb8a1c9f2d6b2da5d731262a5e9c0276ef904df9ef8d48001420cd59f75a2f1ae5c7a1c7c6b9f140e7613e52ef9e249f29f9340b7efb80699e460164324616f98fd4cde3db52497c919e95222fffeacb7e65deca7e368a80ce713c19de7da5369726228ee336f5bd494538c12ccbffeb1b9bfd5fc8906d1c64245b516f103fa96d9c56975837652c1e0fa5803d7ccf1147d8f927e36da717f7ad79471dbe192f5f50f87a79fc3fe030dba569b634b92d2cf307993cce545633af263897cd7e6ebf4dcafb176d07358bdc38d03e45a49dfa9c8c6517cd68d167ffbf6c3b4de0e2dd21909cbad4c467b84e5700be473a39ac59c669d7c155c4bcab9b8026eea3431c779cd277e4922d2b9742e1f6678cbe869ec3b5b7ef4132ddb6cdd06cf27dbeb28be72b949fa897610e48e3a0d789fd2eea75abc97b3dc7e00e5c8b3d24e40c6f24112adb72352b89a2bef0599345338e9e76202a3c46efa6370952b2aca41aadbae0ea32531acafcdab6dd066d769ebf50cf4f3c0a59d2d5fa79600a207b9417c623f76ad05e8cccfcd4038f9448bc40f127ca7c0d372e46074e334fe49f5a956ec0056f4da601e6af80eb1a6c4951054869e665b296d8c14f344ca2dc5fdd5df4a3652536365a1615ad9b422165c77bf8fe65a835c8e0c41e070014eb66ef8c525204e990b3a3d663c1e42221b496895c37a2f0c1bf05e91235409c3fe3d89a9a79d6c78609ab18a463311911f71fa37bb73b15fcd38143d1404fd2ce81004dc7ff89cf1115dcc0c35ce1c1bf9941586fb959770f2618ccb7118a7"
					},
					{
						"c": "09ede20409d5ae0d1c0d3f3d2c68038a384cdd6b7cc5ca2aab670f570adc2dffc3",
						"p": "6d86fe00220f8c6ac2ad4e338d80063dba5423af525bd273ecfac8ef6b509192732a8cd0c53d3313e663ac5ccece3d589fd2634e29f96e82b99ca6f8b953645a005d1bc73493f8c41f84fb8e327d4cbe6711dba194a60db30700df94a41e1fda7afe0619169389f8d8ee12bddf736c4bc86cd5b1809a5a27f195209147dc38d0de6f6710ce9350f3b8e7e6820bfe5182e6e58f0b41b82b6ec6bb01ffe1d8b3c2368ebf1e31dfdb9e00f0bc68d9119a38d19c038c29c7b37e31246e7bba56019bc88881d7d695d32557fc0e93635b5f24deffefc787787144e5de7e86281e79934e7e20d9408c34317c778e6b218ee26d0a5e56b8b84a883e3ddf8603826010234531281486454f8c2cf3fee074f242f9fc1da3c6636b86fb6f941eb8b633d6e3b3f87dfe5ae261a40190bd4636f433bcdd5e3400255594e282c5396db8999d95be08a35be9a8f70fdb7cf5353b90584523daee6e27e208b2ca0e5758b8a24b974dca00bab162505a2aa4bcefd8320f111240b62f861261f0ce9b35979f9f92da7dd6989fe1f41ec46049fd514d9142ce23755f52ec7e64df2af33579e9b8356171b91bc96b875511bef6062dd59ef3fe2ddcc152147554405b12c7c5231513405eb062aa8fa093e3414a144c544d551c4f1f9bf5d5d2ff5b50a3f296c800907704bed8d8ee948c0855eff65ad44413af641cdc68a06a7c855be7ed7dd64d5f623bbc9645763d48774ba2258240a83f8f89ef84d21c65bcb75895ebca08b0090b40aafb7ddef039fcaf4bad2dbbac72336c4412c600e854d368ed775597c15d2e66775ab47024ce7e62fd31bf90b183149990c10b5b678501dbac1af8b2897b67d085d87cab7af4036cba3bdcfdcc7548d7710511045813c6818d859e192e03adc0d6a6b30c4cbac20a0d6f8719c7a9c3ad46d62eec464c4c44b58fca463fea3ce1fc51"
					}
				],
				"fee": "23500000",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"off": "a5a632f26f27a9b71e98c1c8b8098bb41204ffcfd206d995f9c16d10764ad95a",
				"sigs": [
					{
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841be7bf31d80494f5e4a3d656649b1610c61a268f9cafcfc604b5d9f25efb2aa3c5",
						"xs": "02e3c128e436510500616fef3f9a22b15ca015f407c8c5cf96c9059163c873828f"
					},
					{
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b04e1e15ceb1b5dbab8baf7750d7bd4aad6cfe97b83e4dc080dae328eb75881fd",
						"xs": "02e89cce4499ac1e9bb498dab9e3fab93cc40cd3d26c04a0292e00f4bf272499ec"
					}
				],
				"sta": "S3",
				"ver": "4:2"
			}
		}
	}
	# "#
	# , 5, true, true, false, false);
	```
	 */
	fn finalize_tx(&self, token: Token, slate: VersionedSlate) -> Result<VersionedSlate, Error>;

	/**
	Networked version of [Owner::post_tx](struct.Owner.html#method.post_tx).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"method": "post_tx",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"slate": {
				"ver": "4:2",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"sta": "S3",
				"off": "750dbf4fd43b7f4cfd68d2698a522f3ff6e6a00ad9895b33f1ec46493b837b49",
				"fee": "23500000",
				"sigs": [
					{
						"xs": "033bbe2a419ea2e9d6810a8d66552e709d1783ca50759a44dbaf63fc79c0164c4c",
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b92c7c53280dd79f8b028cd9863bac89820267cac794b121e217541efb061ad53"
					},
					{
						"xs": "02b57c1f4fea69a3ee070309cf8f06082022fe06f25a9be1851b56ef0fa18f25d6",
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b4cd4afef1cd2d708100cd1680d6566e4e987ac5c939ace9c0e036a679121c7a8"
					}
				],
				"coms": [
					{
						"f": 1,
						"c": "087df32304c5d4ae8b2af0bc31e700019d722910ef87dd4eec3197b80b207e3045"
					},
					{
						"f": 1,
						"c": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7"
					},
					{
						"c": "099b48cfb1f80a2347dc89818449e68e76a3c6817a532a8e9ef2b4a5ccf4363850",
						"p": "29701ceae262cac77b79b868c883a292e61e6de8192b868edcd1300b0973d91396b156ace6bd673402a303de10ddd8a5e6b7f17ba6557a574a672bd04cc273ab04ed8e2ca80bac483345c0ec843f521814ce1301ec9adc38956a12b4d948acce71295a4f52bcdeb8a1c9f2d6b2da5d731262a5e9c0276ef904df9ef8d48001420cd59f75a2f1ae5c7a1c7c6b9f140e7613e52ef9e249f29f9340b7efb80699e460164324616f98fd4cde3db52497c919e95222fffeacb7e65deca7e368a80ce713c19de7da5369726228ee336f5bd494538c12ccbffeb1b9bfd5fc8906d1c64245b516f103fa96d9c56975837652c1e0fa5803d7ccf1147d8f927e36da717f7ad79471dbe192f5f50f87a79fc3fe030dba569b634b92d2cf307993cce545633af263897cd7e6ebf4dcafb176d07358bdc38d03e45a49dfa9c8c6517cd68d167ffbf6c3b4de0e2dd21909cbad4c467b84e5700be473a39ac59c669d7c155c4bcab9b8026eea3431c779cd277e4922d2b9742e1f6678cbe869ec3b5b7ef4132ddb6cdd06cf27dbeb28be72b949fa897610e48e3a0d789fd2eea75abc97b3dc7e00e5c8b3d24e40c6f24112adb72352b89a2bef0599345338e9e76202a3c46efa6370952b2aca41aadbae0ea32531acafcdab6dd066d769ebf50cf4f3c0a59d2d5fa79600a207b9417c623f76ad05e8cccfcd4038f9448bc40f127ca7c0d372e46074e334fe49f5a956ec0056f4da601e6af80eb1a6c4951054869e665b296d8c14f344ca2dc5fdd5df4a3652536365a1615ad9b422165c77bf8fe65a835c8e0c41e070014eb66ef8c525204e990b3a3d663c1e42221b496895c37a2f0c1bf05e91235409c3fe3d89a9a79d6c78609ab18a463311911f71fa37bb73b15fcd38143d1404fd2ce81004dc7ff89cf1115dcc0c35ce1c1bf9941586fb959770f2618ccb7118a7"
					},
					{
						"c": "09ede20409d5ae0d1c0d3f3d2c68038a384cdd6b7cc5ca2aab670f570adc2dffc3",
						"p": "6d86fe00220f8c6ac2ad4e338d80063dba5423af525bd273ecfac8ef6b509192732a8cd0c53d3313e663ac5ccece3d589fd2634e29f96e82b99ca6f8b953645a005d1bc73493f8c41f84fb8e327d4cbe6711dba194a60db30700df94a41e1fda7afe0619169389f8d8ee12bddf736c4bc86cd5b1809a5a27f195209147dc38d0de6f6710ce9350f3b8e7e6820bfe5182e6e58f0b41b82b6ec6bb01ffe1d8b3c2368ebf1e31dfdb9e00f0bc68d9119a38d19c038c29c7b37e31246e7bba56019bc88881d7d695d32557fc0e93635b5f24deffefc787787144e5de7e86281e79934e7e20d9408c34317c778e6b218ee26d0a5e56b8b84a883e3ddf8603826010234531281486454f8c2cf3fee074f242f9fc1da3c6636b86fb6f941eb8b633d6e3b3f87dfe5ae261a40190bd4636f433bcdd5e3400255594e282c5396db8999d95be08a35be9a8f70fdb7cf5353b90584523daee6e27e208b2ca0e5758b8a24b974dca00bab162505a2aa4bcefd8320f111240b62f861261f0ce9b35979f9f92da7dd6989fe1f41ec46049fd514d9142ce23755f52ec7e64df2af33579e9b8356171b91bc96b875511bef6062dd59ef3fe2ddcc152147554405b12c7c5231513405eb062aa8fa093e3414a144c544d551c4f1f9bf5d5d2ff5b50a3f296c800907704bed8d8ee948c0855eff65ad44413af641cdc68a06a7c855be7ed7dd64d5f623bbc9645763d48774ba2258240a83f8f89ef84d21c65bcb75895ebca08b0090b40aafb7ddef039fcaf4bad2dbbac72336c4412c600e854d368ed775597c15d2e66775ab47024ce7e62fd31bf90b183149990c10b5b678501dbac1af8b2897b67d085d87cab7af4036cba3bdcfdcc7548d7710511045813c6818d859e192e03adc0d6a6b30c4cbac20a0d6f8719c7a9c3ad46d62eec464c4c44b58fca463fea3ce1fc51"
					}
				]
			},
		"fluff": false
		}
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 5, true, true, true, false);
	```
	 */

	fn post_tx(&self, token: Token, slate: VersionedSlate, fluff: bool) -> Result<(), Error>;

	/**
	Networked version of [Owner::cancel_tx](struct.Owner.html#method.cancel_tx).


	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "cancel_tx",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"tx_id": null,
			"tx_slate_id": "0436430c-2b02-624c-2032-570501212b00"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 5, true, true, false, false);
	```
	 */
	fn cancel_tx(
		&self,
		token: Token,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(), Error>;

	/**
	Networked version of [Owner::get_stored_tx](struct.Owner.html#method.get_stored_tx).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_stored_tx",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"id": null,
			"slate_id": "0436430c-2b02-624c-2032-570501212b00"
		}
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"Ok": {
				"coms": [
					{
						"c": "099b48cfb1f80a2347dc89818449e68e76a3c6817a532a8e9ef2b4a5ccf4363850",
						"p": "29701ceae262cac77b79b868c883a292e61e6de8192b868edcd1300b0973d91396b156ace6bd673402a303de10ddd8a5e6b7f17ba6557a574a672bd04cc273ab04ed8e2ca80bac483345c0ec843f521814ce1301ec9adc38956a12b4d948acce71295a4f52bcdeb8a1c9f2d6b2da5d731262a5e9c0276ef904df9ef8d48001420cd59f75a2f1ae5c7a1c7c6b9f140e7613e52ef9e249f29f9340b7efb80699e460164324616f98fd4cde3db52497c919e95222fffeacb7e65deca7e368a80ce713c19de7da5369726228ee336f5bd494538c12ccbffeb1b9bfd5fc8906d1c64245b516f103fa96d9c56975837652c1e0fa5803d7ccf1147d8f927e36da717f7ad79471dbe192f5f50f87a79fc3fe030dba569b634b92d2cf307993cce545633af263897cd7e6ebf4dcafb176d07358bdc38d03e45a49dfa9c8c6517cd68d167ffbf6c3b4de0e2dd21909cbad4c467b84e5700be473a39ac59c669d7c155c4bcab9b8026eea3431c779cd277e4922d2b9742e1f6678cbe869ec3b5b7ef4132ddb6cdd06cf27dbeb28be72b949fa897610e48e3a0d789fd2eea75abc97b3dc7e00e5c8b3d24e40c6f24112adb72352b89a2bef0599345338e9e76202a3c46efa6370952b2aca41aadbae0ea32531acafcdab6dd066d769ebf50cf4f3c0a59d2d5fa79600a207b9417c623f76ad05e8cccfcd4038f9448bc40f127ca7c0d372e46074e334fe49f5a956ec0056f4da601e6af80eb1a6c4951054869e665b296d8c14f344ca2dc5fdd5df4a3652536365a1615ad9b422165c77bf8fe65a835c8e0c41e070014eb66ef8c525204e990b3a3d663c1e42221b496895c37a2f0c1bf05e91235409c3fe3d89a9a79d6c78609ab18a463311911f71fa37bb73b15fcd38143d1404fd2ce81004dc7ff89cf1115dcc0c35ce1c1bf9941586fb959770f2618ccb7118a7"
					}
				],
				"fee": "23500000",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"sigs": [],
				"sta": "S3",
				"ver": "4:3"
			}
		}
	}
	# "#
	# , 5, true, true, false, false);
	```
	 */
	fn get_stored_tx(
		&self,
		token: Token,
		id: Option<u32>,
		slate_id: Option<Uuid>,
	) -> Result<Option<VersionedSlate>, Error>;

	/**
	Networked version of [Owner::get_rewind_hash](struct.Owner.html#method.get_rewind_hash).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_rewind_hash",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id":1,
		"jsonrpc":"2.0",
		"result":{
			"Ok":"c820c52a492b7db511c752035483d0e50e8fd3ec62544f1b99638e220a4682de"
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	 */
	fn get_rewind_hash(&self, token: Token) -> Result<String, Error>;

	/**
	Networked version of [Owner::scan_rewind_hash](struct.Owner.html#method.scan_rewind_hash).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "scan_rewind_hash",
		"params": {
			"rewind_hash": "c820c52a492b7db511c752035483d0e50e8fd3ec62544f1b99638e220a4682de",
			"start_height": 1
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id":1,
		"jsonrpc":"2.0",
		"result":{
			"Ok":{
				"last_pmmr_index":8,
				"output_result":[
					   {
						   "commit":"08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
						   "height":1,
						   "is_coinbase":true,
						   "lock_height":4,
						   "mmr_index":1,
						   "value":60000000000
					   },
					   {
						   "commit":"087df32304c5d4ae8b2af0bc31e700019d722910ef87dd4eec3197b80b207e3045",
						   "height":2,
						   "is_coinbase":true,
						   "lock_height":5,
						   "mmr_index":2,
						   "value":60000000000
					   },
					   {
						   "commit":"084219d64014223a205431acfa8f8cc3e8cb8c6d04df80b26713314becf83861c7",
						   "height":3,
						   "is_coinbase":true,
						   "lock_height":6,
						   "mmr_index":4,
						   "value":60000000000
					   },
					   {
						   "commit":"09c5efc4dab05d7d16fc90168c484c13f15a142ea4e1bf93c3fad12f5e8a402598",
						   "height":4,
						   "is_coinbase":true,
						   "lock_height":7,
						   "mmr_index":5,
						   "value":60000000000
					   },
					   {
						   "commit":"08fe198e525a5937d0c5d01fa354394d2679be6df5d42064a0f7550c332fce3d9d",
						   "height":5,
						   "is_coinbase":true,
						   "lock_height":8,
						   "mmr_index":8,
						   "value":60000000000
					   }
				],
				"rewind_hash":"c820c52a492b7db511c752035483d0e50e8fd3ec62544f1b99638e220a4682de",
				"total_balance":300000000000
			}
		}
	 }
	# "#
	# , 5, false, false, false, false);
	```
	 */
	fn scan_rewind_hash(
		&self,
		rewind_hash: String,
		start_height: Option<u64>,
	) -> Result<ViewWallet, Error>;

	/**
	Networked version of [Owner::scan](struct.Owner.html#method.scan).


	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "scan",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"start_height": 1,
			"delete_unconfirmed": false
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 1, false, false, false, false);
	```
	 */
	fn scan(
		&self,
		token: Token,
		start_height: Option<u64>,
		delete_unconfirmed: bool,
	) -> Result<(), Error>;

	/**
	Networked version of [Owner::node_height](struct.Owner.html#method.node_height).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "node_height",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"header_hash": "d4b3d3c40695afd8c7760f8fc423565f7d41310b7a4e1c4a4a7950a66f16240d",
				"height": "5",
				"updated_from_node": true
			}
		}
	}
	# "#
	# , 5, false, false, false, false);
	```
	 */
	fn node_height(&self, token: Token) -> Result<NodeHeightResult, Error>;

	/**
		Initializes the secure JSON-RPC API. This function must be called and a shared key
		established before any other OwnerAPI JSON-RPC function can be called.

		The shared key will be derived using ECDH with the provided public key on the secp256k1 curve. This
		function will return its public key used in the derivation, which the caller should multiply by its
		private key to derive the shared key.

		Once the key is established, all further requests and responses are encrypted and decrypted with the
		following parameters:
		* AES-256 in GCM mode with 128-bit tags and 96 bit nonces
		* 12 byte nonce which must be included in each request/response to use on the decrypting side
		* Empty vector for additional data
		* Suffix length = AES-256 GCM mode tag length = 16 bytes
		*

		Fully-formed JSON-RPC requests (as documented) should be encrypted using these parameters, encoded
		into base64 and included with the one-time nonce in a request for the `encrypted_request_v3` method
		as follows:

		```
		# let s = r#"
		{
			 "jsonrpc": "2.0",
			 "method": "encrypted_request_v3",
			 "id": "1",
			 "params": {
					"nonce": "ef32...",
					"body_enc": "e0bcd..."
			 }
		}
		# "#;
		```

		With a typical response being:

		```
		# let s = r#"{
		{
			 "jsonrpc": "2.0",
			 "method": "encrypted_response_v3",
			 "id": "1",
			 "Ok": {
					"nonce": "340b...",
					"body_enc": "3f09c..."
			 }
		}
		# }"#;
		```

	*/

	fn init_secure_api(&self, ecdh_pubkey: ECDHPubkey) -> Result<ECDHPubkey, Error>;

	/**
	Networked version of [Owner::get_top_level_directory](struct.Owner.html#method.get_top_level_directory).

	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_top_level_directory",
		"params": {
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "/doctest/dir"
		}
	}
	# "#
	# , 5, false, false, false, false);
	```
	*/

	fn get_top_level_directory(&self) -> Result<String, Error>;

	/**
	Networked version of [Owner::set_top_level_directory](struct.Owner.html#method.set_top_level_directory).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "set_top_level_directory",
		"params": {
			"dir": "/home/wallet_user/my_wallet_dir"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 5, false, false, false, false);
	```
	*/

	fn set_top_level_directory(&self, dir: String) -> Result<(), Error>;

	/**
	Networked version of [Owner::create_config](struct.Owner.html#method.create_config).

	Both the `wallet_config` and `logging_config` parameters can be `null`, the examples
	below are for illustration. Note that the values provided for `log_file_path` and `data_file_dir`
	will be ignored and replaced with the actual values based on the value of `get_top_level_directory`
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_config",
		"params": {
			"chain_type": "Mainnet",
			"wallet_config": {
				"chain_type": null,
				"api_listen_interface": "127.0.0.1",
				"api_listen_port": 3415,
				"owner_api_listen_port": 3420,
				"api_secret_path": null,
				"node_api_secret_path": null,
				"check_node_api_http_addr": "http://127.0.0.1:3413",
				"owner_api_include_foreign": false,
				"data_file_dir": "/path/to/data/file/dir",
				"no_commit_cache": null,
				"tls_certificate_file": null,
				"tls_certificate_key": null,
				"dark_background_color_scheme": null
			},
			"logging_config": {
				"log_to_stdout": false,
				"stdout_log_level": "Info",
				"log_to_file": true,
				"file_log_level": "Debug",
				"log_file_path": "/path/to/log/file",
				"log_file_append": true,
				"log_max_size": null,
				"log_max_files": null,
				"tui_running": null
			},
			"tor_config" : {
				"use_tor_listener": true,
				"socks_proxy_addr": "127.0.0.1:9050",
				"send_config_dir": "."
			}
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 5, false, false, false, false);
	```
	*/
	fn create_config(
		&self,
		chain_type: global::ChainTypes,
		wallet_config: Option<WalletConfig>,
		logging_config: Option<LoggingConfig>,
		tor_config: Option<TorConfig>,
	) -> Result<(), Error>;

	/**
	Networked version of [Owner::create_wallet](struct.Owner.html#method.create_wallet).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_wallet",
		"params": {
			"name": null,
			"mnemonic": null,
			"mnemonic_length": 32,
			"password": "my_secret_password"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn create_wallet(
		&self,
		name: Option<String>,
		mnemonic: Option<String>,
		mnemonic_length: u32,
		password: String,
	) -> Result<(), Error>;

	/**
	Networked version of [Owner::open_wallet](struct.Owner.html#method.open_wallet).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "open_wallet",
		"params": {
			"name": null,
			"password": "my_secret_password"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "d096b3cb75986b3b13f80b8f5243a9edf0af4c74ac37578c5a12cfb5b59b1868"
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn open_wallet(&self, name: Option<String>, password: String) -> Result<Token, Error>;

	/**
	Networked version of [Owner::close_wallet](struct.Owner.html#method.close_wallet).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "close_wallet",
		"params": {
			"name": null
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn close_wallet(&self, name: Option<String>) -> Result<(), Error>;

	/**
	Networked version of [Owner::get_mnemonic](struct.Owner.html#method.get_mnemonic).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_mnemonic",
		"params": {
			"name": null,
			"password": ""
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "fat twenty mean degree forget shell check candy immense awful flame next during february bulb bike sun wink theory day kiwi embrace peace lunch"
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn get_mnemonic(&self, name: Option<String>, password: String) -> Result<String, Error>;

	/**
	Networked version of [Owner::change_password](struct.Owner.html#method.change_password).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "change_password",
		"params": {
			"name": null,
			"old": "",
			"new": "new_password"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/
	fn change_password(&self, name: Option<String>, old: String, new: String) -> Result<(), Error>;

	/**
	Networked version of [Owner::delete_wallet](struct.Owner.html#method.delete_wallet).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "delete_wallet",
		"params": {
			"name": null
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/
	fn delete_wallet(&self, name: Option<String>) -> Result<(), Error>;

	/**
	Networked version of [Owner::start_updated](struct.Owner.html#method.start_updater).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "start_updater",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"frequency": 30000
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn start_updater(&self, token: Token, frequency: u32) -> Result<(), Error>;

	/**
	Networked version of [Owner::stop_updater](struct.Owner.html#method.stop_updater).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "stop_updater",
		"params": null,
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/
	fn stop_updater(&self) -> Result<(), Error>;

	/**
	Networked version of [Owner::get_updater_messages](struct.Owner.html#method.get_updater_messages).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_updater_messages",
		"params": {
			"count": 1
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": []
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn get_updater_messages(&self, count: u32) -> Result<Vec<StatusMessage>, Error>;

	/**
	Networked version of [Owner::get_slatepack_address](struct.Owner.html#method.get_slatepack_address).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_slatepack_address",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"derivation_index": 0
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "tgrin1xtxavwfgs48ckf3gk8wwgcndmn0nt4tvkl8a7ltyejjcy2mc6nfs9gm2lp"
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn get_slatepack_address(
		&self,
		token: Token,
		derivation_index: u32,
	) -> Result<SlatepackAddress, Error>;

	/**
	Networked version of [Owner::get_slatepack_secret_key](struct.Owner.html#method.get_slatepack_secret_key).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_slatepack_secret_key",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"derivation_index": 0
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "86cca2aedea7989dfcca62e54477301d098bac260656d11373e314c099f0b26f"
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn get_slatepack_secret_key(
		&self,
		token: Token,
		derivation_index: u32,
	) -> Result<Ed25519SecretKey, Error>;

	/**
	Networked version of [Owner::create_slatepack_message](struct.Owner.html#method.create_slatepack_message).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_slatepack_message",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"sender_index": 0,
			"recipients": [],
			"slate": {
				"ver": "4:2",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"sta": "S1",
				"off": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"amt": "60000000000",
				"fee": "7000000",
				"sigs": [
					{
						"xs": "030152d2d72e2dba7c6086ad49a219d9ff0dfe0fd993dcaea22e058c210033ce93",
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					}
				]
			}
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "BEGINSLATEPACK. xyfzdULuUuM5r3R kS68aywyCuYssPs Jf1JbvnBcK6NDDo ajiGAgh2SPx4t49 xtKuJE3BZCcSEue ksecMmbSoV2DQbX gGcmJniP9UadcmR N1KSc5FBhwAaUjy LXeYDP7EV7Cmsj4 pLaJdZTJTQbccUH 2zG8QTgoEiEWP5V T6rKst1TibmDAFm RRVHYDtskdYJb5G krqfpgN7RjvPfpm Z5ZFyz6ipAt5q9T 2HCjrTxkHdVi9js 22tr2Lx6iXT5vm8 JL6HhjwyFrSaEmN AjsBE8jgiaAABA6 GGZKwcXeXToMfRt nL9DeX1. ENDSLATEPACK."
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn create_slatepack_message(
		&self,
		token: Token,
		slate: VersionedSlate,
		sender_index: Option<u32>,
		recipients: Vec<SlatepackAddress>,
	) -> Result<String, Error>;

	/**
	Networked version of [Owner::slate_from_slatepack_message](struct.Owner.html#method.slate_from_slatepack_message).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "slate_from_slatepack_message",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"secret_indices": [0],
			"message": "BEGINSLATEPACK. 8GQrdcwdLKJD28F 3a9siP7ZhZgAh7w BR2EiZHza5WMWmZ Cc8zBUemrrYRjhq j3VBwA8vYnvXXKU BDmQBN2yKgmR8mX UzvXHezfznA61d7 qFZYChhz94vd8Ew NEPLz7jmcVN2C3w wrfHbeiLubYozP2 uhLouFiYRrbe3fQ 4uhWGfT3sQYXScT dAeo29EaZJpfauh j8VL5jsxST2SPHq nzXFC2w9yYVjt7D ju7GSgHEp5aHz9R xstGbHjbsb4JQod kYLuELta1ohUwDD pvjhyJmsbLcsPei k5AQhZsJ8RJGBtY bou6cU7tZeFJvor 4LB9CBfFB3pmVWD vSLd5RPS75dcnHP nbXD8mSDZ8hJS2Q A9wgvppWzuWztJ2 dLUU8f9tLJgsRBw YZAs71HiVeg7. ENDSLATEPACK."
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"amt": "6000000000",
				"fee": "8000000",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"off": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"proof": {
					"raddr": "783f6528669742a990e0faf0a5fca5d5b3330e37bbb9cd5c628696d03ce4e810",
					"saddr": "32cdd63928854f8b2628b1dce4626ddcdf35d56cb7cfdf7d64cca5822b78d4d3"
				},
				"sigs": [
					{
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"xs": "023878ce845727f3a4ec76ca3f3db4b38a2d05d636b8c3632108b857fed63c96de"
					}
				],
				"sta": "S1",
				"ver": "4:2"
			}
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn slate_from_slatepack_message(
		&self,
		token: Token,
		message: String,
		secret_indices: Vec<u32>,
	) -> Result<VersionedSlate, Error>;

	/**
	Networked version of [Owner::decode_slatepack_message](struct.Owner.html#method.decode_slatepack_message).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "decode_slatepack_message",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"secret_indices": [0],
			"message": "BEGINSLATEPACK. t9EcGgrKr1GFCQB SK2jPCxME6Hgpqx bntpQm3zKFycoPY nW4UeoL4KQ7ExNK At6EQsvpz6MjUs8 6WG8KHEbMfqufJQ ZJTw2gkcdJmJjiJ f29oGgYqqXDZox4 ujPSjrtoxCN4h3e i1sZ8dYsm3dPeXL 7VQLsYNjAefciqj ZJXPm4Pqd7VDdd4 okGBGBu3YJvYzT6 arAxeCEx66us31h AJLcDweFwyWBkW5 J1DLiYAjt5ftFTo CjpfW9KjiLq2LM5 jepXWEHJPSDAYVK 4macDZUhRbJiG6E hrQcPrJBVC716mb Hw5E1PFrE6on5wq oEmrS4j9vaB5nw8 Z9ZyXvPc2LN7tER yt6pSHZeY9EpYdY zv4bthzfRfF8ePT TMeMpV2gpgyRXQa CPD2TR. ENDSLATEPACK."
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"mode": 0,
				"payload": "AAQAAgQ2QwwrAmJMIDJXBQEhKwAB0gKWSQAAAADTApZJAAAAANQClkkAAAAA1QKWSQAAAAAGAAAAAWWgvAAAAAAAAHoSAAEAAjh4zoRXJ/Ok7HbKPz20s4otBdY2uMNjIQi4V/7WPJbeAxuExVZ7EmRAmV0+1aq6BWXXHhg0YEgZ/5wX9enV3QePAjLN1jkohU+LJiix3ORibdzfNdVst8/ffWTMpYIreNTTeD9lKGaXQqmQ4Prwpfyl1bMzDje7uc1cYoaW0Dzk6BAA",
				"sender": "tgrin1xtxavwfgs48ckf3gk8wwgcndmn0nt4tvkl8a7ltyejjcy2mc6nfs9gm2lp",
				"slatepack": "1.0"
			}
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/

	fn decode_slatepack_message(
		&self,
		token: Token,
		message: String,
		secret_indices: Vec<u32>,
	) -> Result<Slatepack, Error>;

	/**
	Networked version of [Owner::retrieve_payment_proof](struct.Owner.html#method.retrieve_payment_proof).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_payment_proof",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"refresh_from_node": true,
			"tx_id": null,
			"tx_slate_id": "0436430c-2b02-624c-2032-570501212b00"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"amount": "60000000000",
				"excess": "09eac5f5872fa5e08e0c29fd900f1b8f77ff3ad1d0d1c46aeb202cbf92363fe0af",
				"recipient_address": "tgrin10qlk22rxjap2ny8qltc2tl996kenxr3hhwuu6hrzs6tdq08yaqgqq6t83r",
				"recipient_sig": "02868f2d2b983981f8f98043701687a8531ed2de564ea3df48e9e7e0229ccbe8359efe506896df2efbe3528e977252c50e4a41ca3cc9896e7c5a30bbb1d33604",
				"sender_address": "tgrin1xtxavwfgs48ckf3gk8wwgcndmn0nt4tvkl8a7ltyejjcy2mc6nfs9gm2lp",
				"sender_sig": "c511764f3f61ed3d1cbca9514df8bc6811fad5662b1cb0e0587b9c9e49db9f33183cce71af6cb24b507fabf525a2bc405c6e84e63a60334edff0b451ae5e6102"
			}
		}
	}
	# "#
	# , 5, true, true, true, true);
	```
	*/

	fn retrieve_payment_proof(
		&self,
		token: Token,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<PaymentProof, Error>;

	/**
	Networked version of [Owner::verify_payment_proof](struct.Owner.html#method.verify_payment_proof).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "verify_payment_proof",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"proof": {
				"amount": "60000000000",
				"excess": "09eac5f5872fa5e08e0c29fd900f1b8f77ff3ad1d0d1c46aeb202cbf92363fe0af",
				"recipient_address": "slatepack10qlk22rxjap2ny8qltc2tl996kenxr3hhwuu6hrzs6tdq08yaqgqnlumr7",
				"recipient_sig": "02868f2d2b983981f8f98043701687a8531ed2de564ea3df48e9e7e0229ccbe8359efe506896df2efbe3528e977252c50e4a41ca3cc9896e7c5a30bbb1d33604",
				"sender_address": "slatepack1xtxavwfgs48ckf3gk8wwgcndmn0nt4tvkl8a7ltyejjcy2mc6nfskdvkdu",
				"sender_sig": "c511764f3f61ed3d1cbca9514df8bc6811fad5662b1cb0e0587b9c9e49db9f33183cce71af6cb24b507fabf525a2bc405c6e84e63a60334edff0b451ae5e6102"
			}
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				true,
				false
			]
		}
	}
	# "#
	# , 5, true, true, true, true);
	```
	*/

	fn verify_payment_proof(
		&self,
		token: Token,
		proof: PaymentProof,
	) -> Result<(bool, bool), Error>;

	/**
	Networked version of [Owner::set_tor_config](struct.Owner.html#method.set_tor_config).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "set_tor_config",
		"params": {
			"tor_config": {
				"use_tor_listener": true,
				"socks_proxy_addr": "127.0.0.1:59050",
				"send_config_dir": "."
			}
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/
	fn set_tor_config(&self, tor_config: Option<TorConfig>) -> Result<(), Error>;

	/**
	Networked version of [Owner::build_output](struct.Owner.html#method.build_output).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "build_output",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"features": "Plain",
			"amount":  "60000000000"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"blind": "089705aa74b638ee391e295d227c534a50dd58e603bca97a4404747cf8a5a189",
				"key_id": "0300000000000000000000000000000000",
				"output": {
					"commit": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
					"features": "Plain",
					"proof": "4b5d6fb1b4d143fc50c83aef61c5410be760a395ed71f3424f7746bf5ee0539ae299569d99b73ea6583b1057834551faa0ac8cfe34c75431b86d6f37dec1ff070fc01f44babf0d3446781564ff7a143242ea67cb4ff7b11fe399735695c3fe70b40b71f31b04cf73b1d1f3430fb53a8c9f990fae48c09b42f8212d60a2d3ce0b8ea4dc0d37a82c3f328162ab8d50f48c28cb9a721a87a40aa3915bf9fffc0cd820e15b758e8565ad7fbf22d03711dc83f98e7c9f955d9398a1c75bc96df2ee64751592953cced38527b3f68282d2ca2fdf2994fbd93a1642fb9d265d57c3cf7df01501da569f2b4e606a1c3084c807a39947a3e1fd41b0647891e1f64842a2b98e694b93857e30691e0b0bca7bc49dec9d6af1003a40b3431ae0bcae8454a438523d066dcac4f194d8370c5ba6567830f302e1ec2607b8d1720bb6c6c57c549f1a3ef7ad2b54dfdd0178329e0723b8a55b438a1e43a984c072d6505aa5e193042d9703484c8383e78d9553684fad5e399f11f8ae6577e4ac4e3c2478e3fd8df0164600b4816b2167c2bf5b9fd7dd29cc1041fccbf1392240fd7c1dc39dd1ebc86b882a383dfe683e9f029d40b2829e3bf56b9760e1d81b7ad4a9066b1c01ccbea6b196154443cacedaccd5ff4fd25cbd9a8f0d271d5688bbe4b956fd34d3413d0478ac9400f6f1ff3890dea10be072d2d48bfa69a6e1e1b6fffaa9db4663eb1ecc26da331072877eb6d4a05a41584d44ed5d2a96a98727563bf180768940c99a15e9183ae927f47f2c0e13d9c00d7ebf0dacb1b6c139d3e18701d10c9d1ef300eeeab756eaa4584c3f5fb42793f7c2517601ae31d887c177eec8bce35c0aa16ba6991fd885deb9ff7b44ffd489f8e9e9d0717141501143c027d33e8a4baf6d85c859ff8a04d1aafbb3d1a97dc6c8ee3642ec41b8e43a137b43c8e60d69a6f19eb9749e"
				}
			}
		}
	}
	# "#
	# , 0, false, false, false, false);
	```
	*/
	fn build_output(
		&self,
		token: Token,
		features: OutputFeatures,
		amount: Amount,
	) -> Result<BuiltOutput, Error>;

	/**
	Networked version of [Owner::build_output](struct.Owner.html#method.create_mwixnet_req).
	```
	# grin_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_mwixnet_req",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"commitment": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
			"fee_per_hop": "5000000",
			"lock_output": true,
			"server_keys": [
				"97444ae673bb92c713c1a2f7b8882ffbfc1c67401a280a775dce1a8651584332",
				"0c9414341f2140ed34a5a12a6479bf5a6404820d001ab81d9d3e8cc38f049b4e",
				"b58ece97d60e71bb7e53218400b0d67bfe6a3cb7d3b4a67a44f8fb7c525cbca5"
			]
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"comsig": "099561ed0be59f6502ee358ee4f6760cd16d6be04d58d7a2c1bf2fd09dd7fd2d291beaae5483c6f18d1ceaae6321f06f9ba129a1ee9e7d15f152c67397a621538b5c10bbeb95140dee815c02657c91152939afe389458dc59af095e8e8e5c81a08",
				"onion": {
					"commit": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
					"data": [
						"37f68116475e1aa6b58fc911addbd0e04e7aa19ab3e82e7b5cfcaf57d82cf35e7388ce51711cc5ef8cf7630f7dc7229878f91c7ec85991a7fc0051a7bbc66569db3a3aa89ef490055f3c",
						"b9ff8c0c1699808efce46d581647c65764a28e813023ae677d688282422a07505ae1a051037d7ba58f3279846d0300800fc1c5bfcc548dab815e9fd2f29df9515170c41fa6e4e44b8bcb",
						"62ea6b8369686a0415e1e752b9b4d6e66cf5b6066a2d3c60d8818890a55f3adff4601466f4c6e6b646568b99ae93549a3595b7a7b4be815ced87d9297cabbd69518d7b2ed6edd14007528fd346aaea765a1165fe886666627ebcab9588b8ee1c9e98395ae67913c48eb6e924581b40182fce807f97312fb07fd5e216d99941f2b488babce4078a50cd66b28b30a66c4f54fcc127437408a99b30ffd6c3d0d8c7d39e864fc04e321b8c10138c8852d4cad0a4f2780412b9dadcc6e0f2657b7803a81bccb809ca392464be2e01755be7377d0e815698ad6ea51d4617cc92c3ccf852f038e33cc9c90992438ba5c49cca7cc188b682da684e2f4c9733a84a7b64ac5c2216ebf5926f0ee67b664fb5bab799109cbee755ce1aebc8cd352fea51cd84c333cb958093c53544c3f3ab05dba64d8f041c3b179796b476ec04b11044e39db6994ab767315e52cc0ef023432ec88ade2911612db7e74e0923889f765b58b00e3869c5072a4e882c1b721913f63bda986b8c97b7ae575f0d4be596a1ac3cd0db96ce6074ee000b32018b3bda16d7dba34a13ba9c3ce983946414c16e278351a3411cb8ef2cb8ef5b6e1667c4c58bc797c0324ae4fec8960d684e561c0e833ee4c3331c6c439b59042a62993535e23cc8a8a4cf705c0f9b1d62db4e3d76c22c01138800414b143ddff471e4df4413e842a1b41f43cc9647e47145fd6c86d4d1a34fb2f62f5a55b31c9353ee34743c548eff955f2d2143c1a86cbcb452104f96d0142db31153021bbeed995c71a92de8fb1f97269533a508085c543fcb3ee57000bb265e74187b858403aa97b6c7b085e5d5b6025cbfe5f6926d33c835f90e60fc62013e80bbe0a855da5938b4b8f83ac29c5e8251827795356222079a6d1612e2fdf93bd7836d1613c7a353ada48ce256f880bbbb3108e037e3b5647101bd4d549101b0ee73d2248a932a802a3b1beb0b69d777c4285d57e91d83e96fe2f8a1a2f182fe2c6ca37b18460cf8d7f56c201147b9be19f1d01f8ad305c1e9c4dd79b5d8719d6550432352cf737082b1e9de7a083ffbe1"
					],
					"pubkey": "e7ee7d51b11d09f268ade98bc9d7ae9be3c4ac124ce1c3a40e50d34460fa5f08"
				}
			}
		}
	}
	# "#
	# , 5, true, true, false, false);
	```
	 *
	 */

	fn create_mwixnet_req(
		&self,
		token: Token,
		commitment: String,
		fee_per_hop: String,
		lock_output: bool,
		server_keys: Vec<String>,
	) -> Result<SwapReq, Error>;
}

impl<L, C, K> OwnerRpc for Owner<L, C, K>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn accounts(&self, token: Token) -> Result<Vec<AcctPathMapping>, Error> {
		Owner::accounts(self, (&token.keychain_mask).as_ref())
	}

	fn create_account_path(&self, token: Token, label: &String) -> Result<Identifier, Error> {
		Owner::create_account_path(self, (&token.keychain_mask).as_ref(), label)
	}

	fn set_active_account(&self, token: Token, label: &String) -> Result<(), Error> {
		Owner::set_active_account(self, (&token.keychain_mask).as_ref(), label)
	}

	fn retrieve_outputs(
		&self,
		token: Token,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), Error> {
		Owner::retrieve_outputs(
			self,
			(&token.keychain_mask).as_ref(),
			include_spent,
			refresh_from_node,
			tx_id,
		)
	}

	fn retrieve_txs(
		&self,
		token: Token,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), Error> {
		Owner::retrieve_txs(
			self,
			(&token.keychain_mask).as_ref(),
			refresh_from_node,
			tx_id,
			tx_slate_id,
			None,
		)
	}

	fn query_txs(
		&self,
		token: Token,
		refresh_from_node: bool,
		query: RetrieveTxQueryArgs,
	) -> Result<(bool, Vec<TxLogEntry>), Error> {
		Owner::retrieve_txs(
			self,
			(&token.keychain_mask).as_ref(),
			refresh_from_node,
			None,
			None,
			Some(query),
		)
	}

	fn retrieve_summary_info(
		&self,
		token: Token,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), Error> {
		Owner::retrieve_summary_info(
			self,
			(&token.keychain_mask).as_ref(),
			refresh_from_node,
			minimum_confirmations,
		)
	}

	fn init_send_tx(&self, token: Token, args: InitTxArgs) -> Result<VersionedSlate, Error> {
		let slate = Owner::init_send_tx(self, (&token.keychain_mask).as_ref(), args)?;
		let version = SlateVersion::V4;
		VersionedSlate::into_version(slate, version)
	}

	fn issue_invoice_tx(
		&self,
		token: Token,
		args: IssueInvoiceTxArgs,
	) -> Result<VersionedSlate, Error> {
		let slate = Owner::issue_invoice_tx(self, (&token.keychain_mask).as_ref(), args)?;
		let version = SlateVersion::V4;
		VersionedSlate::into_version(slate, version)
	}

	fn process_invoice_tx(
		&self,
		token: Token,
		in_slate: VersionedSlate,
		args: InitTxArgs,
	) -> Result<VersionedSlate, Error> {
		let out_slate = Owner::process_invoice_tx(
			self,
			(&token.keychain_mask).as_ref(),
			&Slate::from(in_slate),
			args,
		)?;
		let version = SlateVersion::V4;
		VersionedSlate::into_version(out_slate, version)
	}

	fn finalize_tx(&self, token: Token, in_slate: VersionedSlate) -> Result<VersionedSlate, Error> {
		let out_slate = Owner::finalize_tx(
			self,
			(&token.keychain_mask).as_ref(),
			&Slate::from(in_slate),
		)?;
		let version = SlateVersion::V4;
		VersionedSlate::into_version(out_slate, version)
	}

	fn tx_lock_outputs(&self, token: Token, in_slate: VersionedSlate) -> Result<(), Error> {
		Owner::tx_lock_outputs(
			self,
			(&token.keychain_mask).as_ref(),
			&Slate::from(in_slate),
		)
	}

	fn cancel_tx(
		&self,
		token: Token,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(), Error> {
		Owner::cancel_tx(self, (&token.keychain_mask).as_ref(), tx_id, tx_slate_id)
	}

	fn get_stored_tx(
		&self,
		token: Token,
		id: Option<u32>,
		slate_id: Option<Uuid>,
	) -> Result<Option<VersionedSlate>, Error> {
		let out_slate = Owner::get_stored_tx(
			self,
			(&token.keychain_mask).as_ref(),
			id,
			(&slate_id).as_ref(),
		)?;
		match out_slate {
			Some(s) => {
				let version = SlateVersion::V4;
				Ok(Some(VersionedSlate::into_version(s, version)?))
			}
			None => Ok(None),
		}
	}

	fn post_tx(&self, token: Token, slate: VersionedSlate, fluff: bool) -> Result<(), Error> {
		Owner::post_tx(
			self,
			(&token.keychain_mask).as_ref(),
			&Slate::from(slate),
			fluff,
		)
	}

	fn get_rewind_hash(&self, token: Token) -> Result<String, Error> {
		Owner::get_rewind_hash(self, (&token.keychain_mask).as_ref())
	}

	fn scan_rewind_hash(
		&self,
		rewind_hash: String,
		start_height: Option<u64>,
	) -> Result<ViewWallet, Error> {
		Owner::scan_rewind_hash(self, rewind_hash, start_height)
	}

	fn scan(
		&self,
		token: Token,
		start_height: Option<u64>,
		delete_unconfirmed: bool,
	) -> Result<(), Error> {
		Owner::scan(
			self,
			(&token.keychain_mask).as_ref(),
			start_height,
			delete_unconfirmed,
		)
	}

	fn node_height(&self, token: Token) -> Result<NodeHeightResult, Error> {
		Owner::node_height(self, (&token.keychain_mask).as_ref())
	}

	fn init_secure_api(&self, ecdh_pubkey: ECDHPubkey) -> Result<ECDHPubkey, Error> {
		let secp_inst = static_secp_instance();
		let secp = secp_inst.lock();
		let sec_key = SecretKey::new(&secp, &mut thread_rng());

		let mut shared_pubkey = ecdh_pubkey.ecdh_pubkey;
		shared_pubkey
			.mul_assign(&secp, &sec_key)
			.map_err(Error::Secp)?;

		let x_coord = shared_pubkey.serialize_vec(&secp, true);
		let shared_key = SecretKey::from_slice(&secp, &x_coord[1..]).map_err(Error::Secp)?;
		{
			let mut s = self.shared_key.lock();
			*s = Some(shared_key);
		}

		let pub_key = PublicKey::from_secret_key(&secp, &sec_key).map_err(Error::Secp)?;

		Ok(ECDHPubkey {
			ecdh_pubkey: pub_key,
		})
	}

	fn get_top_level_directory(&self) -> Result<String, Error> {
		Owner::get_top_level_directory(self)
	}

	fn set_top_level_directory(&self, dir: String) -> Result<(), Error> {
		Owner::set_top_level_directory(self, &dir)
	}

	fn create_config(
		&self,
		chain_type: global::ChainTypes,
		wallet_config: Option<WalletConfig>,
		logging_config: Option<LoggingConfig>,
		tor_config: Option<TorConfig>,
	) -> Result<(), Error> {
		Owner::create_config(self, &chain_type, wallet_config, logging_config, tor_config)
	}

	fn create_wallet(
		&self,
		name: Option<String>,
		mnemonic: Option<String>,
		mnemonic_length: u32,
		password: String,
	) -> Result<(), Error> {
		let n = name.as_ref().map(|s| s.as_str());
		let m = match mnemonic {
			Some(s) => Some(ZeroingString::from(s)),
			None => None,
		};
		Owner::create_wallet(self, n, m, mnemonic_length, ZeroingString::from(password))
	}

	fn open_wallet(&self, name: Option<String>, password: String) -> Result<Token, Error> {
		let n = name.as_ref().map(|s| s.as_str());
		let sec_key = Owner::open_wallet(self, n, ZeroingString::from(password), true)?;
		Ok(Token {
			keychain_mask: sec_key,
		})
	}

	fn close_wallet(&self, name: Option<String>) -> Result<(), Error> {
		let n = name.as_ref().map(|s| s.as_str());
		Owner::close_wallet(self, n)
	}

	fn get_mnemonic(&self, name: Option<String>, password: String) -> Result<String, Error> {
		let n = name.as_ref().map(|s| s.as_str());
		let res = Owner::get_mnemonic(self, n, ZeroingString::from(password))?;
		Ok((&*res).to_string())
	}

	fn change_password(&self, name: Option<String>, old: String, new: String) -> Result<(), Error> {
		let n = name.as_ref().map(|s| s.as_str());
		Owner::change_password(self, n, ZeroingString::from(old), ZeroingString::from(new))
	}

	fn delete_wallet(&self, name: Option<String>) -> Result<(), Error> {
		let n = name.as_ref().map(|s| s.as_str());
		Owner::delete_wallet(self, n)
	}

	fn start_updater(&self, token: Token, frequency: u32) -> Result<(), Error> {
		Owner::start_updater(
			self,
			(&token.keychain_mask).as_ref(),
			Duration::from_millis(frequency as u64),
		)
	}

	fn stop_updater(&self) -> Result<(), Error> {
		Owner::stop_updater(self)
	}

	fn get_updater_messages(&self, count: u32) -> Result<Vec<StatusMessage>, Error> {
		Owner::get_updater_messages(self, count as usize)
	}

	fn get_slatepack_address(
		&self,
		token: Token,
		derivation_index: u32,
	) -> Result<SlatepackAddress, Error> {
		Owner::get_slatepack_address(self, (&token.keychain_mask).as_ref(), derivation_index)
	}

	fn get_slatepack_secret_key(
		&self,
		token: Token,
		derivation_index: u32,
	) -> Result<Ed25519SecretKey, Error> {
		let key = Owner::get_slatepack_secret_key(
			self,
			(&token.keychain_mask).as_ref(),
			derivation_index,
		)?;
		Ok(Ed25519SecretKey { key })
	}

	fn create_slatepack_message(
		&self,
		token: Token,
		slate: VersionedSlate,
		sender_index: Option<u32>,
		recipients: Vec<SlatepackAddress>,
	) -> Result<String, Error> {
		let res = Owner::create_slatepack_message(
			self,
			(&token.keychain_mask).as_ref(),
			&Slate::from(slate),
			sender_index,
			recipients,
		)?;
		Ok(res.trim().into())
	}

	fn slate_from_slatepack_message(
		&self,
		token: Token,
		message: String,
		secret_indices: Vec<u32>,
	) -> Result<VersionedSlate, Error> {
		let slate = Owner::slate_from_slatepack_message(
			self,
			(&token.keychain_mask).as_ref(),
			message,
			secret_indices,
		)?;
		let version = SlateVersion::V4;
		VersionedSlate::into_version(slate, version)
	}

	fn decode_slatepack_message(
		&self,
		token: Token,
		message: String,
		secret_indices: Vec<u32>,
	) -> Result<Slatepack, Error> {
		Owner::decode_slatepack_message(
			self,
			(&token.keychain_mask).as_ref(),
			message,
			secret_indices,
		)
	}

	fn retrieve_payment_proof(
		&self,
		token: Token,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<PaymentProof, Error> {
		Owner::retrieve_payment_proof(
			self,
			(&token.keychain_mask).as_ref(),
			refresh_from_node,
			tx_id,
			tx_slate_id,
		)
	}

	fn verify_payment_proof(
		&self,
		token: Token,
		proof: PaymentProof,
	) -> Result<(bool, bool), Error> {
		Owner::verify_payment_proof(self, (&token.keychain_mask).as_ref(), &proof)
	}

	fn set_tor_config(&self, tor_config: Option<TorConfig>) -> Result<(), Error> {
		Owner::set_tor_config(self, tor_config);
		Ok(())
	}

	fn build_output(
		&self,
		token: Token,
		features: OutputFeatures,
		amount: Amount,
	) -> Result<BuiltOutput, Error> {
		Owner::build_output(self, (&token.keychain_mask).as_ref(), features, amount.0)
	}

	fn create_mwixnet_req(
		&self,
		token: Token,
		commitment: String,
		fee_per_hop: String,
		lock_output: bool,
		server_keys: Vec<String>,
	) -> Result<SwapReq, Error> {
		let commit =
			Commitment::from_vec(from_hex(&commitment).map_err(|e| Error::CommitDeser(e))?);

		let secp_inst = static_secp_instance();
		let secp = secp_inst.lock();

		let mut keys = vec![];
		for key in server_keys {
			keys.push(SecretKey::from_slice(
				&secp,
				&grin_util::from_hex(&key).map_err(|e| Error::ServerKeyDeser(e))?,
			)?)
		}

		let req_params = MixnetReqCreationParams {
			server_keys: keys,
			fee_per_hop: fee_per_hop
				.parse::<u64>()
				.map_err(|_| Error::U64Deser(fee_per_hop))?,
		};

		Owner::create_mwixnet_req(
			self,
			(&token.keychain_mask).as_ref(),
			&req_params,
			&commit,
			lock_output,
		)
	}
}

/// helper to set up a real environment to run integrated doctests
pub fn run_doctest_owner(
	request: serde_json::Value,
	test_dir: &str,
	blocks_to_mine: u64,
	perform_tx: bool,
	lock_tx: bool,
	finalize_tx: bool,
	payment_proof: bool,
) -> Result<Option<serde_json::Value>, String> {
	use easy_jsonrpc_mw::Handler;
	use grin_keychain::ExtKeychain;
	use grin_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};
	use grin_wallet_impls::{DefaultLCProvider, DefaultWalletImpl};
	use grin_wallet_libwallet::{api_impl, WalletInst};

	use crate::core::global::ChainTypes;
	use grin_util as util;

	use std::{fs, thread};

	util::init_test_logger();
	let _ = fs::remove_dir_all(test_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);

	let mut wallet_proxy: WalletProxy<
		DefaultLCProvider<LocalWalletClient, ExtKeychain>,
		LocalWalletClient,
		ExtKeychain,
	> = WalletProxy::new(test_dir);
	let chain = wallet_proxy.chain.clone();

	let rec_phrase_1 = util::ZeroingString::from(
		"fat twenty mean degree forget shell check candy immense awful \
		 flame next during february bulb bike sun wink theory day kiwi embrace peace lunch",
	);
	let empty_string = util::ZeroingString::from("");

	let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());
	let mut wallet1 =
		Box::new(DefaultWalletImpl::<LocalWalletClient>::new(client1.clone()).unwrap())
			as Box<
				dyn WalletInst<
					'static,
					DefaultLCProvider<LocalWalletClient, ExtKeychain>,
					LocalWalletClient,
					ExtKeychain,
				>,
			>;
	let lc = wallet1.lc_provider().unwrap();
	let _ = lc.set_top_level_directory(&format!("{}/wallet1", test_dir));
	lc.create_wallet(None, Some(rec_phrase_1), 32, empty_string.clone(), false)
		.unwrap();
	let mask1 = lc
		.open_wallet(None, empty_string.clone(), true, true)
		.unwrap();
	let wallet1 = Arc::new(Mutex::new(wallet1));

	if mask1.is_some() {
		println!("WALLET 1 MASK: {:?}", mask1.clone().unwrap());
	}

	wallet_proxy.add_wallet(
		"wallet1",
		client1.get_send_instance(),
		wallet1.clone(),
		mask1.clone(),
	);

	let mut slate_outer = Slate::blank(2, false);

	let rec_phrase_2 = util::ZeroingString::from(
		"hour kingdom ripple lunch razor inquiry coyote clay stamp mean \
		 sell finish magic kid tiny wage stand panther inside settle feed song hole exile",
	);
	let client2 = LocalWalletClient::new("wallet2", wallet_proxy.tx.clone());
	let mut wallet2 =
		Box::new(DefaultWalletImpl::<LocalWalletClient>::new(client2.clone()).unwrap())
			as Box<
				dyn WalletInst<
					'static,
					DefaultLCProvider<LocalWalletClient, ExtKeychain>,
					LocalWalletClient,
					ExtKeychain,
				>,
			>;
	let lc = wallet2.lc_provider().unwrap();
	let _ = lc.set_top_level_directory(&format!("{}/wallet2", test_dir));
	lc.create_wallet(None, Some(rec_phrase_2), 32, empty_string.clone(), false)
		.unwrap();
	let mask2 = lc.open_wallet(None, empty_string, true, true).unwrap();
	let wallet2 = Arc::new(Mutex::new(wallet2));

	if mask2.is_some() {
		println!("WALLET 2 MASK: {:?}", mask2.clone().unwrap());
	}

	wallet_proxy.add_wallet(
		"wallet2",
		client2.get_send_instance(),
		wallet2.clone(),
		mask2.clone(),
	);

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// Mine a few blocks to wallet 1 so there's something to send
	for _ in 0..blocks_to_mine {
		let _ = test_framework::award_blocks_to_wallet(
			&chain,
			wallet1.clone(),
			(&mask1).as_ref(),
			1 as usize,
			false,
		);
		//update local outputs after each block, so transaction IDs stay consistent
		let (wallet_refreshed, _) = api_impl::owner::retrieve_summary_info(
			wallet1.clone(),
			(&mask1).as_ref(),
			&None,
			true,
			1,
		)
		.unwrap();
		assert!(wallet_refreshed);
	}

	if perform_tx {
		let amount = 60_000_000_000;
		let mut w_lock = wallet1.lock();
		let w = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
		let proof_address = match payment_proof {
			true => {
				let address = "783f6528669742a990e0faf0a5fca5d5b3330e37bbb9cd5c628696d03ce4e810";
				let address = OnionV3Address::try_from(address).unwrap();
				Some(SlatepackAddress::try_from(address).unwrap())
			}
			false => None,
		};
		let args = InitTxArgs {
			src_acct_name: None,
			amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			payment_proof_recipient_address: proof_address,
			..Default::default()
		};
		let mut slate =
			api_impl::owner::init_send_tx(&mut **w, (&mask1).as_ref(), args, true).unwrap();
		println!("INITIAL SLATE");
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
		{
			let mut w_lock = wallet2.lock();
			let w2 = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
			slate = api_impl::foreign::receive_tx(&mut **w2, (&mask2).as_ref(), &slate, None, true)
				.unwrap();
			w2.close().unwrap();
		}
		// Spit out slate for input to finalize_tx
		if lock_tx {
			println!("LOCKING TX");
			api_impl::owner::tx_lock_outputs(&mut **w, (&mask1).as_ref(), &slate).unwrap();
		}
		println!("RECEIPIENT SLATE");
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
		if finalize_tx {
			slate = api_impl::owner::finalize_tx(&mut **w, (&mask1).as_ref(), &slate).unwrap();
			error!("FINALIZED TX SLATE");
			println!("{}", serde_json::to_string_pretty(&slate).unwrap());
		}
		slate_outer = slate;
	}

	if payment_proof {
		api_impl::owner::post_tx(&client1, slate_outer.tx_or_err().unwrap(), true).unwrap();
	}

	if perform_tx && lock_tx && finalize_tx {
		// mine to move the chain on
		let _ = test_framework::award_blocks_to_wallet(
			&chain,
			wallet1.clone(),
			(&mask1).as_ref(),
			3 as usize,
			false,
		);
	}

	let mut api_owner = Owner::new(wallet1, None);
	api_owner.doctest_mode = true;
	let owner_api = &api_owner as &dyn OwnerRpc;
	let res = owner_api.handle_request(request).as_option();
	let _ = fs::remove_dir_all(test_dir);
	Ok(res)
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_owner_assert_response {
	($request:expr, $expected_response:expr, $blocks_to_mine:expr, $perform_tx:expr, $lock_tx:expr, $finalize_tx:expr, $payment_proof:expr) => {
		// create temporary wallet, run jsonrpc request on owner api of wallet, delete wallet, return
		// json response.
		// In order to prevent leaking tempdirs, This function should not panic.

		// These cause LMDB to run out of disk space on CircleCI
		// disable for now on windows
		// TODO: Fix properly
		#[cfg(not(target_os = "windows"))]
		{
			use grin_wallet_api::run_doctest_owner;
			use serde_json;
			use serde_json::Value;
			use tempfile::tempdir;

			let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
			let dir = dir
				.path()
				.to_str()
				.ok_or("Failed to convert tmpdir path to string.".to_owned())
				.unwrap();

			let request_val: Value = serde_json::from_str($request).unwrap();
			let expected_response: Value = serde_json::from_str($expected_response).unwrap();

			let response = run_doctest_owner(
				request_val,
				dir,
				$blocks_to_mine,
				$perform_tx,
				$lock_tx,
				$finalize_tx,
				$payment_proof,
			)
			.unwrap()
			.unwrap();

			if response != expected_response {
				panic!(
					"(left != right) \nleft: {}\nright: {}",
					serde_json::to_string_pretty(&response).unwrap(),
					serde_json::to_string_pretty(&expected_response).unwrap()
				);
			}
		}
	};
}
