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

//! JSON-RPC Stub generation for the Foreign API

use crate::keychain::Keychain;
use crate::libwallet::{
	self, BlockFees, CbData, Error, InitTxArgs, IssueInvoiceTxArgs, NodeClient, NodeVersionInfo,
	Slate, SlateVersion, VersionInfo, VersionedCoinbase, VersionedSlate, WalletLCProvider,
};
use crate::{Foreign, ForeignCheckMiddlewareFn};
use easy_jsonrpc_mw;

/// Public definition used to generate Foreign jsonrpc api.
/// * When running `grin-wallet listen` with defaults, the V2 api is available at
/// `localhost:3415/v2/foreign`
/// * The endpoint only supports POST operations, with the json-rpc request as the body
#[easy_jsonrpc_mw::rpc]
pub trait ForeignRpc {
	/**
	Networked version of [Foreign::check_version](struct.Foreign.html#method.check_version).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "check_version",
		"id": 1,
		"params": []
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"foreign_api_version": 2,
				"supported_slate_versions": [
					"V4"
				]
			}
		}
	}
	# "#
	# ,false, 0, false, false);
	```
	*/
	fn check_version(&self) -> Result<VersionInfo, Error>;

	/**
	Networked Legacy (non-secure token) version of [Foreign::build_coinbase](struct.Foreign.html#method.build_coinbase).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "build_coinbase",
		"id": 1,
		"params": [
			{
				"fees": 0,
				"height": 0,
				"key_id": null
			}
		]
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"kernel": {
					"excess": "08dfe86d732f2dd24bac36aa7502685221369514197c26d33fac03041d47e4b490",
					"excess_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841be02fa098c54c9bf638e0ee1ad5eb896caa11565f632be7b9cd65643ba371044f",
					"features": "Coinbase"
				},
				"key_id": "0300000000000000000000000400000000",
				"output": {
					"commit": "08fe198e525a5937d0c5d01fa354394d2679be6df5d42064a0f7550c332fce3d9d",
					"features": "Coinbase",
					"proof": "9d8488fcb43c9c0f683b9ce62f3c8e047b71f2b4cd94b99a3c9a36aef3bb8361ee17b4489eb5f6d6507250532911acb76f18664604c2ca4215347a5d5d8e417d00ca2d59ec29371286986428b0ec1177fc2e416339ea8542eff8186550ad0d65ffac35d761c38819601d331fd427576e2fff823bbc3faa04f49f5332bd4de46cd4f83d0fd46cdb1dfb87069e95974e4a45e0235db71f5efe5cec83bbb30e152ac50a010ef4e57e33aabbeb894b9114f90bb5c3bb03b009014e358aa3914b1a208eb9d8806fbb679c256d4c1a47b0fce3f1235d58192cb7f615bd7c5dab48486db8962c2a594e69ff70029784a810b4eb76b0516805f3417308cda8acb38b9a3ea061568f0c97f5b46a3beff556dc7ebb58c774f08be472b4b6f603e5f8309c2d1f8d6f52667cb86816b330eca5374148aa898f5bbaf3f23a3ebcdc359ee1e14d73a65596c0ddf51f123234969ac8b557ba9dc53255dd6f5c0d3dd2c035a6d1a1185102612fdca474d018b9f9e81acfa3965d42769f5a303bbaabb78d17e0c026b8be0039c55ad1378c8316101b5206359f89fd1ee239115dde458749a040997be43c039055594cab76f602a0a1ee4f5322f3ab1157342404239adbf8b6786544cd67d9891c2689530e65f2a4b8e52d8551b92ffefb812ffa4a472a10701884151d1fb77d8cdc0b1868cb31b564e98e4c035e0eaa26203b882552c7b69deb0d8ec67cf28d5ec044554f8a91a6cae87eb377d6d906bba6ec94dda24ebfd372727f68334af798b11256d88e17cef7c4fed092128215f992e712ed128db2a9da2f5e8fadea9395bddd294a524dce47f818794c56b03e1253bf0fb9cb8beebc5742e4acf19c24824aa1d41996e839906e24be120a0bdf6800da599ec9ec3d1c4c11571c9f143eadbb554fa3c8c9777994a3f3421d454e4ec54c11b97eea3e4e6ede2d97a2bc"
				}
			}
		}
	}
	# "#
	# ,false, 4, false, false);
	```
	*/

	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<VersionedCoinbase, Error>;

	/**
	;Networked version of [Foreign::receive_tx](struct.Foreign.html#method.receive_tx).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "receive_tx",
		"id": 1,
		"params": [
			{
				"amt": "6000000000",
				"fee": "23500000",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"off": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"proof": {
					"raddr": "32cdd63928854f8b2628b1dce4626ddcdf35d56cb7cfdf7d64cca5822b78d4d3",
					"saddr": "32cdd63928854f8b2628b1dce4626ddcdf35d56cb7cfdf7d64cca5822b78d4d3"
				},
				"sigs": [
					{
						"nonce": "02b57c1f4fea69a3ee070309cf8f06082022fe06f25a9be1851b56ef0fa18f25d6",
						"xs": "023878ce845727f3a4ec76ca3f3db4b38a2d05d636b8c3632108b857fed63c96de"
					}
				],
				"sta": "S1",
				"ver": "4:2"
			},
			null,
			null
		]
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
						"c": "091582c92b99943b57955e52b5ccf1223780c2a2e55995c00c86fca2bcb46b6b9f",
						"p": "49972a8d5b7c088e7813c3988ebe0982f8f0b12b849b1788df7da07b549408b0d6c99f80c0e2335370c104225ef5d282d79966e9044c959bedc3be03af6246fa07fc13eb3c60c90213c9f3a7a5ecf9a34c8fbaddc1a72e49e12dba9495e5aaa53bb6ac6ed63d8774707c57ab604d6bdc46de18da57a731fe336c3ccef92b4dae967417ffdae2c7d75864d46d30e287dd9cc15882e15f296b9bab0040e4432f4024be33924f112dd26c90cc800ac09a327b0ac3a661f63da9945fb1bcc82a7777d61d97cbe657675e22d035d2cf9ea03a89cfa410960ebc18a0a18b1909f4c5bef20b0fd13ffcf5a818ad8768d354b1c0f2e9b16dd7a9cf0641546f57d1945a98b8684d067dd085b90b40457e4c14665fb1b94feecf30a90f508ded16ba1bba8080a6866dffd0b1f01738fff8c62ce5e38e677835752a1b4072124dd9ff14ba8ff92126baebbb5f6e14fbb052f5d5b09aec11bfd880d7d4640a295aa83f184034d26f00cbdbabf9b89fddd7a7c9cc8c5d4b53fc39971e4495a8d984ac9607be89780fde528ee3f2d6b912908b4caf04f5c93f64431517af6b32d0b9c18255959f6903c6696ec71f615a0c877630a2d871f3f8a107fc80f306a94b6ad5790070f7d2535163bad7feae9263a9d3558ea1acecc4e61ff4e05b0162f6aba1a3b299ff1c3bb85e4109e550ad870c328bedc45fed8b504f679bc3c1a25b2b65ede44602f21fac123ba7c5f132e7c786bf9420a27bae4d2559cf7779e77f96b747b6d3ad5c13b5e8c9b49a7083001b2f98bcf242d4644537bb5a3b5b41764812a93395b7ab372c18be575e02c3763b4170234e5fddeb43420aadb71cb80f75cc681c1e7ffee3e6a8868c6076fd1da539ab9a12fef1c8cbe271b6de60100c9f82d826dc97b47b57ee9804e60112f556c1dce4f12ecc91ef34d69090b8c9d2ae9cbae38994a955cb"
					}
				],
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"off": "a4f88ac429dee1d453ae33ed9f944417a52c7310477936e484fd83f0f22db483",
				"proof": {
					"raddr": "32cdd63928854f8b2628b1dce4626ddcdf35d56cb7cfdf7d64cca5822b78d4d3",
					"rsig": "02357a13b304ba8e22f4896d5664b72ad6d1b824e88782e2b716686ea14ec47281ef5ee14c03ead84c3260f5b0c1529ad3ddae57f28f6b8b1b66532bfcb2ee0f",
					"saddr": "32cdd63928854f8b2628b1dce4626ddcdf35d56cb7cfdf7d64cca5822b78d4d3"
				},
				"sigs": [
					{
						"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841be4f81215c8e678c7bd5f04f3562388948864d7a5a0374e220ab6dc5e02bae66f",
						"xs": "02e3c128e436510500616fef3f9a22b15ca015f407c8c5cf96c9059163c873828f"
					}
				],
				"sta": "S2",
				"ver": "4:2"
			}
		}
	}
	# "#
	# ,false, 5, true, false);
	```
	*/
	fn receive_tx(
		&self,
		slate: VersionedSlate,
		dest_acct_name: Option<String>,
		dest: Option<String>,
	) -> Result<VersionedSlate, Error>;

	/**

	Networked version of [Foreign::finalize_tx](struct.Foreign.html#method.finalize_tx).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "finalize_tx",
		"id": 1,
		"params": [{
			"ver": "4:2",
			"id": "0436430c-2b02-624c-2032-570501212b00",
			"sta": "I2",
			"off": "383bc9df0dd332629520a0a72f8dd7f0e97d579dccb4dbdc8592aa3d424c846c",
			"fee": "23500000",
			"sigs": [
				{
					"xs": "02e3c128e436510500616fef3f9a22b15ca015f407c8c5cf96c9059163c873828f",
					"nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
					"part": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841be7bf31d80494f5e4a3d656649b1610c61a268f9cafcfc604b5d9f25efb2aa3c5"
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
					"c": "09ede20409d5ae0d1c0d3f3d2c68038a384cdd6b7cc5ca2aab670f570adc2dffc3",
					"p": "6d86fe00220f8c6ac2ad4e338d80063dba5423af525bd273ecfac8ef6b509192732a8cd0c53d3313e663ac5ccece3d589fd2634e29f96e82b99ca6f8b953645a005d1bc73493f8c41f84fb8e327d4cbe6711dba194a60db30700df94a41e1fda7afe0619169389f8d8ee12bddf736c4bc86cd5b1809a5a27f195209147dc38d0de6f6710ce9350f3b8e7e6820bfe5182e6e58f0b41b82b6ec6bb01ffe1d8b3c2368ebf1e31dfdb9e00f0bc68d9119a38d19c038c29c7b37e31246e7bba56019bc88881d7d695d32557fc0e93635b5f24deffefc787787144e5de7e86281e79934e7e20d9408c34317c778e6b218ee26d0a5e56b8b84a883e3ddf8603826010234531281486454f8c2cf3fee074f242f9fc1da3c6636b86fb6f941eb8b633d6e3b3f87dfe5ae261a40190bd4636f433bcdd5e3400255594e282c5396db8999d95be08a35be9a8f70fdb7cf5353b90584523daee6e27e208b2ca0e5758b8a24b974dca00bab162505a2aa4bcefd8320f111240b62f861261f0ce9b35979f9f92da7dd6989fe1f41ec46049fd514d9142ce23755f52ec7e64df2af33579e9b8356171b91bc96b875511bef6062dd59ef3fe2ddcc152147554405b12c7c5231513405eb062aa8fa093e3414a144c544d551c4f1f9bf5d5d2ff5b50a3f296c800907704bed8d8ee948c0855eff65ad44413af641cdc68a06a7c855be7ed7dd64d5f623bbc9645763d48774ba2258240a83f8f89ef84d21c65bcb75895ebca08b0090b40aafb7ddef039fcaf4bad2dbbac72336c4412c600e854d368ed775597c15d2e66775ab47024ce7e62fd31bf90b183149990c10b5b678501dbac1af8b2897b67d085d87cab7af4036cba3bdcfdcc7548d7710511045813c6818d859e192e03adc0d6a6b30c4cbac20a0d6f8719c7a9c3ad46d62eec464c4c44b58fca463fea3ce1fc51"
				}
			]
		}]
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
				"sta": "I3",
				"ver": "4:2"
			}
		}
	}
	# "#
	# ,false, 5, false, true);
	```
	*/
	fn finalize_tx(&self, slate: VersionedSlate) -> Result<VersionedSlate, Error>;
}

impl<'a, L, C, K> ForeignRpc for Foreign<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	fn check_version(&self) -> Result<VersionInfo, Error> {
		Foreign::check_version(self)
	}

	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<VersionedCoinbase, Error> {
		let cb: CbData = Foreign::build_coinbase(self, block_fees)?;
		Ok(VersionedCoinbase::into_version(cb, SlateVersion::V4))
	}

	fn receive_tx(
		&self,
		in_slate: VersionedSlate,
		dest_acct_name: Option<String>,
		dest: Option<String>,
	) -> Result<VersionedSlate, Error> {
		let version = in_slate.version();
		let slate_from = Slate::from(in_slate);
		let out_slate = Foreign::receive_tx(
			self,
			&slate_from,
			dest_acct_name.as_ref().map(String::as_str),
			dest,
		)?;
		Ok(VersionedSlate::into_version(out_slate, version)?)
	}

	fn finalize_tx(&self, in_slate: VersionedSlate) -> Result<VersionedSlate, Error> {
		let version = in_slate.version();
		let out_slate = Foreign::finalize_tx(self, &Slate::from(in_slate), true)?;
		Ok(VersionedSlate::into_version(out_slate, version)?)
	}
}

fn test_check_middleware(
	_name: ForeignCheckMiddlewareFn,
	_node_version_info: Option<NodeVersionInfo>,
	_slate: Option<&Slate>,
) -> Result<(), libwallet::Error> {
	// TODO: Implement checks
	// return Err(Error::GenericError("Test Rejection".into()))?
	Ok(())
}

/// helper to set up a real environment to run integrated doctests
pub fn run_doctest_foreign(
	request: serde_json::Value,
	test_dir: &str,
	use_token: bool,
	blocks_to_mine: u64,
	init_tx: bool,
	init_invoice_tx: bool,
) -> Result<Option<serde_json::Value>, String> {
	use easy_jsonrpc_mw::Handler;
	use grin_keychain::ExtKeychain;
	use grin_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};
	use grin_wallet_impls::{DefaultLCProvider, DefaultWalletImpl};
	use grin_wallet_libwallet::{api_impl, WalletInst};

	use crate::core::global;
	use crate::core::global::ChainTypes;
	use grin_util as util;

	use std::sync::Arc;
	use util::Mutex;

	use std::fs;
	use std::thread;

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
		.open_wallet(None, empty_string.clone(), use_token, true)
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
	let mask2 = lc.open_wallet(None, empty_string, use_token, true).unwrap();
	let wallet2 = Arc::new(Mutex::new(wallet2));

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

	if init_invoice_tx {
		let amount = 60_000_000_000;
		let mut slate = {
			let mut w_lock = wallet2.lock();
			let w = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
			let args = IssueInvoiceTxArgs {
				amount,
				..Default::default()
			};
			api_impl::owner::issue_invoice_tx(&mut **w, (&mask2).as_ref(), args, true).unwrap()
		};
		slate = {
			let mut w_lock = wallet1.lock();
			let w = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
			let args = InitTxArgs {
				src_acct_name: None,
				amount: slate.amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};
			api_impl::owner::process_invoice_tx(&mut **w, (&mask1).as_ref(), &slate, args, true)
				.unwrap()
		};
		println!("INIT INVOICE SLATE");
		// Spit out slate for input to finalize_tx
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
	}

	if init_tx {
		let amount = 60_000_000_000;
		let mut w_lock = wallet1.lock();
		let w = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
		let args = InitTxArgs {
			src_acct_name: None,
			amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let slate = api_impl::owner::init_send_tx(&mut **w, (&mask1).as_ref(), args, true).unwrap();
		println!("INIT SLATE");
		// Spit out slate for input to finalize_tx
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
	}

	let mut api_foreign = match init_invoice_tx {
		false => Foreign::new(wallet1, mask1, Some(test_check_middleware), true),
		true => Foreign::new(wallet2, mask2, Some(test_check_middleware), true),
	};
	api_foreign.doctest_mode = true;
	let foreign_api = &api_foreign as &dyn ForeignRpc;
	let res = foreign_api.handle_request(request).as_option();
	let _ = fs::remove_dir_all(test_dir);
	Ok(res)
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_foreign_assert_response {
	($request:expr, $expected_response:expr, $use_token:expr, $blocks_to_mine:expr, $init_tx:expr, $init_invoice_tx:expr) => {
		// create temporary wallet, run jsonrpc request on owner api of wallet, delete wallet, return
		// json response.
		// In order to prevent leaking tempdirs, This function should not panic.
		use grin_wallet_api::run_doctest_foreign;
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

		let response = run_doctest_foreign(
			request_val,
			dir,
			$use_token,
			$blocks_to_mine,
			$init_tx,
			$init_invoice_tx,
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
	};
}
