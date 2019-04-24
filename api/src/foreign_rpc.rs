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

//! JSON-RPC Stub generation for the Foreign API

use crate::keychain::Keychain;
use crate::libwallet::{
	BlockFees, CbData, ErrorKind, InitTxArgs, NodeClient, Slate, VersionInfo, VersionedSlate,
	WalletBackend,
};
use crate::Foreign;
use easy_jsonrpc;

/// Public definition used to generate Foreign jsonrpc api.
/// * When running `grin-wallet listen` with defaults, the V2 api is available at
/// `localhost:3415/v2/foreign`
/// * The endpoint only supports POST operations, with the json-rpc request as the body
#[easy_jsonrpc::rpc]
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
				"default_slate_version": 2,
				"foreign_api_version": 2
			}
		}
	}
	# "#
	# , 0, false);
	```

	*/
	fn check_version(&self) -> Result<VersionInfo, ErrorKind>;

	/**
	Networked version of [Foreign::build_coinbase](struct.Foreign.html#method.build_coinbase).

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
					"excess_sig": "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f4f0471a33b6465cdb9e72b635f5611aa6c89ebd51aeee038f69b4cc598a02fe0",
					"features": "Coinbase",
					"fee": "0",
					"lock_height": "0"
				},
				"key_id": "0300000000000000000000000400000000",
				"output": {
					"commit": "08fe198e525a5937d0c5d01fa354394d2679be6df5d42064a0f7550c332fce3d9d",
					"features": "Coinbase",
					"proof": "9166dc13a374a50d99f16ddfb228ce6010ea22d1676de755c34123402b5a8e68871b37d716c14e07be14ceb0771cca62a302358aa82922fa87f1387cff3a4507027f04f3fcf54ed16bd97e40a06c6f969139188daca366bb78ccbc7ff0203de62e30077f8b4a8b314901666205d24ca93d54581aa082e37c370e178dea267ff11fa4669756a31c026348255108c4de4b7abe3636ebdd67f25387c9c2868d16fab9209ebee6d19c6395eaf313da67f164d8e997ed97de9478ddb24c34d8a0dcedc24c5d0a9d1c9f15de3264323fc768271d7981b1e2ae1e59675537115fdcd1ea7d60a7bd276865698d1c1598b7c22a1a6e212db4d0a0ba98706a746f63f2d8460a9d28b4e8a7d2ad1f531b32046e2285a034c2d49f7896026fa186f9665766ae158435157f94bd31b8ebf5c0637a9d72036348c1d1fb70659b6ca5e64427a9eb51569074311e970316fd370373149067a0781cd49cc450e80e14a84f9818ae8caf6c02877f15ab11397d60309249658e5a03f49354dce3873118be6f43ca436aa81165ca44d624fd6f504b8d186bca2ef7e3c5ff2b85db86b29ddd0fb58173960caf2b437c8190511685303ab0eb1b5a757e1509529063a145f5242350edb8e1a1807f505866fdb5689fd39d4595cf5084d30a1ba2af882969bf64aecad342926b16930a3d93781dcebc839b7bf5762146e0016c502aad33d24c9e708c810505bd9c6648bd8303ddbbe5c5cf82eb420784223182e1b59286249e38458c885f089e9211b3aafe7c6f85097878679775287423ebca7557cd3be9e44bb454c6b1914b9012e100d601d7a2ecb0c2a07b5e6f0c293b671e45a425d97169eb793834a40a0a64277e68b2809ca4556eed7d130c2ea973021fda08a01c771111b1cc12b647029fe19f1018486a0ef82bbe5ca7ff484c71d52f3238766d771eaf4204793809dc27"
				}
			}
		}
	}
	# "#
	# , 4, false);
	```
	 */
	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<CbData, ErrorKind>;

	/**
	Networked version of [Foreign::verify_slate_messages](struct.Foreign.html#method.verify_slate_messages).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "verify_slate_messages",
		"id": 1,
		"params": [ {
				"amount": "6000000000",
				"fee": "8000000",
				"height": "4",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"lock_height": "4",
				"num_participants": 2,
				"participant_data": [
				{
					"id": "0",
					"message": "my message",
					"message_sig": "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f756f655333250204644c1cb169e7a78f21b57437930db91e808f39be58134c1d",
					"part_sig": null,
					"public_blind_excess": "034b4df2f0558b73ea72a1ca5c4ab20217c66bbe0829056fca7abe76888e9349ee",
					"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				}
				],
				"tx": {
					"body": {
						"inputs": [
						{
							"commit": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
							"features": "Coinbase"
						}
						],
						"kernels": [
						{
							"excess": "000000000000000000000000000000000000000000000000000000000000000000",
							"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							"features": "HeightLocked",
							"fee": "8000000",
							"lock_height": "4"
						}
						],
						"outputs": [
						{
							"commit": "094be57c91787fc2033d5d97fae099f1a6ddb37ea48370f1a138f09524c767fdd3",
							"features": "Plain",
							"proof": "2a42e9e902b70ce44e1fccb14de87ee0a97100bddf12c6bead1b9c5f4eb60300f29c13094fa12ffeee238fb4532b18f6b61cf51b23c1c7e1ad2e41560dc27edc0a2b9e647a0b3e4e806fced5b65e61d0f1f5197d3e2285c632d359e27b6b9206b2caffea4f67e0c7a2812e7a22c134b98cf89bd43d9f28b8bec25cce037a0ac5b1ae8f667e54e1250813a5263004486b4465ad4e641ab2b535736ea26535a11013564f08f483b7dab1c2bcc3ee38eadf2f7850eff7e3459a4bbabf9f0cf6c50d0c0a4120565cd4a2ce3e354c11721cd695760a24c70e0d5a0dfc3c5dcd51dfad6de2c237a682f36dc0b271f21bb3655e5333016aaa42c2efa1446e5f3c0a79ec417c4d30f77556951cb0f05dbfafb82d9f95951a9ea241fda2a6388f73ace036b98acce079f0e4feebccc96290a86dcc89118a901210b245f2d114cf94396e4dbb461e82aa26a0581389707957968c7cdc466213bb1cd417db207ef40c05842ab67a01a9b96eb1430ebc26e795bb491258d326d5174ad549401059e41782121e506744af8af9d8e493644a87d613600888541cbbe538c625883f3eb4aa3102c5cfcc25de8e97af8927619ce6a731b3b8462d51d993066b935b0648d2344ad72e4fd70f347fbd81041042e5ea31cc7b2e3156a920b80ecba487b950ca32ca95fae85b759c936246ecf441a9fdd95e8fee932d6782cdec686064018c857efc47fb4b2a122600d5fdd79af2486f44df7e629184e1c573bc0a9b3feb40b190ef2861a1ab45e2ac2201b9cd42e495deea247269820ed32389a2810ad6c0f9a296d2a2d9c54089fed50b7f5ecfcd33ab9954360e1d7f5598c32128cfcf2a1d8bf14616818da8a5343bfa88f0eedf392e9d4ab1ace1b60324129cd4852c2e27813a9cf71a6ae6229a4fcecc1a756b3e664c5f50af333082616815a3bec8fc0b75b8e4e767d719"
						}
						]
					},
					"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
				},
				"version_info": {
				"min_compat_version": 0,
				"orig_version": 2,
				"version": 2
				}
			}
		]
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
	# ,1 ,false);
	```
	 */
	fn verify_slate_messages(&self, slate: &Slate) -> Result<(), ErrorKind>;

	/**
		Networked version of [Foreign::receive_tx](struct.Foreign.html#method.receive_tx).

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
			"version_info": {
				"version": 2,
				"orig_version": 2,
				"min_compat_version": 0
			},
			"num_participants": 2,
			"id": "0436430c-2b02-624c-2032-570501212b00",
			"tx": {
				"offset": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"body": {
					"inputs": [
						{
							"features": "Coinbase",
							"commit": "087df32304c5d4ae8b2af0bc31e700019d722910ef87dd4eec3197b80b207e3045"
						},
						{
							"features": "Coinbase",
							"commit": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7"
						}
					],
					"outputs": [
						{
							"features": "Plain",
							"commit": "0812276cc788e6870612296d926cba9f0e7b9810670710b5a6e6f1ba006d395774",
							"proof": "dcff6175390c602bfa92c2ffd1a9b2d84dcc9ea941f6f317bdd0f875244ef23e696fd17c71df79760ce5ce1a96aab1d15dd057358dc835e972febeb86d50ccec0dad7cfe0246d742eb753cf7b88c045d15bc7123f8cf7155647ccf663fca92a83c9a65d0ed756ea7ebffd2cac90c380a102ed9caaa355d175ed0bf58d3ac2f5e909d6c447dfc6b605e04925c2b17c33ebd1908c965a5541ea5d2ed45a0958e6402f89d7a56df1992e036d836e74017e73ccad5cb3a82b8e139e309792a31b15f3ffd72ed033253428c156c2b9799458a25c1da65b719780a22de7fe7f437ae2fccd22cf7ea357ab5aa66a5ef7d71fb0dc64aa0b5761f68278062bb39bb296c787e4cabc5e2a2933a416ce1c9a9696160386449c437e9120f7bb26e5b0e74d1f2e7d5bcd7aafb2a92b87d1548f1f911fb06af7bd6cc13cee29f7c9cb79021aed18186272af0e9d189ec107c81a8a3aeb4782b0d950e4881aa51b776bb6844b25bce97035b48a9bdb2aea3608687bcdd479d4fa998b5a839ff88558e4a29dff0ed13b55900abb5d439b70793d902ae9ad34587b18c919f6b875c91d14deeb1c373f5e76570d59a6549758f655f1128a54f162dfe8868e1587028e26ad91e528c5ae7ee9335fa58fb59022b5de29d80f0764a9917390d46db899acc6a5b416e25ecc9dccb7153646addcc81cadb5f0078febc7e05d7735aba494f39ef05697bbcc9b47b2ccc79595d75fc13c80678b5e237edce58d731f34c05b1ddcaa649acf2d865bbbc3ceda10508bcdd29d0496744644bf1c3516f6687dfeef5649c7dff90627d642739a59d91a8d1d0c4dc55d74a949e1074427664b467992c9e0f7d3af9d6ea79513e8946ddc0d356bac49878e64e6a95b0a30214214faf2ce317fa622ff3266b32a816e10a18e6d789a5da1f23e67b4f970a68a7bcd9e18825ee274b0483896a40"
						}
					],
					"kernels": [
						{
							"features": "Plain",
							"fee": "7000000",
							"lock_height": "0",
							"excess": "000000000000000000000000000000000000000000000000000000000000000000",
							"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
						}
					]
				}
			},
			"amount": "60000000000",
			"fee": "7000000",
			"height": "5",
			"lock_height": "0",
			"participant_data": [
				{
					"id": "0",
					"public_blind_excess": "033ac2158fa0077f087de60c19d8e431753baa5b63b6e1477f05a2a6e7190d4592",
					"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
					"part_sig": null,
					"message": null,
					"message_sig": null
				}
			]
		},
		null,
		"Thanks, Yeastplume"
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
				"amount": "60000000000",
				"fee": "7000000",
				"height": "5",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"lock_height": "0",
				"num_participants": 2,
				"participant_data": [
				{
					"id": "0",
					"message": null,
					"message_sig": null,
					"part_sig": null,
					"public_blind_excess": "033ac2158fa0077f087de60c19d8e431753baa5b63b6e1477f05a2a6e7190d4592",
					"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				},
				{
					"id": "1",
					"message": "Thanks, Yeastplume",
		  "message_sig": "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078ff97f43f2eda0f695161ba23dc48db7a1bcbd7f131f1e21bdb4e1ad1eb2f1a130",
					"part_sig": "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078ffc965b05962362aee43e5264bd3fd0f26dbd7092cfe070069e26d2df28bd352b",
					"public_blind_excess": "038fe0443243dab173c068ef5fa891b242d2b5eb890ea09475e6e381170442ee16",
					"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				}
				],
				"tx": {
				"body": {
					"inputs": [
					{
						"commit": "087df32304c5d4ae8b2af0bc31e700019d722910ef87dd4eec3197b80b207e3045",
						"features": "Coinbase"
					},
					{
						"commit": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
						"features": "Coinbase"
					}
					],
					"kernels": [
					{
						"excess": "000000000000000000000000000000000000000000000000000000000000000000",
						"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
						"features": "Plain",
						"fee": "7000000",
						"lock_height": "0"
					}
					],
					"outputs": [
					{
						"commit": "084ee97defa8c37124d4c69baa753e2532535faa81f79ea5e0489db25297d5beb8",
						"features": "Plain",
						"proof": "bffb26e7df4bf753f4d8e810c67fb5106b1746c1870f5cb96585537eb8e2f66b372ed05fd35ae18c6e8515cd9f2aaae85d5a7655361c6a8573e20fbdfdda6e0a0b25817fc0db23dc25297382af379659d846bd8044f807c467722708d3a3797b84fceb09eb29f11c77b79c7c93c578d06d95b58d845930531e5cac6346d1373ee1c5db69c14d0aa1a9c22e187dc346156c468540ad166a04902d3faf357ed31a50775d274913ccc9ba976ca3977e18f383b20f0cd02a0866b7b44847bfbba35c099f5eba9c9747cad961033321925f3e0ad43e357aaecc50989bbbcb5b44ead58fe359c59903530c58bf1c9a6f9fb120a3492e835fabc01bb8b31b52b15ace4785a08c3ea9a82bd15c41c744544286b114b1be733fa6237300cf2dc99e8af6f8557bd9a083ba59cc1a500bdfba228b53785a7fdbf576f7dce035769058bc7644041ec5731485e5641eac5c75a6eb57e4abc287b0be8eab77c7e8a5122ee8d49f02f103a3af6fe38b8fcecd1aa9bb342b3e110f4003ee6c771ed93401ca3438dcf0d751a36dbb7a7a45d32709525686f3d2e5f542c747c9c745fe50cd789a0aa55419934afff363044d3c3f5f7669ebb9f2245b449bfdc4e09dfb1661552485107afbd9a2b571a0647b1fc330089a65e4b5df07f58f1a9c11c3da51d56cd854f227c5111d25ca8c4bec4bb0fbcb4a23fc3288418423dd0649d731b6a6c08851954ea920046ce67a4114d35c3876c25361e7a99474aa04354a4ed0555f9bef527d902fbb0d1d5c2b42f5eea5ced359005121167f9908729939dba610cdabca41f714e144ab148faec77f4d70566287671e6786459bd7d16787a24e12f2328b9faab1c7ac80a916d2f83f12a7351a2bedff610d33dfb2df7d8e57b68fb4a5dcc0d8e4fa807b2077877aa96ba7bc22e627a4f6a308d3abc091f56d518258f073cc1b70ef81"
					},
					{
						"commit": "0812276cc788e6870612296d926cba9f0e7b9810670710b5a6e6f1ba006d395774",
						"features": "Plain",
						"proof": "dcff6175390c602bfa92c2ffd1a9b2d84dcc9ea941f6f317bdd0f875244ef23e696fd17c71df79760ce5ce1a96aab1d15dd057358dc835e972febeb86d50ccec0dad7cfe0246d742eb753cf7b88c045d15bc7123f8cf7155647ccf663fca92a83c9a65d0ed756ea7ebffd2cac90c380a102ed9caaa355d175ed0bf58d3ac2f5e909d6c447dfc6b605e04925c2b17c33ebd1908c965a5541ea5d2ed45a0958e6402f89d7a56df1992e036d836e74017e73ccad5cb3a82b8e139e309792a31b15f3ffd72ed033253428c156c2b9799458a25c1da65b719780a22de7fe7f437ae2fccd22cf7ea357ab5aa66a5ef7d71fb0dc64aa0b5761f68278062bb39bb296c787e4cabc5e2a2933a416ce1c9a9696160386449c437e9120f7bb26e5b0e74d1f2e7d5bcd7aafb2a92b87d1548f1f911fb06af7bd6cc13cee29f7c9cb79021aed18186272af0e9d189ec107c81a8a3aeb4782b0d950e4881aa51b776bb6844b25bce97035b48a9bdb2aea3608687bcdd479d4fa998b5a839ff88558e4a29dff0ed13b55900abb5d439b70793d902ae9ad34587b18c919f6b875c91d14deeb1c373f5e76570d59a6549758f655f1128a54f162dfe8868e1587028e26ad91e528c5ae7ee9335fa58fb59022b5de29d80f0764a9917390d46db899acc6a5b416e25ecc9dccb7153646addcc81cadb5f0078febc7e05d7735aba494f39ef05697bbcc9b47b2ccc79595d75fc13c80678b5e237edce58d731f34c05b1ddcaa649acf2d865bbbc3ceda10508bcdd29d0496744644bf1c3516f6687dfeef5649c7dff90627d642739a59d91a8d1d0c4dc55d74a949e1074427664b467992c9e0f7d3af9d6ea79513e8946ddc0d356bac49878e64e6a95b0a30214214faf2ce317fa622ff3266b32a816e10a18e6d789a5da1f23e67b4f970a68a7bcd9e18825ee274b0483896a40"
					}
					]
				},
				"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
				},
				"version_info": {
				"min_compat_version": 0,
				"orig_version": 2,
				"version": 2
				}
			}
		}
	}
	# "#
	# , 5, true);
	```
	 */
	fn receive_tx(
		&self,
		slate: VersionedSlate,
		dest_acct_name: Option<String>,
		message: Option<String>,
	) -> Result<VersionedSlate, ErrorKind>;
}

impl<W: ?Sized, C, K> ForeignRpc for Foreign<W, C, K>
where
	W: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	fn check_version(&self) -> Result<VersionInfo, ErrorKind> {
		Foreign::check_version(self).map_err(|e| e.kind())
	}

	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<CbData, ErrorKind> {
		Foreign::build_coinbase(self, block_fees).map_err(|e| e.kind())
	}

	fn verify_slate_messages(&self, slate: &Slate) -> Result<(), ErrorKind> {
		Foreign::verify_slate_messages(self, slate).map_err(|e| e.kind())
	}

	fn receive_tx(
		&self,
		slate: VersionedSlate,
		dest_acct_name: Option<String>,
		message: Option<String>,
	) -> Result<VersionedSlate, ErrorKind> {
		let version = slate.version();
		let slate: Slate = slate.into();
		let slate = Foreign::receive_tx(
			self,
			&slate,
			dest_acct_name.as_ref().map(String::as_str),
			message,
		)
		.map_err(|e| e.kind())?;

		Ok(VersionedSlate::into_version(slate, version))
	}
}

/// helper to set up a real environment to run integrated doctests
pub fn run_doctest_foreign(
	request: serde_json::Value,
	test_dir: &str,
	blocks_to_mine: u64,
	init_tx: bool,
) -> Result<Option<serde_json::Value>, String> {
	use crate::{Foreign, ForeignRpc};
	use easy_jsonrpc::Handler;
	use grin_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};
	use grin_wallet_libwallet::api_impl;
	use grin_wallet_util::grin_keychain::ExtKeychain;

	use crate::core::global;
	use crate::core::global::ChainTypes;
	use grin_wallet_util::grin_util as util;

	use std::fs;
	use std::thread;

	util::init_test_logger();
	let _ = fs::remove_dir_all(test_dir);
	global::set_mining_mode(ChainTypes::AutomatedTesting);

	let mut wallet_proxy: WalletProxy<LocalWalletClient, ExtKeychain> = WalletProxy::new(test_dir);
	let chain = wallet_proxy.chain.clone();

	let rec_phrase_1 =
		"fat twenty mean degree forget shell check candy immense awful \
		 flame next during february bulb bike sun wink theory day kiwi embrace peace lunch";
	let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());
	let wallet1 = test_framework::create_wallet(
		&format!("{}/wallet1", test_dir),
		client1.clone(),
		Some(rec_phrase_1),
	);
	wallet_proxy.add_wallet("wallet1", client1.get_send_instance(), wallet1.clone());

	let rec_phrase_2 =
		"hour kingdom ripple lunch razor inquiry coyote clay stamp mean \
		 sell finish magic kid tiny wage stand panther inside settle feed song hole exile";
	let client2 = LocalWalletClient::new("wallet2", wallet_proxy.tx.clone());
	let wallet2 = test_framework::create_wallet(
		&format!("{}/wallet2", test_dir),
		client2.clone(),
		Some(rec_phrase_2),
	);
	wallet_proxy.add_wallet("wallet2", client2.get_send_instance(), wallet2.clone());

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// Mine a few blocks to wallet 1 so there's something to send
	for _ in 0..blocks_to_mine {
		let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), 1 as usize, false);
		//update local outputs after each block, so transaction IDs stay consistent
		let mut w = wallet1.lock();
		w.open_with_credentials().unwrap();
		let (wallet_refreshed, _) =
			api_impl::owner::retrieve_summary_info(&mut *w, true, 1).unwrap();
		assert!(wallet_refreshed);
		w.close().unwrap();
	}

	if init_tx {
		let amount = 60_000_000_000;
		let mut w = wallet1.lock();
		w.open_with_credentials().unwrap();
		let args = InitTxArgs {
			src_acct_name: None,
			amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let slate = api_impl::owner::initiate_tx(&mut *w, args, true).unwrap();
		println!("INIT SLATE");
		// Spit out slate for input to finalize_tx
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
	}

	let mut api_foreign = Foreign::new(wallet1.clone());
	api_foreign.doctest_mode = true;
	let foreign_api = &api_foreign as &dyn ForeignRpc;
	Ok(foreign_api.handle_request(request).as_option())
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_foreign_assert_response {
	($request:expr, $expected_response:expr, $blocks_to_mine:expr, $init_tx:expr) => {
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

		let response = run_doctest_foreign(request_val, dir, $blocks_to_mine, $init_tx)
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
