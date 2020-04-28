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
	self, BlockFees, CbData, ErrorKind, InitTxArgs, IssueInvoiceTxArgs, NodeClient,
	NodeVersionInfo, Slate, SlateVersion, VersionInfo, VersionedCoinbase, VersionedSlate,
	WalletLCProvider,
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
					"V4",
					"V3"
				]
			}
		}
	}
	# "#
	# ,false, 0, false, false);
	```
	*/
	fn check_version(&self) -> Result<VersionInfo, ErrorKind>;

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
					"features": "Coinbase",
					"fee": "0",
					"lock_height": "0"
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

	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<VersionedCoinbase, ErrorKind>;

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
				"ver": "4:2",
				"id": "BDZDDCsCYkwgMlcFASErAA==",
				"sta": "S1",
				"amt": "60000000000",
				"fee": "7000000",
				"sigs": [
					{
						"xs": "AzrCFY+gB38IfeYMGdjkMXU7qltjtuFHfwWipucZDUWS",
						"nonce": "AxuExVZ7EmRAmV0+1aq6BWXXHhg0YEgZ/5wX9enV3QeP"
					}
				]
			},
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
						"c": "CE7pfe+ow3Ek1MabqnU+JTJTX6qB956l4EidslKX1b64",
						"p": "AH333d0e/KdXsgcHQMxgRig5DrWeFR+W/y6qU2H1Q1/Rqm6j/ryX/P4bMkjQQMgt42GAOSl2ui0RR8L7AhyHrQRPH5djk02dP0QxQXdi7tA8U84Xrtt4JFZcH0j8zsnEq8DSi9MrAs6b7kC/amDPfJwgPMJOS3efkB4SyYdXNpjPfwTjqs4m5xJiE4YFQkgArfMpXQn39F3d8YVceF6Y1F6uPNER0YVS5zOJVFjfFecaE4ONeJpMs2n03biqnFA7CA/YihRyRd8FItQTbTahg72UHmz5Tf/HhDixIZTU33EU0eJ6ei8BSSCjISI+y+uyuWQqIvjtTnSIMSXz51ey8RiFP/qxto8VwaLQIeWD/z/R6ihyCoEyWzzCMnup+y/ZsmRK2388ey4xmyU2o09n5vCTRvJNpryuGyQfhZBJNHbf41sYPlTxBeshm2AeDlOWVAlwHcH9lWLEKtl3UF6nvyZPAXcFaaSjWKcPsLLGWWn6w7I5VPDKCtrOBwMkPx2rYmUJqGVuepgXCcOsHVFpS6+lWq1FwQGTfL8+RdZwjAe+cUGXaaEKT2Tyt9U6VOrHPNvTJ5+RxfiZGksXYhw2GVqTkTZPoiHoqN7iHrw6brnNKUCjZ25+883UYxm9wR90h4Xkn/Qb7CwyQyVdg8aJW8DIk+anctdECmgyEkaxd3CdO9gtDcL1vKQMh46Fm2+CMZo4bgt/y8gBCiUXiwhBg4m6fGp3+ZrH9K5caGq2V0/NARb4VzvM2j7f3/NsnJLOL7i/sM4v5caySYxusW/C1A3p3cuhmafpPWSKvznWskjhlt5xJ+a4EuMIBJfyqCr6aaRxq1EedT5bF6HDnGcooGWJivZnRgjZKmJeluLwJY/i6waifQWG2InWH5f6qj+s9Yza"
					}
				],
				"id": "BDZDDCsCYkwgMlcFASErAA==",
				"sigs": [
					{
						"nonce": "AxuExVZ7EmRAmV0+1aq6BWXXHhg0YEgZ/5wX9enV3QeP",
						"part": "jwfd1en1F5z/GUhgNBge12UFuqrVPl2ZQGQSe1bFhBuDzJAtTJOYgRDsL76wJaXewdjHgSi+P4wTP6JNel0H5g==",
						"xs": "A4/gRDJD2rFzwGjvX6iRskLSteuJDqCUdebjgRcEQu4W"
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
	) -> Result<VersionedSlate, ErrorKind>;

	/**

	Networked version of [Foreign::finalize_invoice_tx](struct.Foreign.html#method.finalize_invoice_tx).

	# Json rpc example

	```
	# grin_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "finalize_invoice_tx",
		"id": 1,
		"params": [{
			"ver": "4:2",
			"id": "BDZDDCsCYkwgMlcFASErAA==",
			"sta": "I2",
			"fee": "7000000",
			"sigs": [
				{
					"xs": "Ap8S+fjFSJoYkE3nzUbcM4S3k2nUy8F810spnajCz3RF",
					"nonce": "AxuExVZ7EmRAmV0+1aq6BWXXHhg0YEgZ/5wX9enV3QeP",
					"part": "jwfd1en1F5z/GUhgNBge12UFuqrVPl2ZQGQSe1bFhBvq4k8bzeCFWV1DPpSAyld7oKe/CX+IdBoOgUMGt2Doag=="
				}
			],
			"coms": [
				{
					"f": 1,
					"c": "CH3zIwTF1K6LKvC8MecAAZ1yKRDvh91O7DGXuAsgfjBF"
				},
				{
					"f": 1,
					"c": "COHanm3E1ugIpxiy8RCpkd13XWXOWuQIpOHwAqSWGqnn"
				},
				{
					"c": "CBInbMeI5ocGEiltkmy6nw57mBBnBxC1pubxugBtOVd0",
					"p": "KEufkZlBHGu/cifq4VzJ+n7TBTSvPs/4Ww0BbaMpyuHx7fefAUJkNMuQr8wvCh+yluXFGpG15XofAjD9pPjFlQ55hvo3m5nWS2A5qGzH414EC6GSt4EEOVmFEmjKmHSpGIBeqVjIT3/ujTq0Ji8DL1o/hA683Sc7Kb6BARTm6GqVnY5MCAVy4+8knt1q1oUD7DvESGVIUg6id1pBrqZ6rJmUX86eendp1x+JOtfw0BCGkva2hSMSyub5hXBjBVvaWdzlIZJ8cAQLgCakG2UXyuChyUfKJEmEpcCt98ZIOwk5NGxI9hysN9UB9GocWHi2fO4NByP07q3J9dce1enzO0KUtY0+vu/qoT8gNXWZvlSc4Y5uLrHVDhI1zMQOyRhMaKYjdBpyOM5pqjodJRVrO36zj91vvlRzl5/u4zF98nnGDUiiiYJqpMdtvOJNUmiQ1Obi+D6A9nShJI/B3AN9mCAJASrhEz9eFYrmza2xjI1T5KiuVZXHWHgsZ6oMIPFG1SCFz0WjV5TOxFcCgw+JUqaXRHGPvm/g09pm40jdNHOgrO1wgPv1SUw+fhQZFvOxNbMyd/mY/Nms+8qHCYFIZumDil3NpMKUIs8VcpPm/CzMLSVCNReEO9jiHGHO1yMSwLSIFMMSAhsNMVmNI4mwsym6oRaZIqTDQXPdX1QFRb5QZqDykfGocOGq/5TBnwqFUlSIKheYS67aCOjq1T0VY+nuS8NnQnic7086sVgFTX3f4qKze1qKML6E/335p9dYqbdnUaNiIFdyGj7FuHNYLQyRzR/rvBU2YnOYVOoVyZAwI8GTxrV2i1VIQQj4l83EfROpCIsyVY5X8S9YB2aGScmaF7UZBRJzQOi0nEJ3Xxs8qwct+tM9M8weS6WWTXKO0KkF"
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
				"amount": "60000000000",
				"fee": "7000000",
				"height": "5",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"participant_data": [
					{
						"part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bc9ea21b259d61e4de177d9ef8ab475dfab0ec7299009a7fea61010f963f2e6c0",
						"public_blind_excess": "033bbe2a419ea2e9d6810a8d66552e709d1783ca50759a44dbaf63fc79c0164c4c",
						"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					},
					{
						"part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b1840d69ed5f33bc9b424422903d5d1d3e9b914143bcbe3b7ed32d8f15fcccce3",
						"public_blind_excess": "029f12f9f8c5489a18904de7cd46dc3384b79369d4cbc17cd74b299da8c2cf7445",
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
								"excess": "09bac6083b05a32a9d9b37710c70dd0a1ef9329fde0848558976b6f1b81d80ceed",
								"excess_sig": "66074d25a751c4743342c90ad8ead9454daa00d9b9aed29bca321036d16c4b4da0e9c180a26b88565afcd269a7ac98f896c8db3dcbd48ab69443e8eac3beb3a4",
								"features": "Plain",
								"fee": "7000000",
								"lock_height": "0"
							}
						],
						"outputs": [
							{
								"commit": "099b48cfb1f80a2347dc89818449e68e76a3c6817a532a8e9ef2b4a5ccf4363850",
								"features": "Plain",
								"proof": "7ebcd2ed9bf5fb29854033ba3d0e720613bdf7dfacc586d2f6084c1cde0a2b72e955d4ce625916701dc7c347132f40d0f102a34e801d745ee54b49b765d08aae0bb801c60403e57cafade3b4b174e795b633ab9e402b5b1b6e1243fd10bbcf9368a75cb6a6c375c7bdf02da9e03b7f210df45d942e6fba2729cd512a372e6ed91a1b5c9c22831febea843e3f85adcf198f39ac9f7b73b70c60bfb474aa69878ea8d1d32fef30166b59caacaec3fd024de29a90f1587e08d2c36b3d5c560cabf658e212e0a40a4129b3e5c35557058def5551f4eb395759597ba808b3c34eac3bfb9716e4480d7931c5789c538463ec75be0eb807c894047fda6cbcd22682d3c6d3823cb330f090a2099e3510a3706b57d46c95224394d7f1c0a20d99cc314b8f1d9d02668e2e435f62e1194de0be6a1f50f72ed777ed51c8819f527a94918d1aa8df6461e98ed4c2b18210de50fbcf8c3df210bfe326d41f1dc0ad748cb0320ae28401c85ab4f7dcb99d88a052e95dc85b76d22b36cabd60e06ab84bb7e4ddfdab9c9730c8a986583237ed1ecbb323ee8e79b8cadca4b438b7c09531670b471dda6a2eb3e747916c88ce7d9d8e1b7f61660eeb9e5a13c60e4dfe89d1177d81d6f6570fda85158e646a15f1e8b9e977494dc19a339aab2e0e478670d80092d6ba37646e60714ef64eb4a3d37fe15f8f38b59114af34b235489eed3f69b7781c5fe496eb43ffe245c14bd740f745844a38cf0d904347aaa2b64f51add18822dac009d8b63fa3e4c9b1fa72187f9a4acba1ab315daa1b04c9a41f3be846ac420b37990e6c947a16cc9d5c0671b292bf77d7d8b8974d2ad3afae95ba7772c37432840f53a007f31e0195f3abdf100c4477723cc6c6d5da14894a73dfac342833731036487488fdade7b9d556c06f26173b6b67598d3769447ce2828d71dd45ac5af436c6b0"
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
				"ver": "4.3"
			}
		}
	}
	# "#
	# ,false, 5, false, true);
	```
	*/
	fn finalize_invoice_tx(&self, slate: VersionedSlate) -> Result<VersionedSlate, ErrorKind>;
}

impl<'a, L, C, K> ForeignRpc for Foreign<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	fn check_version(&self) -> Result<VersionInfo, ErrorKind> {
		Foreign::check_version(self).map_err(|e| e.kind())
	}

	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<VersionedCoinbase, ErrorKind> {
		let cb: CbData = Foreign::build_coinbase(self, block_fees).map_err(|e| e.kind())?;
		Ok(VersionedCoinbase::into_version(cb, SlateVersion::V3))
	}

	fn receive_tx(
		&self,
		in_slate: VersionedSlate,
		dest_acct_name: Option<String>,
	) -> Result<VersionedSlate, ErrorKind> {
		let version = in_slate.version();
		let slate_from = Slate::from(in_slate);
		let out_slate = Foreign::receive_tx(
			self,
			&slate_from,
			dest_acct_name.as_ref().map(String::as_str),
		)
		.map_err(|e| e.kind())?;
		Ok(VersionedSlate::into_version(out_slate, version).map_err(|e| e.kind())?)
	}

	fn finalize_invoice_tx(&self, in_slate: VersionedSlate) -> Result<VersionedSlate, ErrorKind> {
		let version = in_slate.version();
		let out_slate =
			Foreign::finalize_invoice_tx(self, &Slate::from(in_slate)).map_err(|e| e.kind())?;
		Ok(VersionedSlate::into_version(out_slate, version).map_err(|e| e.kind())?)
	}
}

fn test_check_middleware(
	_name: ForeignCheckMiddlewareFn,
	_node_version_info: Option<NodeVersionInfo>,
	_slate: Option<&Slate>,
) -> Result<(), libwallet::Error> {
	// TODO: Implement checks
	// return Err(ErrorKind::GenericError("Test Rejection".into()))?
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
	use grin_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};
	use grin_wallet_impls::{DefaultLCProvider, DefaultWalletImpl};
	use grin_wallet_libwallet::{api_impl, WalletInst};
	use grin_wallet_util::grin_keychain::ExtKeychain;

	use crate::core::global;
	use crate::core::global::ChainTypes;
	use grin_wallet_util::grin_util as util;

	use std::sync::Arc;
	use util::Mutex;

	use std::fs;
	use std::thread;

	util::init_test_logger();
	let _ = fs::remove_dir_all(test_dir);
	global::set_mining_mode(ChainTypes::AutomatedTesting);

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
		// Spit out slate for input to finalize_invoice_tx
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
		false => Foreign::new(wallet1, mask1, Some(test_check_middleware)),
		true => Foreign::new(wallet2, mask2, Some(test_check_middleware)),
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
