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
						"part": "jwfd1en1F5z/GUhgNBge12UFuqrVPl2ZQGQSe1bFhBsrNb0o39ImngZw4M+ScL1t8tA/vWRSPuSuYiOWBVuW/A==",
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
					"part": "jwfd1en1F5z/GUhgNBge12UFuqrVPl2ZQGQSe1bFhBsYQNae1fM7ybQkQikD1dHT6bkUFDvL47ftMtjxX8zM4w=="
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
				"coms": [
					{
						"c": "CH3zIwTF1K6LKvC8MecAAZ1yKRDvh91O7DGXuAsgfjBF",
						"f": 1
					},
					{
						"c": "COHanm3E1ugIpxiy8RCpkd13XWXOWuQIpOHwAqSWGqnn",
						"f": 1
					},
					{
						"c": "CZtIz7H4CiNH3ImBhEnmjnajxoF6UyqOnvK0pcz0NjhQ",
						"p": "KXAc6uJiysd7ebhoyIOikuYebegZK4aO3NEwCwlz2ROWsVas5r1nNAKjA94Q3dil5rfxe6ZVeldKZyvQTMJzqwTtjiyoC6xIM0XA7IQ/UhgUzhMB7JrcOJVqErTZSKzOcSlaT1K83rihyfLWstpdcxJipenAJ275BN+e+NSAAUIM1Z91ovGuXHocfGufFA52E+Uu+eJJ8p+TQLfvuAaZ5GAWQyRhb5j9TN49tSSXyRnpUiL//qy35l3sp+NoqAznE8Gd59pTaXJiKO4zb1vUlFOMEsy//rG5v9X8iQbRxkJFtRbxA/qW2cVpdYN2UsHg+lgD18zxFH2Pkn422nF/eteUcdvhkvX1D4enn8P+Aw26VptjS5LSzzB5k8zlRWM68mOJfNfm6/Tcr7F20HNYvcONA+RaSd+pyMZRfNaNFn/79sO03g4t0hkJy61MRnuE5XAL5HOjmsWcZp18FVxLyrm4Am7qNDHHec0nfkki0rl0Lh9meMvoaew7W370Ey3bbN0Gzyfb6yi+crlJ+ol2EOSOOg14n9Lup1q8l7PcfgDlyLPSTkDG8kESrbcjUriaK+8FmTRTOOnnYgKjxG76Y3CVKyrKQarbrg6jJTGsr82rbdBm12nr9Qz088ClnS1fp5YAoge5QXxiP3atBejMz81AOPlEi8QPEnynwNNy5GB04zT+SfWpVuwAVvTaYB5q+A6xpsSVEFSGnmZbKW2MFPNEyi3F/dXfSjZSU2NloWFa2bQiFlx3v4/mWoNcjgxB4HABTrZu+MUlIE6ZCzo9ZjweQiIbSWiVw3ovDBvwXpEjVAnD/j2JqaedbHhgmrGKRjMRkR9x+je7c7FfzTgUPRQE/SzoEATcf/ic8RFdzAw1zhwb+ZQVhvuVl3DyYYzLcRin"
					},
					{
						"c": "CBInbMeI5ocGEiltkmy6nw57mBBnBxC1pubxugBtOVd0",
						"p": "KEufkZlBHGu/cifq4VzJ+n7TBTSvPs/4Ww0BbaMpyuHx7fefAUJkNMuQr8wvCh+yluXFGpG15XofAjD9pPjFlQ55hvo3m5nWS2A5qGzH414EC6GSt4EEOVmFEmjKmHSpGIBeqVjIT3/ujTq0Ji8DL1o/hA683Sc7Kb6BARTm6GqVnY5MCAVy4+8knt1q1oUD7DvESGVIUg6id1pBrqZ6rJmUX86eendp1x+JOtfw0BCGkva2hSMSyub5hXBjBVvaWdzlIZJ8cAQLgCakG2UXyuChyUfKJEmEpcCt98ZIOwk5NGxI9hysN9UB9GocWHi2fO4NByP07q3J9dce1enzO0KUtY0+vu/qoT8gNXWZvlSc4Y5uLrHVDhI1zMQOyRhMaKYjdBpyOM5pqjodJRVrO36zj91vvlRzl5/u4zF98nnGDUiiiYJqpMdtvOJNUmiQ1Obi+D6A9nShJI/B3AN9mCAJASrhEz9eFYrmza2xjI1T5KiuVZXHWHgsZ6oMIPFG1SCFz0WjV5TOxFcCgw+JUqaXRHGPvm/g09pm40jdNHOgrO1wgPv1SUw+fhQZFvOxNbMyd/mY/Nms+8qHCYFIZumDil3NpMKUIs8VcpPm/CzMLSVCNReEO9jiHGHO1yMSwLSIFMMSAhsNMVmNI4mwsym6oRaZIqTDQXPdX1QFRb5QZqDykfGocOGq/5TBnwqFUlSIKheYS67aCOjq1T0VY+nuS8NnQnic7086sVgFTX3f4qKze1qKML6E/335p9dYqbdnUaNiIFdyGj7FuHNYLQyRzR/rvBU2YnOYVOoVyZAwI8GTxrV2i1VIQQj4l83EfROpCIsyVY5X8S9YB2aGScmaF7UZBRJzQOi0nEJ3Xxs8qwct+tM9M8weS6WWTXKO0KkF"
					}
				],
				"id": "BDZDDCsCYkwgMlcFASErAA==",
				"sigs": [
					{
						"nonce": "AxuExVZ7EmRAmV0+1aq6BWXXHhg0YEgZ/5wX9enV3QeP",
						"part": "jwfd1en1F5z/GUhgNBge12UFuqrVPl2ZQGQSe1bFhBsYQNae1fM7ybQkQikD1dHT6bkUFDvL47ftMtjxX8zM4w==",
						"xs": "Ap8S+fjFSJoYkE3nzUbcM4S3k2nUy8F810spnajCz3RF"
					},
					{
						"nonce": "AxuExVZ7EmRAmV0+1aq6BWXXHhg0YEgZ/5wX9enV3QeP",
						"part": "jwfd1en1F5z/GUhgNBge12UFuqrVPl2ZQGQSe1bFhBvJ6iGyWdYeTeF32e+KtHXfqw7HKZAJp/6mEBD5Y/LmwA==",
						"xs": "Azu+KkGeounWgQqNZlUucJ0Xg8pQdZpE269j/HnAFkxM"
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
