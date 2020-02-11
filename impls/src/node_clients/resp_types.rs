// Copyright 2020 The Grin Developers
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
// Derived from https://github.com/apoelstra/rust-jsonrpc

//! JSON RPC Types for V2 node client

#[derive(Debug, Deserialize)]
pub struct GetTipResp {
	pub height: u64,
	pub last_block_pushed: String,
	pub prev_block_to_last: String,
	pub total_difficulty: u64,
}

#[derive(Debug, Deserialize)]
pub struct GetVersionResp {
	pub node_version: String,
	pub block_header_version: u16,
}
