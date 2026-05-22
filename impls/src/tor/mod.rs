// Copyright 2018 The Grin Developers
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

pub mod bridge;
pub mod config;
pub mod process;
pub mod proxy;
pub mod arti;

/// Running Tor instance control.
pub struct Tor {
    /// External to process control.
    pub process: Option<process::TorProcess>,
    /// Integrated service.
    pub service: Option<std::sync::Arc<tor_hsservice::RunningOnionService>>,
    /// Integrated client.
    pub client: Option<arti_client::TorClient<tor_rtcompat::tokio::TokioNativeTlsRuntime>>
}
