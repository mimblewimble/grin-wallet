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

use serde::{Deserialize, Serialize};
use futures::future;

/// Chunk payload type
pub enum ChunkPayloadType {
    /// First chunk
    Init = 0x00,
    /// Append chunk
    Add = 0x01,
    /// Last chunk
    Last = 0x02,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
/// App Version
pub struct Version {
    /// Application Mode
    #[serde(rename(serialize = "testMode"))]
    pub mode: u8,
    /// Version Major
    pub major: u16,
    /// Version Minor
    pub minor: u16,
    /// Version Patch
    pub patch: u16,
    /// Device is locked
    pub locked: bool,
    /// Target ID
    pub target_id: [u8; 4],
}

#[derive(Clone, Debug, Deserialize, Serialize)]
/// App Information
pub struct AppInfo {
    /// Name of the application
    #[serde(rename(serialize = "appName"))]
    pub app_name: String,
    /// App version
    #[serde(rename(serialize = "appVersion"))]
    pub app_version: String,
    /// Flag length
    #[serde(rename(serialize = "flagLen"))]
    pub flag_len: u8,
    /// Flag value
    #[serde(rename(serialize = "flagsValue"))]
    pub flags_value: u8,
    /// Flag Recovery
    #[serde(rename(serialize = "flagsRecovery"))]
    pub flag_recovery: bool,
    /// Flag Signed MCU code
    #[serde(rename(serialize = "flagsSignedMCUCode"))]
    pub flag_signed_mcu_code: bool,
    /// Flag Onboarded
    #[serde(rename(serialize = "flagsOnboarded"))]
    pub flag_onboarded: bool,
    /// Flag Pin Validated
    #[serde(rename(serialize = "flagsPINValidated"))]
    pub flag_pin_validated: bool,
}
