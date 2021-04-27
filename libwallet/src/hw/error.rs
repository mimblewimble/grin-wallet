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

use thiserror::Error;
use serde::{Deserialize, Serialize};

/// Error definition
pub struct Error {
	
}

/// App Error
#[derive(Clone, Debug, Eq, Error, PartialEq, Deserialize, Serialize)]
pub enum LedgerAppError {
    /// Invalid version error
    #[error("This version is not supported")]
    InvalidVersion,
    /// The message cannot be empty
    #[error("message cannot be empty")]
    InvalidEmptyMessage,
    /// Invalid payload type in chunk
    #[error("The chunk payload type was invalid. First message should be Init")]
    InvalidChunkPayloadType,
    /// The size fo the message to sign is invalid
    #[error("message size is invalid (too big)")]
    InvalidMessageSize,
    /// Public Key is invalid
    #[error("received an invalid PK")]
    InvalidPK,
    /// No signature has been returned
    #[error("received no signature back")]
    NoSignature,
    /// The signature is not valid
    #[error("received an invalid signature")]
    InvalidSignature,
    /// The derivation is invalid
    #[error("invalid derivation path")]
    InvalidDerivationPath,
    /// The derivation is invalid
    #[error("Transport | {0}")]
    TransportError(#[from] TransportError),
    /// Crypto related errors
    #[error("Crypto")]
    Crypto,
    /// Utf8 related errors
    #[error("Utf8 conversion error")]
    Utf8,
    /// Format ID error
    #[error("response format ID not recognized")]
    InvalidFormatID,
    /// HexEncode
    #[error("Couldn't encode string to HEX")]
    HexEncode,
    /// Application specific error
    #[error("App Error: | {0} {1}")]
    AppSpecific(u16, String),
}

/// Transport Error
#[derive(Clone, Debug, Eq, Error, PartialEq, Deserialize, Serialize)]
pub enum TransportError {
    /// Transport specific error
    #[error("APDU Exchange Error")]
    APDUExchangeError,
    /// Response was too short (< 2 bytes)
    #[error("APDU Response was too short")]
    ResponseTooShort,
    /// Error Unknown
    #[error("Unknown Error")]
    UnknownError,
}

/// Ledger HID Error
#[derive(Error, Debug)]
pub enum LedgerHIDError {
    /// Device not found error
    #[error("Ledger device not found")]
    DeviceNotFound,
    /// Communication error
    #[error("Ledger device: communication error `{0}`")]
    Comm(&'static str),
    /// Ioctl error
    #[error("Ledger device: Ioctl error")]
    Ioctl(#[from] crate::nix::Error),
    /// i/o error
    #[error("Ledger device: i/o error")]
    Io(#[from] std::io::Error),
    /// HID error
    #[error("Ledger device: Io error")]
    Hid(#[from] hidapi::HidError),
    /// UT8F error
    #[error("Ledger device: UTF8 error")]
    UTF8(#[from] std::str::Utf8Error),
}

/// APDU packet error codes
#[derive(Copy, Clone)]
pub enum APDUErrorCodes {
    NoError = 0x9000,
    ExecutionError = 0x6400,
    WrongLength = 0x6700,
    EmptyBuffer = 0x6982,
    OutputBufferTooSmall = 0x6983,
    DataInvalid = 0x6984,
    ConditionsNotSatisfied = 0x6985,
    CommandNotAllowed = 0x6986,
    BadKeyHandle = 0x6A80,
    InvalidP1P2 = 0x6B00,
    InsNotSupported = 0x6D00,
    ClaNotSupported = 0x6E00,
    Unknown = 0x6F00,
    SignVerifyError = 0x6F01,
}