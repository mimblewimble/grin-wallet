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

use crate::error::*;
use trait_async::trait_async;

#[derive(Debug)]
/// Commands follow the ISO/IEC 7816-4 smartcard protocol.
pub struct APDUCommand {
    /// Protocol version
    pub cla: u8, 
    /// Instruction command
    pub ins: u8,
    /// Subcommand
    pub p1: u8,
    /// Command/Subcommand counter
    pub p2: u8,
    /// options, additional data
    pub data: Vec<u8>, 
}

#[derive(Debug)]
pub struct APDUAnswer {
    pub data: Vec<u8>,
    pub retcode: u16,
}

/// Transport struct
pub struct APDUTransport {
    /// Native rust transport
    pub transport_wrapper: Box<dyn Exchange>,
}

/// Use this method to communicate with the ledger device
#[trait_async]
pub trait Exchange: Send + Sync {
    /// Use to talk to the ledger device
    async fn exchange(&self, command: &APDUCommand) -> Result<APDUAnswer, TransportError>;
}
