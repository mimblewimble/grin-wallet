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
