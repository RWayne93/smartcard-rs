use std::sync::Arc;

use smartcard_apdu::{CommandApdu, ResponseApdu};

use crate::{ReaderInfo, Result};

pub trait CardSession {
    fn reader_name(&self) -> &str;
    fn atr(&self) -> Option<&[u8]>;
    fn transmit(&mut self, command: &CommandApdu) -> Result<ResponseApdu>;
}

pub trait Transport: Send + Sync {
    fn list_readers(&self) -> Result<Vec<ReaderInfo>>;
    fn connect(&self, reader: &str) -> Result<Box<dyn CardSession>>;
}

pub type SharedTransport = Arc<dyn Transport>;
