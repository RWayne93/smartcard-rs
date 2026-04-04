use std::ffi::CString;

use pcsc::{Context, MAX_BUFFER_SIZE, Protocols, Scope, ShareMode};
use smartcard_apdu::{ApduError, CommandApdu, ResponseApdu};
use smartcard_core::{CardSession, ReaderInfo, Result, SmartcardError, Transport};

pub struct PcscTransport {
    context: Context,
}

impl PcscTransport {
    pub fn establish_user() -> Result<Self> {
        Self::establish(Scope::User)
    }

    pub fn establish(scope: Scope) -> Result<Self> {
        let context = Context::establish(scope).map_err(map_pcsc_error)?;
        Ok(Self { context })
    }
}

impl Transport for PcscTransport {
    fn list_readers(&self) -> Result<Vec<ReaderInfo>> {
        let readers = self.context.list_readers_owned().map_err(map_pcsc_error)?;
        Ok(readers
            .into_iter()
            .map(|reader| ReaderInfo::new(reader.to_string_lossy().into_owned()))
            .collect())
    }

    fn connect(&self, reader: &str) -> Result<Box<dyn CardSession>> {
        let reader = CString::new(reader).map_err(|_| {
            SmartcardError::invalid_argument("reader name contains interior NUL bytes")
        })?;
        let card = self
            .context
            .connect(&reader, ShareMode::Shared, Protocols::ANY)
            .map_err(map_pcsc_error)?;

        let status = card.status2_owned().map_err(map_pcsc_error)?;
        let atr = status.atr();
        let atr = if atr.is_empty() {
            None
        } else {
            Some(atr.to_vec())
        };

        Ok(Box::new(PcscSession {
            card,
            reader_name: reader.to_string_lossy().into_owned(),
            atr,
        }))
    }
}

struct PcscSession {
    card: pcsc::Card,
    reader_name: String,
    atr: Option<Vec<u8>>,
}

impl CardSession for PcscSession {
    fn reader_name(&self) -> &str {
        &self.reader_name
    }

    fn atr(&self) -> Option<&[u8]> {
        self.atr.as_deref()
    }

    fn transmit(&mut self, command: &CommandApdu) -> Result<ResponseApdu> {
        let encoded = command
            .encode()
            .map_err(|error| SmartcardError::protocol(error.to_string()))?;
        let tx = self.card.transaction().map_err(map_pcsc_error)?;
        let mut rapdu_buf = [0; MAX_BUFFER_SIZE];
        let rapdu = tx
            .transmit(&encoded, &mut rapdu_buf)
            .map_err(map_pcsc_error)?;
        ResponseApdu::from_bytes(rapdu).map_err(map_apdu_error)
    }
}

fn map_pcsc_error(error: pcsc::Error) -> SmartcardError {
    SmartcardError::transport(error.to_string())
}

fn map_apdu_error(error: ApduError) -> SmartcardError {
    SmartcardError::protocol(error.to_string())
}
