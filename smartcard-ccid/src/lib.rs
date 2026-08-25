use pcsc_rs::{
    ipc::{self, Client},
    usb::{self, Reader},
};
use smartcard_apdu::{ApduError, CommandApdu, ResponseApdu};
use smartcard_core::{CardSession, ReaderInfo, Result, SmartcardError, Transport};

const SCARD_SHARE_SHARED: u64 = 0x0002;
const SCARD_PROTOCOL_T1: u64 = 0x0002;

#[derive(Clone, Debug, Default)]
pub struct CcidTransport;

impl CcidTransport {
    pub fn new() -> Self {
        Self
    }
}

impl Transport for CcidTransport {
    fn list_readers(&self) -> Result<Vec<ReaderInfo>> {
        let readers = usb::list_readers().map_err(map_usb_error)?;
        Ok(readers
            .into_iter()
            .map(|reader| ReaderInfo::new(reader.pcsc_name()))
            .collect())
    }

    fn connect(&self, reader: &str) -> Result<Box<dyn CardSession>> {
        let reader_info = usb::list_readers()
            .map_err(map_usb_error)?
            .into_iter()
            .find(|candidate| candidate.pcsc_name() == reader)
            .ok_or_else(|| SmartcardError::not_found(format!("reader {reader:?}")))?;

        let reader_name = reader_info.pcsc_name();
        let mut reader = Reader::open(reader_info.index).map_err(map_usb_error)?;
        let power_on = reader.power_on().map_err(map_usb_error)?;
        let atr = if power_on.data.is_empty() {
            None
        } else {
            Some(power_on.data)
        };

        Ok(Box::new(CcidSession {
            reader_name,
            reader,
            atr,
        }))
    }
}

#[derive(Clone, Debug)]
pub struct DaemonTransport {
    client: Client,
}

impl DaemonTransport {
    pub fn from_env() -> Self {
        Self {
            client: Client::from_env(),
        }
    }

    pub fn with_client(client: Client) -> Self {
        Self { client }
    }
}

impl Default for DaemonTransport {
    fn default() -> Self {
        Self::from_env()
    }
}

impl Transport for DaemonTransport {
    fn list_readers(&self) -> Result<Vec<ReaderInfo>> {
        let readers = self.client.list_readers().map_err(map_ipc_error)?;
        Ok(readers.into_iter().map(ReaderInfo::new).collect())
    }

    fn connect(&self, reader: &str) -> Result<Box<dyn CardSession>> {
        let connection = self
            .client
            .connect(reader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1)
            .map_err(map_ipc_error)?;
        let atr = if connection.atr.is_empty() {
            None
        } else {
            Some(connection.atr)
        };

        Ok(Box::new(DaemonSession {
            reader_name: reader.to_owned(),
            client: self.client.clone(),
            handle: connection.handle,
            atr,
        }))
    }
}

struct DaemonSession {
    reader_name: String,
    client: Client,
    handle: u64,
    atr: Option<Vec<u8>>,
}

impl CardSession for DaemonSession {
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
        let data = self
            .client
            .transmit(self.handle, &encoded)
            .map_err(map_ipc_error)?;
        ResponseApdu::from_bytes(&data).map_err(map_apdu_error)
    }
}

impl Drop for DaemonSession {
    fn drop(&mut self) {
        let _ = self.client.disconnect(self.handle);
    }
}

struct CcidSession {
    reader_name: String,
    reader: Reader,
    atr: Option<Vec<u8>>,
}

impl CardSession for CcidSession {
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
        let response = self.reader.transmit_apdu(&encoded).map_err(map_usb_error)?;
        ResponseApdu::from_bytes(&response.data).map_err(map_apdu_error)
    }
}

fn map_usb_error(error: usb::Error) -> SmartcardError {
    SmartcardError::transport(error.to_string())
}

fn map_ipc_error(error: ipc::Error) -> SmartcardError {
    SmartcardError::transport(error.to_string())
}

fn map_apdu_error(error: ApduError) -> SmartcardError {
    SmartcardError::protocol(error.to_string())
}
