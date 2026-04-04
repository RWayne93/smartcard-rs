use std::error::Error;
use std::fmt;
use std::fmt::Write;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandApdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
    pub le: Option<u8>,
}

impl CommandApdu {
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8, data: impl Into<Vec<u8>>, le: Option<u8>) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data: data.into(),
            le,
        }
    }

    pub fn from_hex(input: &str) -> Result<Self, ApduError> {
        let bytes = hex_to_bytes(input)?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ApduError> {
        if bytes.len() < 4 {
            return Err(ApduError::CommandTooShort(bytes.len()));
        }

        let mut command = Self::new(bytes[0], bytes[1], bytes[2], bytes[3], Vec::new(), None);
        if bytes.len() == 4 {
            return Ok(command);
        }

        if bytes[4] == 0 && bytes.len() > 5 {
            return Err(ApduError::ExtendedLengthNotSupported);
        }

        if bytes.len() == 5 {
            command.le = Some(bytes[4]);
            return Ok(command);
        }

        let lc = bytes[4] as usize;
        let data_end = 5 + lc;
        if bytes.len() == data_end {
            command.data = bytes[5..data_end].to_vec();
            return Ok(command);
        }

        if bytes.len() == data_end + 1 {
            command.data = bytes[5..data_end].to_vec();
            command.le = Some(bytes[data_end]);
            return Ok(command);
        }

        Err(ApduError::InvalidCommandLength {
            expected: data_end,
            actual: bytes.len(),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, ApduError> {
        if self.data.len() > u8::MAX as usize {
            return Err(ApduError::ExtendedLengthNotSupported);
        }

        let mut encoded = vec![self.cla, self.ins, self.p1, self.p2];
        match (self.data.is_empty(), self.le) {
            (true, None) => {}
            (true, Some(le)) => encoded.push(le),
            (false, None) => {
                encoded.push(self.data.len() as u8);
                encoded.extend_from_slice(&self.data);
            }
            (false, Some(le)) => {
                encoded.push(self.data.len() as u8);
                encoded.extend_from_slice(&self.data);
                encoded.push(le);
            }
        }

        Ok(encoded)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseApdu {
    pub data: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

impl ResponseApdu {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ApduError> {
        if bytes.len() < 2 {
            return Err(ApduError::ResponseTooShort(bytes.len()));
        }

        let split_at = bytes.len() - 2;
        Ok(Self {
            data: bytes[..split_at].to_vec(),
            sw1: bytes[split_at],
            sw2: bytes[split_at + 1],
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.data.clone();
        bytes.push(self.sw1);
        bytes.push(self.sw2);
        bytes
    }

    pub fn status_word(&self) -> u16 {
        ((self.sw1 as u16) << 8) | self.sw2 as u16
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApduError {
    InvalidHexLength,
    InvalidHexCharacter { index: usize, value: char },
    CommandTooShort(usize),
    ResponseTooShort(usize),
    InvalidCommandLength { expected: usize, actual: usize },
    ExtendedLengthNotSupported,
}

impl fmt::Display for ApduError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHexLength => write!(f, "hex string must contain an even number of digits"),
            Self::InvalidHexCharacter { index, value } => {
                write!(f, "invalid hex character '{value}' at offset {index}")
            }
            Self::CommandTooShort(length) => {
                write!(f, "command APDU must be at least 4 bytes, got {length}")
            }
            Self::ResponseTooShort(length) => {
                write!(f, "response APDU must be at least 2 bytes, got {length}")
            }
            Self::InvalidCommandLength { expected, actual } => {
                write!(
                    f,
                    "command APDU body length mismatch: expected {expected} bytes, got {actual}"
                )
            }
            Self::ExtendedLengthNotSupported => {
                write!(f, "extended-length APDUs are not supported yet")
            }
        }
    }
}

impl Error for ApduError {}

pub fn hex_to_bytes(input: &str) -> Result<Vec<u8>, ApduError> {
    let filtered: Vec<char> = input
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && *ch != ':' && *ch != '_')
        .collect();

    if filtered.len() % 2 != 0 {
        return Err(ApduError::InvalidHexLength);
    }

    let mut bytes = Vec::with_capacity(filtered.len() / 2);
    for (pair_index, pair) in filtered.chunks(2).enumerate() {
        let offset = pair_index * 2;
        let high = pair[0].to_digit(16).ok_or(ApduError::InvalidHexCharacter {
            index: offset,
            value: pair[0],
        })?;
        let low = pair[1].to_digit(16).ok_or(ApduError::InvalidHexCharacter {
            index: offset + 1,
            value: pair[1],
        })?;
        bytes.push(((high << 4) | low) as u8);
    }

    Ok(bytes)
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut hex, "{byte:02X}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::{CommandApdu, ResponseApdu, bytes_to_hex, hex_to_bytes};

    #[test]
    fn hex_round_trip_is_uppercase() {
        let input = "00 a4 04 00 09 a0 00 00 03 08 00 00 10 00";
        let bytes = hex_to_bytes(input).expect("hex parsing should succeed");
        assert_eq!(bytes_to_hex(&bytes), "00A4040009A00000030800001000");
    }

    #[test]
    fn command_apdu_round_trip() {
        let command = CommandApdu::from_hex("00A4040009A00000030800001000")
            .expect("select APDU should parse");
        let encoded = command.encode().expect("command encoding should succeed");
        assert_eq!(
            encoded,
            hex_to_bytes("00A4040009A00000030800001000").unwrap()
        );
    }

    #[test]
    fn response_status_word_is_exposed() {
        let response = ResponseApdu::from_bytes(&hex_to_bytes("9000").unwrap())
            .expect("response parsing should succeed");
        assert_eq!(response.status_word(), 0x9000);
    }
}
