use std::error::Error;
use std::fmt;

use smartcard_apdu::bytes_to_hex;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tlv {
    pub tag: Vec<u8>,
    pub value: Vec<u8>,
}

impl Tlv {
    pub fn children(&self) -> Result<Vec<Self>, TlvError> {
        if !self.is_constructed() {
            return Err(TlvError::ExpectedConstructedTag(self.tag_as_hex()));
        }

        parse_tlv_all(&self.value)
    }

    pub fn is_constructed(&self) -> bool {
        self.tag.first().is_some_and(|byte| byte & 0x20 == 0x20)
    }

    pub fn tag_as_hex(&self) -> String {
        bytes_to_hex(&self.tag)
    }

    pub fn tag_eq(&self, expected: &[u8]) -> bool {
        self.tag == expected
    }
}

pub fn parse_tlv_all(input: &[u8]) -> Result<Vec<Tlv>, TlvError> {
    let mut tlvs = Vec::new();
    let mut offset = 0usize;

    while offset < input.len() {
        let (tlv, consumed) = parse_one(&input[offset..], offset)?;
        tlvs.push(tlv);
        offset += consumed;
    }

    Ok(tlvs)
}

fn parse_one(input: &[u8], absolute_offset: usize) -> Result<(Tlv, usize), TlvError> {
    let tag_len = parse_tag_length(input, absolute_offset)?;
    let tag = input[..tag_len].to_vec();
    let (value_len, length_len) = parse_length(&input[tag_len..], absolute_offset + tag_len)?;
    let value_offset = tag_len + length_len;
    let value_end = value_offset + value_len;

    if input.len() < value_end {
        return Err(TlvError::UnexpectedEof {
            offset: absolute_offset + input.len(),
        });
    }

    Ok((
        Tlv {
            tag,
            value: input[value_offset..value_end].to_vec(),
        },
        value_end,
    ))
}

fn parse_tag_length(input: &[u8], absolute_offset: usize) -> Result<usize, TlvError> {
    let first = *input.first().ok_or(TlvError::UnexpectedEof {
        offset: absolute_offset,
    })?;

    if first & 0x1F != 0x1F {
        return Ok(1);
    }

    let mut length = 1usize;
    loop {
        let byte = *input.get(length).ok_or(TlvError::UnexpectedEof {
            offset: absolute_offset + length,
        })?;
        length += 1;
        if byte & 0x80 == 0 {
            return Ok(length);
        }
    }
}

fn parse_length(input: &[u8], absolute_offset: usize) -> Result<(usize, usize), TlvError> {
    let first = *input.first().ok_or(TlvError::UnexpectedEof {
        offset: absolute_offset,
    })?;

    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }

    let width = (first & 0x7F) as usize;
    if width == 0 {
        return Err(TlvError::IndefiniteLengthUnsupported {
            offset: absolute_offset,
        });
    }

    if width > std::mem::size_of::<usize>() {
        return Err(TlvError::LengthTooWide {
            offset: absolute_offset,
            width,
        });
    }

    if input.len() < 1 + width {
        return Err(TlvError::UnexpectedEof {
            offset: absolute_offset + input.len(),
        });
    }

    let mut value_len = 0usize;
    for byte in &input[1..=width] {
        value_len = (value_len << 8) | (*byte as usize);
    }

    Ok((value_len, 1 + width))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlvError {
    UnexpectedEof { offset: usize },
    IndefiniteLengthUnsupported { offset: usize },
    LengthTooWide { offset: usize, width: usize },
    ExpectedConstructedTag(String),
}

impl fmt::Display for TlvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof { offset } => {
                write!(f, "unexpected end of TLV at offset {offset}")
            }
            Self::IndefiniteLengthUnsupported { offset } => {
                write!(
                    f,
                    "indefinite-length TLV is not supported at offset {offset}"
                )
            }
            Self::LengthTooWide { offset, width } => {
                write!(
                    f,
                    "TLV length field is too wide ({width} bytes) at offset {offset}"
                )
            }
            Self::ExpectedConstructedTag(tag) => {
                write!(f, "tag {tag} is not constructed")
            }
        }
    }
}

impl Error for TlvError {}
