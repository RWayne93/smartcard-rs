mod tlv;

use std::error::Error;
use std::fmt;

use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
use sha2::{Digest, Sha256};
use smartcard_apdu::{CommandApdu, ResponseApdu, bytes_to_hex};
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

pub use tlv::{Tlv, TlvError, parse_tlv_all};

pub const PIV_AID: [u8; 11] = [
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectResponse {
    pub aid: Vec<u8>,
    pub label: Option<String>,
    pub coexistent_aids: Vec<Vec<u8>>,
    pub records: Vec<Tlv>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertificateSlot {
    pub key_reference: u8,
    pub object_id: [u8; 3],
    pub short_name: &'static str,
    pub label: &'static str,
}

impl CertificateSlot {
    pub fn key_reference_hex(&self) -> String {
        format!("{:02X}", self.key_reference)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateObject {
    pub slot: CertificateSlot,
    pub der: Vec<u8>,
    pub is_compressed: bool,
    pub mscuid: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateSummary {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub sha256_fingerprint: String,
    pub not_before: String,
    pub not_after: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyPinStatus {
    Verified,
    Incorrect { tries_remaining: u8 },
    Blocked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignAlgorithm {
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EccP256,
    EccP384,
}

impl SignAlgorithm {
    pub fn algorithm_reference(self) -> u8 {
        match self {
            Self::Rsa1024 => 0x06,
            Self::Rsa2048 => 0x07,
            Self::Rsa3072 => 0x05,
            Self::Rsa4096 => 0x16,
            Self::EccP256 => 0x11,
            Self::EccP384 => 0x14,
        }
    }

    pub fn key_size_bytes(self) -> usize {
        match self {
            Self::Rsa1024 => 128,
            Self::Rsa2048 => 256,
            Self::Rsa3072 => 384,
            Self::Rsa4096 => 512,
            Self::EccP256 => 32,
            Self::EccP384 => 48,
        }
    }
}

pub const PRIMARY_CERTIFICATE_SLOTS: [CertificateSlot; 4] = [
    CertificateSlot {
        key_reference: 0x9A,
        object_id: [0x5F, 0xC1, 0x05],
        short_name: "piv-auth",
        label: "PIV Authentication",
    },
    CertificateSlot {
        key_reference: 0x9C,
        object_id: [0x5F, 0xC1, 0x0A],
        short_name: "signing",
        label: "Digital Signature",
    },
    CertificateSlot {
        key_reference: 0x9D,
        object_id: [0x5F, 0xC1, 0x0B],
        short_name: "key-mgmt",
        label: "Key Management",
    },
    CertificateSlot {
        key_reference: 0x9E,
        object_id: [0x5F, 0xC1, 0x01],
        short_name: "card-auth",
        label: "Card Authentication",
    },
];

pub fn select_piv_application() -> CommandApdu {
    CommandApdu::new(0x00, 0xA4, 0x04, 0x00, PIV_AID, Some(0x00))
}

pub fn get_data_command(tag: &[u8]) -> CommandApdu {
    let mut data = Vec::with_capacity(tag.len() + 2);
    data.push(0x5C);
    data.push(tag.len() as u8);
    data.extend_from_slice(tag);
    CommandApdu::new(0x00, 0xCB, 0x3F, 0xFF, data, Some(0x00))
}

pub const CHUID_OBJECT_ID: [u8; 3] = [0x5F, 0xC1, 0x02];

pub fn read_certificate_command(slot: CertificateSlot) -> CommandApdu {
    get_data_command(&slot.object_id)
}

pub fn read_chuid_command() -> CommandApdu {
    get_data_command(&CHUID_OBJECT_ID)
}

/// Card serial from the CHUID, using the same choice as OpenSC: the 25-byte
/// FASC-N, or the 16-byte GUID when the FASC-N agency code is 9999.
pub fn parse_chuid_serial(response: &ResponseApdu) -> Result<Option<Vec<u8>>, PivError> {
    match response.status_word() {
        0x9000 => {}
        0x6A82 => return Ok(None),
        status => {
            return Err(PivError::UnexpectedStatusWord {
                operation: "GET DATA CHUID",
                status,
            });
        }
    }

    let outer = parse_tlv_all(&response.data).map_err(PivError::MalformedTlv)?;
    let Some(container) = outer.iter().find(|tlv| tlv.tag_eq(&[0x53])) else {
        return Ok(None);
    };
    let records = parse_tlv_all(&container.value).map_err(PivError::MalformedTlv)?;
    let fascn = records
        .iter()
        .find(|record| record.tag_eq(&[0x30]) && record.value.len() == 25)
        .map(|record| record.value.as_slice());
    let guid = records
        .iter()
        .find(|record| record.tag_eq(&[0x34]) && record.value.len() == 16)
        .map(|record| record.value.as_slice());
    let guid_present = guid.is_some_and(|guid| guid.iter().any(|byte| *byte != 0));

    if let Some(fascn) = fascn
        && !(guid_present && fascn_agency_code_is_9999(fascn))
    {
        return Ok(Some(fascn.to_vec()));
    }
    if let Some(guid) = guid.filter(|_| guid_present) {
        return Ok(Some(guid.to_vec()));
    }
    Ok(None)
}

fn fascn_agency_code_is_9999(fascn: &[u8]) -> bool {
    fascn.len() == 25
        && fascn[0] == 0xD4
        && fascn[1] == 0xE7
        && fascn[2] == 0x39
        && (fascn[3] | 0x7F) == 0xFF
}

pub fn parse_select_response(data: &[u8]) -> Result<SelectResponse, PivError> {
    let templates = parse_tlv_all(data).map_err(PivError::MalformedTlv)?;
    if templates.len() != 1 {
        return Err(PivError::InvalidSelectResponse(
            "expected a single application property template".to_owned(),
        ));
    }

    let template = &templates[0];
    if !template.tag_eq(&[0x61]) {
        return Err(PivError::InvalidSelectResponse(format!(
            "expected top-level tag 61, got {}",
            template.tag_as_hex()
        )));
    }

    let records = template.children().map_err(PivError::MalformedTlv)?;
    let aid = records
        .iter()
        .find(|record| record.tag_eq(&[0x4F]))
        .map(|record| record.value.clone())
        .ok_or_else(|| PivError::MissingDataObject("4F"))?;

    let label = records
        .iter()
        .find(|record| record.tag_eq(&[0x50]))
        .map(|record| {
            String::from_utf8(record.value.clone())
                .map_err(|_| PivError::InvalidDataObject("50", "label is not valid UTF-8"))
        })
        .transpose()?;

    let mut coexistent_aids = Vec::new();
    for record in &records {
        if !record.tag_eq(&[0x79]) {
            continue;
        }

        for nested in record.children().map_err(PivError::MalformedTlv)? {
            if nested.tag_eq(&[0x4F]) {
                coexistent_aids.push(nested.value);
            }
        }
    }

    Ok(SelectResponse {
        aid,
        label,
        coexistent_aids,
        records,
    })
}

pub fn parse_certificate_response(
    slot: CertificateSlot,
    response: &ResponseApdu,
) -> Result<Option<CertificateObject>, PivError> {
    match response.status_word() {
        0x9000 => {}
        0x6A82 => return Ok(None),
        status => {
            return Err(PivError::UnexpectedStatusWord {
                operation: "GET DATA",
                status,
            });
        }
    }

    let outer = parse_tlv_all(&response.data).map_err(PivError::MalformedTlv)?;
    if outer.len() != 1 || !outer[0].tag_eq(&[0x53]) {
        return Err(PivError::InvalidCertificateObject(format!(
            "expected outer certificate container tag 53, got {}",
            outer
                .first()
                .map(|tlv| tlv.tag_as_hex())
                .unwrap_or_else(|| "none".to_owned())
        )));
    }

    let records = parse_tlv_all(&outer[0].value).map_err(PivError::MalformedTlv)?;
    let der = records
        .iter()
        .find(|record| record.tag_eq(&[0x70]))
        .map(|record| record.value.clone())
        .ok_or_else(|| PivError::MissingDataObject("70"))?;

    let cert_info = records
        .iter()
        .find(|record| record.tag_eq(&[0x71]))
        .ok_or_else(|| PivError::MissingDataObject("71"))?;
    if cert_info.value.len() != 1 {
        return Err(PivError::InvalidDataObject(
            "71",
            "certificate info must be exactly one byte",
        ));
    }

    let is_compressed = match cert_info.value[0] {
        0x00 => false,
        0x01 => true,
        _ => {
            return Err(PivError::InvalidDataObject(
                "71",
                "certificate compression flag must be 0x00 or 0x01",
            ));
        }
    };

    let mscuid = records
        .iter()
        .find(|record| record.tag_eq(&[0x72]))
        .map(|record| record.value.clone());

    Ok(Some(CertificateObject {
        slot,
        der,
        is_compressed,
        mscuid,
    }))
}

pub fn summarize_certificate(
    certificate: &CertificateObject,
) -> Result<CertificateSummary, PivError> {
    let (_, parsed) = X509Certificate::from_der(&certificate.der)
        .map_err(|error| PivError::InvalidCertificateDer(error.to_string()))?;

    let fingerprint = Sha256::digest(&certificate.der);

    Ok(CertificateSummary {
        subject: parsed.subject().to_string(),
        issuer: parsed.issuer().to_string(),
        serial_number: parsed.tbs_certificate.raw_serial_as_string().to_uppercase(),
        sha256_fingerprint: bytes_to_hex(fingerprint.as_ref()),
        not_before: parsed.validity().not_before.to_string(),
        not_after: parsed.validity().not_after.to_string(),
    })
}

pub fn infer_sign_algorithm(certificate: &CertificateObject) -> Result<SignAlgorithm, PivError> {
    let (_, parsed) = X509Certificate::from_der(&certificate.der)
        .map_err(|error| PivError::InvalidCertificateDer(error.to_string()))?;

    let public_key = parsed
        .public_key()
        .parsed()
        .map_err(|error| PivError::UnsupportedSigningAlgorithm(error.to_string()))?;

    match public_key {
        PublicKey::RSA(rsa) => match rsa.key_size() {
            1024 => Ok(SignAlgorithm::Rsa1024),
            2048 => Ok(SignAlgorithm::Rsa2048),
            3072 => Ok(SignAlgorithm::Rsa3072),
            4096 => Ok(SignAlgorithm::Rsa4096),
            bits => Err(PivError::UnsupportedSigningAlgorithm(format!(
                "unsupported RSA key size {bits}"
            ))),
        },
        PublicKey::EC(ec) => match ec.key_size() {
            256 => Ok(SignAlgorithm::EccP256),
            384 => Ok(SignAlgorithm::EccP384),
            bits => Err(PivError::UnsupportedSigningAlgorithm(format!(
                "unsupported EC key size {bits}"
            ))),
        },
        other => Err(PivError::UnsupportedSigningAlgorithm(format!(
            "unsupported public key type {other:?}"
        ))),
    }
}

pub fn prepare_signing_input_sha256(
    algorithm: SignAlgorithm,
    digest: &[u8],
) -> Result<Vec<u8>, PivError> {
    if digest.len() != 32 {
        return Err(PivError::InvalidDigestLength {
            algorithm: "sha256",
            expected: 32,
            actual: digest.len(),
        });
    }

    match algorithm {
        SignAlgorithm::Rsa1024
        | SignAlgorithm::Rsa2048
        | SignAlgorithm::Rsa3072
        | SignAlgorithm::Rsa4096 => {
            build_rsa_pkcs1_v1_5_sha256_block(algorithm.key_size_bytes(), digest)
        }
        SignAlgorithm::EccP256 | SignAlgorithm::EccP384 => {
            if digest.len() > algorithm.key_size_bytes() {
                return Err(PivError::InvalidDigestLength {
                    algorithm: "sha256",
                    expected: algorithm.key_size_bytes(),
                    actual: digest.len(),
                });
            }
            Ok(digest.to_vec())
        }
    }
}

pub fn build_sign_commands(
    slot: CertificateSlot,
    algorithm: SignAlgorithm,
    signing_input: &[u8],
) -> Result<Vec<CommandApdu>, PivError> {
    let data = build_general_authenticate_data(signing_input)?;
    let chunks: Vec<&[u8]> = data.chunks(u8::MAX as usize).collect();
    let mut commands = Vec::with_capacity(chunks.len());

    for (index, chunk) in chunks.iter().enumerate() {
        let is_last = index + 1 == chunks.len();
        commands.push(CommandApdu::new(
            if is_last { 0x00 } else { 0x10 },
            0x87,
            algorithm.algorithm_reference(),
            slot.key_reference,
            chunk.to_vec(),
            if is_last { Some(0x00) } else { None },
        ));
    }

    Ok(commands)
}

pub fn parse_sign_response(response: &ResponseApdu) -> Result<Vec<u8>, PivError> {
    match response.status_word() {
        0x9000 => {}
        0x6982 => {
            return Err(PivError::SecurityStatusNotSatisfied(
                "PIN not verified or touch/policy requirement not satisfied".to_owned(),
            ));
        }
        status => {
            return Err(PivError::UnexpectedStatusWord {
                operation: "GENERAL AUTHENTICATE",
                status,
            });
        }
    }

    let outer = parse_tlv_all(&response.data).map_err(PivError::MalformedTlv)?;
    if outer.len() != 1 || !outer[0].tag_eq(&[0x7C]) {
        return Err(PivError::InvalidSignatureResponse(format!(
            "expected outer signature template tag 7C, got {}",
            outer
                .first()
                .map(|tlv| tlv.tag_as_hex())
                .unwrap_or_else(|| "none".to_owned())
        )));
    }

    let records = parse_tlv_all(&outer[0].value).map_err(PivError::MalformedTlv)?;
    let signature = records
        .iter()
        .find(|record| record.tag_eq(&[0x82]))
        .map(|record| record.value.clone())
        .ok_or_else(|| PivError::MissingDataObject("82"))?;

    Ok(signature)
}

pub fn verify_signature_sha256(
    certificate: &CertificateObject,
    digest: &[u8],
    signature: &[u8],
) -> Result<(), PivError> {
    if digest.len() != 32 {
        return Err(PivError::InvalidDigestLength {
            algorithm: "sha256",
            expected: 32,
            actual: digest.len(),
        });
    }

    let (_, parsed) = X509Certificate::from_der(&certificate.der)
        .map_err(|error| PivError::InvalidCertificateDer(error.to_string()))?;

    let public_key = parsed
        .public_key()
        .parsed()
        .map_err(|error| PivError::UnsupportedSigningAlgorithm(error.to_string()))?;

    match public_key {
        PublicKey::RSA(rsa) => {
            let modulus = BigUint::from_bytes_be(rsa.modulus);
            let exponent = BigUint::from_bytes_be(rsa.exponent);
            let public_key = RsaPublicKey::new(modulus, exponent)
                .map_err(|error| PivError::UnsupportedSigningAlgorithm(error.to_string()))?;

            public_key
                .verify(Pkcs1v15Sign::new::<Sha256>(), digest, signature)
                .map_err(|error| PivError::SignatureVerificationFailed(error.to_string()))
        }
        PublicKey::EC(_) => Err(PivError::UnsupportedSigningAlgorithm(
            "ECDSA verification is not implemented yet".to_owned(),
        )),
        other => Err(PivError::UnsupportedSigningAlgorithm(format!(
            "unsupported public key type {other:?}"
        ))),
    }
}

pub const PIV_PIN_MIN_LENGTH: usize = 6;
pub const PIV_PIN_MAX_LENGTH: usize = 8;

pub fn verify_pin_command(pin: &str) -> Result<CommandApdu, PivError> {
    if !(PIV_PIN_MIN_LENGTH..=PIV_PIN_MAX_LENGTH).contains(&pin.len()) {
        return Err(PivError::PinLengthOutOfRange {
            length: pin.len(),
            min: PIV_PIN_MIN_LENGTH,
            max: PIV_PIN_MAX_LENGTH,
        });
    }

    if !pin.is_ascii() {
        return Err(PivError::NonAsciiPin);
    }

    let mut data = vec![0xFF; 8];
    for (index, byte) in pin.as_bytes().iter().enumerate() {
        data[index] = *byte;
    }

    Ok(CommandApdu::new(0x00, 0x20, 0x00, 0x80, data, None))
}

pub fn parse_verify_pin_response(response: &ResponseApdu) -> Result<VerifyPinStatus, PivError> {
    match response.status_word() {
        0x9000 => Ok(VerifyPinStatus::Verified),
        0x6983 => Ok(VerifyPinStatus::Blocked),
        _ if response.sw1 == 0x63 && (response.sw2 & 0xF0) == 0xC0 => {
            Ok(VerifyPinStatus::Incorrect {
                tries_remaining: response.sw2 & 0x0F,
            })
        }
        status => Err(PivError::UnexpectedStatusWord {
            operation: "VERIFY PIN",
            status,
        }),
    }
}

fn build_general_authenticate_data(signing_input: &[u8]) -> Result<Vec<u8>, PivError> {
    let mut data = Vec::new();
    let input_len = encode_ber_length(signing_input.len())?;
    let outer_len = encode_ber_length(2 + 1 + input_len.len() + signing_input.len())?;

    data.push(0x7C);
    data.extend_from_slice(&outer_len);
    data.push(0x82);
    data.push(0x00);
    data.push(0x81);
    data.extend_from_slice(&input_len);
    data.extend_from_slice(signing_input);

    Ok(data)
}

fn build_rsa_pkcs1_v1_5_sha256_block(
    modulus_len: usize,
    digest: &[u8],
) -> Result<Vec<u8>, PivError> {
    const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    let digest_info_len = SHA256_DIGEST_INFO_PREFIX.len() + digest.len();
    let min_block_len = 3 + 8 + digest_info_len;
    if modulus_len < min_block_len {
        return Err(PivError::UnsupportedSigningAlgorithm(format!(
            "RSA modulus length {modulus_len} is too small for SHA-256 PKCS#1 v1.5"
        )));
    }

    let padding_len = modulus_len - 3 - digest_info_len;
    let mut block = Vec::with_capacity(modulus_len);
    block.push(0x00);
    block.push(0x01);
    block.extend(std::iter::repeat_n(0xFF, padding_len));
    block.push(0x00);
    block.extend_from_slice(&SHA256_DIGEST_INFO_PREFIX);
    block.extend_from_slice(digest);

    Ok(block)
}

fn encode_ber_length(length: usize) -> Result<Vec<u8>, PivError> {
    if length < 0x80 {
        return Ok(vec![length as u8]);
    }

    let mut encoded = Vec::new();
    let mut value = length;
    while value > 0 {
        encoded.push((value & 0xFF) as u8);
        value >>= 8;
    }
    encoded.reverse();

    if encoded.len() > 3 {
        return Err(PivError::InvalidDataObject(
            "length",
            "BER length wider than 3 bytes is not supported",
        ));
    }

    let mut result = Vec::with_capacity(encoded.len() + 1);
    result.push(0x80 | encoded.len() as u8);
    result.extend_from_slice(&encoded);
    Ok(result)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PivError {
    PinLengthOutOfRange {
        length: usize,
        min: usize,
        max: usize,
    },
    NonAsciiPin,
    MissingDataObject(&'static str),
    InvalidDataObject(&'static str, &'static str),
    InvalidSelectResponse(String),
    InvalidCertificateObject(String),
    InvalidCertificateDer(String),
    InvalidSignatureResponse(String),
    InvalidDigestLength {
        algorithm: &'static str,
        expected: usize,
        actual: usize,
    },
    SignatureVerificationFailed(String),
    SecurityStatusNotSatisfied(String),
    UnsupportedSigningAlgorithm(String),
    UnexpectedStatusWord {
        operation: &'static str,
        status: u16,
    },
    MalformedTlv(TlvError),
}

impl fmt::Display for PivError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PinLengthOutOfRange { length, min, max } => {
                write!(f, "PIN length must be {min} to {max} bytes, got {length}")
            }
            Self::NonAsciiPin => write!(f, "PIN must be ASCII"),
            Self::MissingDataObject(tag) => write!(f, "missing required data object {tag}"),
            Self::InvalidDataObject(tag, reason) => {
                write!(f, "invalid data object {tag}: {reason}")
            }
            Self::InvalidSelectResponse(reason) => write!(f, "invalid SELECT response: {reason}"),
            Self::InvalidCertificateObject(reason) => {
                write!(f, "invalid certificate object: {reason}")
            }
            Self::InvalidCertificateDer(reason) => {
                write!(f, "invalid certificate DER: {reason}")
            }
            Self::InvalidSignatureResponse(reason) => {
                write!(f, "invalid signature response: {reason}")
            }
            Self::InvalidDigestLength {
                algorithm,
                expected,
                actual,
            } => write!(
                f,
                "{algorithm} digest length mismatch: expected {expected} bytes, got {actual}"
            ),
            Self::SignatureVerificationFailed(reason) => {
                write!(f, "signature verification failed: {reason}")
            }
            Self::SecurityStatusNotSatisfied(reason) => {
                write!(f, "security status not satisfied: {reason}")
            }
            Self::UnsupportedSigningAlgorithm(reason) => {
                write!(f, "unsupported signing algorithm: {reason}")
            }
            Self::UnexpectedStatusWord { operation, status } => {
                write!(f, "{operation} failed with status {:04X}", status)
            }
            Self::MalformedTlv(error) => write!(f, "malformed TLV: {error}"),
        }
    }
}

impl Error for PivError {}

#[cfg(test)]
mod tests {
    use smartcard_apdu::{ResponseApdu, hex_to_bytes};

    use super::{
        PIV_AID, PRIMARY_CERTIFICATE_SLOTS, PivError, SignAlgorithm, VerifyPinStatus,
        build_sign_commands, parse_certificate_response, parse_chuid_serial, parse_select_response,
        parse_sign_response, parse_tlv_all, parse_verify_pin_response,
        prepare_signing_input_sha256, read_certificate_command, read_chuid_command,
        verify_pin_command, verify_signature_sha256,
    };

    #[test]
    fn piv_aid_has_expected_length() {
        assert_eq!(PIV_AID.len(), 11);
    }

    #[test]
    fn pin_shorter_than_six_bytes_is_rejected() {
        let error = verify_pin_command("12345").expect_err("short PIN should be rejected");
        assert!(matches!(
            error,
            PivError::PinLengthOutOfRange {
                length: 5,
                min: 6,
                max: 8
            }
        ));
    }

    #[test]
    fn pin_is_padded_with_ff() {
        let command = verify_pin_command("123456").expect("PIN should build");
        assert_eq!(
            command.data,
            vec![b'1', b'2', b'3', b'4', b'5', b'6', 0xFF, 0xFF]
        );
    }

    #[test]
    fn tlv_parser_supports_nested_records() {
        let tlvs = parse_tlv_all(&hex_to_bytes("61064F02AABB5000").unwrap())
            .expect("TLV parsing should succeed");
        assert_eq!(tlvs.len(), 1);
        assert!(tlvs[0].tag_eq(&[0x61]));

        let children = tlvs[0].children().expect("constructed tag should parse");
        assert_eq!(children.len(), 2);
        assert!(children[0].tag_eq(&[0x4F]));
        assert_eq!(children[0].value, vec![0xAA, 0xBB]);
        assert!(children[1].tag_eq(&[0x50]));
        assert!(children[1].value.is_empty());
    }

    #[test]
    fn select_response_is_parsed_from_real_card_output() {
        let response = hex_to_bytes(
            "61374F0BA00000030800001000010079074F05A000000308501F48494420476C6F62616C2041637469764944204170706C657420322E372E34",
        )
        .expect("sample response should parse as hex");

        let select = parse_select_response(&response).expect("SELECT response should parse");

        assert_eq!(select.aid, PIV_AID);
        assert_eq!(
            select.label.as_deref(),
            Some("HID Global ActivID Applet 2.7.4")
        );
        assert_eq!(
            select.coexistent_aids,
            vec![vec![0xA0, 0x00, 0x00, 0x03, 0x08]]
        );
    }

    #[test]
    fn read_certificate_command_uses_get_data() {
        let command = read_certificate_command(PRIMARY_CERTIFICATE_SLOTS[0]);
        let encoded = command.encode().expect("command should encode");
        assert_eq!(encoded, hex_to_bytes("00CB3FFF055C035FC10500").unwrap());
    }

    #[test]
    fn read_chuid_command_uses_the_chuid_object_id() {
        let encoded = read_chuid_command()
            .encode()
            .expect("command should encode");
        assert_eq!(encoded, hex_to_bytes("00CB3FFF055C035FC10200").unwrap());
    }

    #[test]
    fn chuid_with_agency_code_9999_uses_the_guid() {
        let mut fascn = vec![0x00; 25];
        fascn[..4].copy_from_slice(&[0xD4, 0xE7, 0x39, 0xFF]);
        let response = chuid_response(
            &fascn,
            &hex_to_bytes("c666f679dd714cea8a86a282201093fc").unwrap(),
        );

        let serial = parse_chuid_serial(&response)
            .expect("CHUID should parse")
            .expect("GUID should be present");
        assert_eq!(
            serial,
            hex_to_bytes("c666f679dd714cea8a86a282201093fc").unwrap()
        );
    }

    #[test]
    fn chuid_with_a_real_fascn_uses_the_fascn() {
        let mut fascn = vec![0x00; 25];
        fascn[24] = 0xAB;
        let response = chuid_response(
            &fascn,
            &hex_to_bytes("c666f679dd714cea8a86a282201093fc").unwrap(),
        );

        let serial = parse_chuid_serial(&response)
            .expect("CHUID should parse")
            .expect("FASC-N should be present");
        assert_eq!(serial, fascn);
    }

    #[test]
    fn missing_chuid_returns_none() {
        let response =
            ResponseApdu::from_bytes(&hex_to_bytes("6A82").unwrap()).expect("status should parse");
        let serial = parse_chuid_serial(&response).expect("missing CHUID is not fatal");
        assert!(serial.is_none());
    }

    fn chuid_response(fascn: &[u8], guid: &[u8]) -> ResponseApdu {
        let mut body = Vec::new();
        body.push(0x30);
        body.push(fascn.len() as u8);
        body.extend_from_slice(fascn);
        body.push(0x34);
        body.push(guid.len() as u8);
        body.extend_from_slice(guid);
        body.extend_from_slice(&[0xFE, 0x00]);

        let mut data = Vec::new();
        data.push(0x53);
        data.push(body.len() as u8);
        data.extend_from_slice(&body);
        data.extend_from_slice(&[0x90, 0x00]);
        ResponseApdu::from_bytes(&data).expect("response bytes should parse")
    }

    #[test]
    fn certificate_response_is_parsed() {
        let slot = PRIMARY_CERTIFICATE_SLOTS[0];
        let response = ResponseApdu::from_bytes(
            &hex_to_bytes("530E700430820100710100720101FE009000").unwrap(),
        )
        .expect("response bytes should parse");

        let certificate =
            parse_certificate_response(slot, &response).expect("certificate should parse");
        let certificate = certificate.expect("slot should be present");

        assert_eq!(certificate.slot, slot);
        assert_eq!(certificate.der, vec![0x30, 0x82, 0x01, 0x00]);
        assert!(!certificate.is_compressed);
        assert_eq!(certificate.mscuid, Some(vec![0x01]));
    }

    #[test]
    fn missing_certificate_slot_returns_none() {
        let slot = PRIMARY_CERTIFICATE_SLOTS[1];
        let response =
            ResponseApdu::from_bytes(&hex_to_bytes("6A82").unwrap()).expect("status should parse");

        let certificate =
            parse_certificate_response(slot, &response).expect("missing slot is not fatal");
        assert!(certificate.is_none());
    }

    #[test]
    fn verify_pin_response_reports_success() {
        let response =
            ResponseApdu::from_bytes(&hex_to_bytes("9000").unwrap()).expect("status should parse");

        let status = parse_verify_pin_response(&response).expect("status should parse");
        assert_eq!(status, VerifyPinStatus::Verified);
    }

    #[test]
    fn verify_pin_response_reports_retries_remaining() {
        let response =
            ResponseApdu::from_bytes(&hex_to_bytes("63C2").unwrap()).expect("status should parse");

        let status = parse_verify_pin_response(&response).expect("status should parse");
        assert_eq!(status, VerifyPinStatus::Incorrect { tries_remaining: 2 });
    }

    #[test]
    fn verify_pin_response_reports_blocked_state() {
        let response =
            ResponseApdu::from_bytes(&hex_to_bytes("6983").unwrap()).expect("status should parse");

        let status = parse_verify_pin_response(&response).expect("status should parse");
        assert_eq!(status, VerifyPinStatus::Blocked);
    }

    #[test]
    fn rsa_signing_input_is_pkcs1_padded() {
        let digest = vec![0xAB; 32];
        let input = prepare_signing_input_sha256(SignAlgorithm::Rsa2048, &digest)
            .expect("input should be prepared");

        assert_eq!(input.len(), 256);
        assert_eq!(&input[..2], &[0x00, 0x01]);
        assert_eq!(&input[input.len() - 32..], digest.as_slice());
    }

    #[test]
    fn rsa_2048_sign_command_is_split_into_two_apdus() {
        let digest = vec![0xAB; 32];
        let input = prepare_signing_input_sha256(SignAlgorithm::Rsa2048, &digest)
            .expect("input should be prepared");
        let commands =
            build_sign_commands(PRIMARY_CERTIFICATE_SLOTS[1], SignAlgorithm::Rsa2048, &input)
                .expect("sign commands should be built");

        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0].cla, 0x10);
        assert_eq!(commands[0].ins, 0x87);
        assert_eq!(commands[0].p1, 0x07);
        assert_eq!(commands[0].p2, 0x9C);
        assert_eq!(commands[0].data.len(), 255);
        assert_eq!(commands[0].le, None);
        assert_eq!(commands[1].cla, 0x00);
        assert_eq!(commands[1].le, Some(0x00));
    }

    #[test]
    fn sign_response_extracts_signature() {
        let response = ResponseApdu::from_bytes(&hex_to_bytes("7C0582030102039000").unwrap())
            .expect("response should parse");

        let signature = parse_sign_response(&response).expect("signature should parse");
        assert_eq!(signature, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn rsa_signature_verifies_against_certificate() {
        let certificate = super::CertificateObject {
            slot: PRIMARY_CERTIFICATE_SLOTS[1],
            der: hex_to_bytes("308202023082016BA00302010202145C5ABC72AC965906A865793E0C10EE5E563A86DE300D06092A864886F70D01010B050030133111300F06035504030C08746573742D706976301E170D3236303430343033323932375A170D3236303430353033323932375A30133111300F06035504030C08746573742D70697630819F300D06092A864886F70D010101050003818D0030818902818100D4DDD9D9D9A93CF9417A8FD5590BE4F2A1EA09234C4CAF46330D3A9F703C0FD8F83C95D35DD63707FDF949FCFE2BCF0FE457ACE975D5B4A8A687591FD5152B4D4E4676BC17C67DDD624209E6A786419833C8EBF6DF4C48892E928DF8674EF0B1538C72EE9B951C06F8D388D048F14729D4BA7EF8EF15DC8D33EA4C74DACFB1010203010001A3533051301D0603551D0E041604146AAAD17C5666B545B18DD72EFACDC24E36E66189301F0603551D230418301680146AAAD17C5666B545B18DD72EFACDC24E36E66189300F0603551D130101FF040530030101FF300D06092A864886F70D01010B0500038181008360210CF5FC6EA893D014165C10912D49262498A8837DB9705F317110CDAA2D364C0457FD845FA096A9595CB89B3516E76214E9185D3756B8D8EE00585DA10A949E36A7472AD961D96D9F4F1848188AA8811CB8938ABC275B47E5F6B70073AA624EC9EF15DE4E5E7D84351696C4AE888CF00D72281D13B4CA2B6770764C5D8A").unwrap(),
            is_compressed: false,
            mscuid: None,
        };
        let digest =
            hex_to_bytes("5891B5B522D5DF086D0FF0B110FBD9D21BB4FC7163AF34D08286A2E846F6BE03")
                .unwrap();
        let signature = hex_to_bytes("80A6E466D62F4414CE770CDC20D8F460D4432C0569176963CF73B042DF424EF3EFDB39DA52A44E5819B1B7312F0FF82C188AEA1E2C0D8A7F511F1F4182AA712FD2E8EA42888179A531808C2835B2DF6A8414965BD66B939FB6282DB54C437992756CE265B1C8129DB57CAD0A57BEE9685B9AAE19A97EF72E1D6792603DDA9B9F").unwrap();

        verify_signature_sha256(&certificate, &digest, &signature)
            .expect("signature should verify");
    }

    #[test]
    fn rsa_signature_verification_rejects_wrong_digest() {
        let certificate = super::CertificateObject {
            slot: PRIMARY_CERTIFICATE_SLOTS[1],
            der: hex_to_bytes("308202023082016BA00302010202145C5ABC72AC965906A865793E0C10EE5E563A86DE300D06092A864886F70D01010B050030133111300F06035504030C08746573742D706976301E170D3236303430343033323932375A170D3236303430353033323932375A30133111300F06035504030C08746573742D70697630819F300D06092A864886F70D010101050003818D0030818902818100D4DDD9D9D9A93CF9417A8FD5590BE4F2A1EA09234C4CAF46330D3A9F703C0FD8F83C95D35DD63707FDF949FCFE2BCF0FE457ACE975D5B4A8A687591FD5152B4D4E4676BC17C67DDD624209E6A786419833C8EBF6DF4C48892E928DF8674EF0B1538C72EE9B951C06F8D388D048F14729D4BA7EF8EF15DC8D33EA4C74DACFB1010203010001A3533051301D0603551D0E041604146AAAD17C5666B545B18DD72EFACDC24E36E66189301F0603551D230418301680146AAAD17C5666B545B18DD72EFACDC24E36E66189300F0603551D130101FF040530030101FF300D06092A864886F70D01010B0500038181008360210CF5FC6EA893D014165C10912D49262498A8837DB9705F317110CDAA2D364C0457FD845FA096A9595CB89B3516E76214E9185D3756B8D8EE00585DA10A949E36A7472AD961D96D9F4F1848188AA8811CB8938ABC275B47E5F6B70073AA624EC9EF15DE4E5E7D84351696C4AE888CF00D72281D13B4CA2B6770764C5D8A").unwrap(),
            is_compressed: false,
            mscuid: None,
        };
        let digest =
            hex_to_bytes("6891B5B522D5DF086D0FF0B110FBD9D21BB4FC7163AF34D08286A2E846F6BE03")
                .unwrap();
        let signature = hex_to_bytes("80A6E466D62F4414CE770CDC20D8F460D4432C0569176963CF73B042DF424EF3EFDB39DA52A44E5819B1B7312F0FF82C188AEA1E2C0D8A7F511F1F4182AA712FD2E8EA42888179A531808C2835B2DF6A8414965BD66B939FB6282DB54C437992756CE265B1C8129DB57CAD0A57BEE9685B9AAE19A97EF72E1D6792603DDA9B9F").unwrap();

        let error = verify_signature_sha256(&certificate, &digest, &signature)
            .expect_err("signature should not verify");
        assert!(matches!(
            error,
            super::PivError::SignatureVerificationFailed(_)
        ));
    }
}
