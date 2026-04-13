use std::collections::{BTreeSet, VecDeque};
use std::env;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::ptr;
use std::slice;
use std::sync::OnceLock;

use sha1::Sha1;
use sha2::{Digest, Sha256};
use smartcard_core::{SmartcardError, SmartcardRuntime};
use smartcard_piv::{CertificateSlot, PRIMARY_CERTIFICATE_SLOTS, PivError, SignAlgorithm};
use smartcard_worker::ReaderWorker;
use x509_parser::oid_registry::OID_X509_SERIALNUMBER;
use x509_parser::pem::Pem;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

use crate::abi::*;
use crate::provider::{
    CertificateAttributes, FindTemplateKey, FindTemplatePredicate, KeyType, Mechanism, ObjectClass,
    ObjectData, ObjectRecord, ObjectTemplate, ProviderError,
};

pub(crate) fn trace(message: impl AsRef<str>) {
    if trace_enabled() {
        eprintln!("[smartcard-pkcs11] {}", message.as_ref());
    }
}

pub(crate) fn trace_certs(message: impl AsRef<str>) {
    if trace_certs_enabled() {
        eprintln!("[smartcard-pkcs11][certs] {}", message.as_ref());
    }
}

fn trace_enabled() -> bool {
    static TRACE_ENABLED: OnceLock<bool> = OnceLock::new();
    *TRACE_ENABLED.get_or_init(|| {
        env::var("SMARTCARD_PKCS11_TRACE")
            .map(|value| value != "0")
            .unwrap_or(false)
    })
}

fn trace_certs_enabled() -> bool {
    static TRACE_CERTS_ENABLED: OnceLock<bool> = OnceLock::new();
    *TRACE_CERTS_ENABLED.get_or_init(|| {
        env::var("SMARTCARD_PKCS11_TRACE_CERTS")
            .map(|value| value != "0")
            .unwrap_or(false)
    })
}

pub(crate) fn token_serial(atr: &[u8], reader_name: &str) -> String {
    let mut serial = if atr.is_empty() {
        reader_name
            .bytes()
            .filter(|byte| byte.is_ascii_alphanumeric())
            .map(char::from)
            .collect::<String>()
    } else {
        hex_upper(atr)
    };
    if serial.is_empty() {
        serial = "SMARTCARDRS000001".to_owned();
    }
    serial.truncate(16);
    while serial.len() < 16 {
        serial.push(' ');
    }
    serial
}

pub(crate) struct TokenMetadata {
    pub(crate) label: String,
    pub(crate) manufacturer: String,
    pub(crate) model: String,
    pub(crate) serial_number: String,
}

pub(crate) fn derive_token_metadata(
    certificates: &[(CertificateSlot, Vec<u8>)],
    select_label: Option<&str>,
    atr: &[u8],
    reader_name: &str,
) -> TokenMetadata {
    let label = certificates
        .iter()
        .find(|(slot, _)| slot.key_reference == 0x9A)
        .and_then(|(_, der)| certificate_common_name(der))
        .or_else(|| {
            certificates
                .iter()
                .find_map(|(_, der)| certificate_common_name(der))
        })
        .or_else(|| {
            select_label
                .map(str::trim)
                .filter(|label| !label.is_empty())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "PIV Token".to_owned());

    let serial_number = certificates
        .iter()
        .find(|(slot, _)| slot.key_reference == 0x9E)
        .and_then(|(_, der)| certificate_subject_serial_number(der))
        .or_else(|| {
            certificates
                .iter()
                .find_map(|(_, der)| certificate_subject_serial_number(der))
        })
        .unwrap_or_else(|| token_serial(atr, reader_name));

    TokenMetadata {
        label,
        // OpenSC presents PIV tokens this way to NSS/modutil. Matching that
        // shape produces more accurate and interoperable token URIs than using
        // the module vendor name here.
        manufacturer: "piv_II".to_owned(),
        model: "PKCS#15 emulated".to_owned(),
        serial_number,
    }
}

fn certificate_common_name(der: &[u8]) -> Option<String> {
    let (_, parsed) = X509Certificate::from_der(der).ok()?;
    parsed
        .subject()
        .iter_common_name()
        .find_map(|name| name.as_str().ok())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

fn certificate_subject_serial_number(der: &[u8]) -> Option<String> {
    let (_, parsed) = X509Certificate::from_der(der).ok()?;
    let value = parsed
        .subject()
        .iter_by_oid(&OID_X509_SERIALNUMBER)
        .find_map(|attribute| attribute.as_str().ok())?;
    normalize_token_identifier(value)
}

fn normalize_token_identifier(value: &str) -> Option<String> {
    let mut normalized: String = value
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .collect();
    if normalized.is_empty() {
        normalized = value
            .chars()
            .filter(|character| character.is_ascii_alphanumeric())
            .collect();
    }
    if normalized.is_empty() {
        return None;
    }
    normalized.make_ascii_lowercase();
    normalized.truncate(16);
    Some(normalized)
}

fn hex_upper(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0F) as usize] as char);
    }
    output
}

fn attribute_type_name(type_: CkAttributeType) -> &'static str {
    match type_ {
        CKA_CLASS => "CKA_CLASS",
        CKA_TOKEN => "CKA_TOKEN",
        CKA_PRIVATE => "CKA_PRIVATE",
        CKA_LABEL => "CKA_LABEL",
        CKA_VALUE => "CKA_VALUE",
        CKA_CERTIFICATE_TYPE => "CKA_CERTIFICATE_TYPE",
        CKA_ISSUER => "CKA_ISSUER",
        CKA_SERIAL_NUMBER => "CKA_SERIAL_NUMBER",
        CKA_KEY_TYPE => "CKA_KEY_TYPE",
        CKA_SUBJECT => "CKA_SUBJECT",
        CKA_ID => "CKA_ID",
        CKA_ENCRYPT => "CKA_ENCRYPT",
        CKA_SIGN => "CKA_SIGN",
        CKA_VERIFY => "CKA_VERIFY",
        CKA_MODULUS => "CKA_MODULUS",
        CKA_MODULUS_BITS => "CKA_MODULUS_BITS",
        CKA_PUBLIC_EXPONENT => "CKA_PUBLIC_EXPONENT",
        CKA_ALWAYS_AUTHENTICATE => "CKA_ALWAYS_AUTHENTICATE",
        CKA_PROFILE_ID => "CKA_PROFILE_ID",
        CKA_TRUST_DIGITAL_SIGNATURE => "CKA_TRUST_DIGITAL_SIGNATURE",
        CKA_TRUST_NON_REPUDIATION => "CKA_TRUST_NON_REPUDIATION",
        CKA_TRUST_KEY_ENCIPHERMENT => "CKA_TRUST_KEY_ENCIPHERMENT",
        CKA_TRUST_DATA_ENCIPHERMENT => "CKA_TRUST_DATA_ENCIPHERMENT",
        CKA_TRUST_KEY_AGREEMENT => "CKA_TRUST_KEY_AGREEMENT",
        CKA_TRUST_KEY_CERT_SIGN => "CKA_TRUST_KEY_CERT_SIGN",
        CKA_TRUST_CRL_SIGN => "CKA_TRUST_CRL_SIGN",
        CKA_TRUST_SERVER_AUTH => "CKA_TRUST_SERVER_AUTH",
        CKA_TRUST_CLIENT_AUTH => "CKA_TRUST_CLIENT_AUTH",
        CKA_TRUST_CODE_SIGNING => "CKA_TRUST_CODE_SIGNING",
        CKA_TRUST_EMAIL_PROTECTION => "CKA_TRUST_EMAIL_PROTECTION",
        CKA_TRUST_IPSEC_END_SYSTEM => "CKA_TRUST_IPSEC_END_SYSTEM",
        CKA_TRUST_IPSEC_TUNNEL => "CKA_TRUST_IPSEC_TUNNEL",
        CKA_TRUST_IPSEC_USER => "CKA_TRUST_IPSEC_USER",
        CKA_TRUST_TIME_STAMPING => "CKA_TRUST_TIME_STAMPING",
        CKA_TRUST_STEP_UP_APPROVED => "CKA_TRUST_STEP_UP_APPROVED",
        CKA_CERT_SHA1_HASH => "CKA_CERT_SHA1_HASH",
        CKA_CERT_MD5_HASH => "CKA_CERT_MD5_HASH",
        _ => "UNKNOWN",
    }
}

fn summarize_attribute_value(attribute: &CkAttribute) -> Result<String, CkRv> {
    let value = unsafe { attribute_value_bytes(attribute)? };
    match attribute.type_ {
        CKA_CLASS
        | CKA_CERTIFICATE_TYPE
        | CKA_KEY_TYPE
        | CKA_PROFILE_ID
        | CKA_MODULUS_BITS
        | CKA_TRUST_DIGITAL_SIGNATURE
        | CKA_TRUST_NON_REPUDIATION
        | CKA_TRUST_KEY_ENCIPHERMENT
        | CKA_TRUST_DATA_ENCIPHERMENT
        | CKA_TRUST_KEY_AGREEMENT
        | CKA_TRUST_KEY_CERT_SIGN
        | CKA_TRUST_CRL_SIGN
        | CKA_TRUST_SERVER_AUTH
        | CKA_TRUST_CLIENT_AUTH
        | CKA_TRUST_CODE_SIGNING
        | CKA_TRUST_EMAIL_PROTECTION
        | CKA_TRUST_IPSEC_END_SYSTEM
        | CKA_TRUST_IPSEC_TUNNEL
        | CKA_TRUST_IPSEC_USER
        | CKA_TRUST_TIME_STAMPING => Ok(parse_ulong(value)?.to_string()),
        CKA_TOKEN | CKA_PRIVATE | CKA_ENCRYPT | CKA_SIGN | CKA_VERIFY | CKA_ALWAYS_AUTHENTICATE => {
            Ok(parse_bool(value)?.to_string())
        }
        CKA_LABEL => Ok(format!("{:?}", String::from_utf8_lossy(value))),
        CKA_ID => Ok(format!("0x{}", hex_upper(value))),
        CKA_ISSUER | CKA_SERIAL_NUMBER | CKA_SUBJECT => Ok(format!("0x{}", hex_upper(value))),
        CKA_VALUE | CKA_MODULUS | CKA_PUBLIC_EXPONENT | CKA_CERT_SHA1_HASH | CKA_CERT_MD5_HASH => {
            Ok(format!("<{} bytes>", value.len()))
        }
        _ => Ok(format!("<{} bytes>", value.len())),
    }
}

pub(crate) fn summarize_find_template(attributes: &[CkAttribute]) -> Result<String, CkRv> {
    if attributes.is_empty() {
        return Ok("<empty>".to_owned());
    }

    let mut output = String::new();
    for (index, attribute) in attributes.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        let name = attribute_type_name(attribute.type_);
        if name == "UNKNOWN" {
            write!(&mut output, "0x{:08X}", attribute.type_).expect("write to string");
        } else {
            output.push_str(name);
        }

        if attribute.p_value.is_null() && attribute.ul_value_len != 0 {
            output.push_str("=<null>");
            continue;
        }

        if attribute.ul_value_len == 0 {
            output.push_str("=<empty>");
            continue;
        }

        let value = summarize_attribute_value(attribute)?;
        output.push('=');
        output.push_str(&value);
    }
    Ok(output)
}

pub(crate) fn summarize_attribute_types(attributes: &[CkAttribute]) -> String {
    if attributes.is_empty() {
        return "<empty>".to_owned();
    }

    let mut output = String::new();
    for (index, attribute) in attributes.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        let name = attribute_type_name(attribute.type_);
        if name == "UNKNOWN" {
            write!(&mut output, "0x{:08X}", attribute.type_).expect("write to string");
        } else {
            output.push_str(name);
        }
    }
    output
}

pub(crate) fn should_trace_find_template(attributes: &[CkAttribute]) -> bool {
    attributes.iter().any(|attribute| {
        matches!(
            attribute.type_,
            CKA_CLASS
                | CKA_CERTIFICATE_TYPE
                | CKA_CERT_MD5_HASH
                | CKA_CERT_SHA1_HASH
                | CKA_ID
                | CKA_ISSUER
                | CKA_SERIAL_NUMBER
                | CKA_SUBJECT
                | CKA_TRUST_CLIENT_AUTH
                | CKA_TRUST_CODE_SIGNING
                | CKA_TRUST_EMAIL_PROTECTION
                | CKA_TRUST_SERVER_AUTH
                | CKA_VALUE
        )
    })
}

pub(crate) fn should_trace_attribute_types(attributes: &[CkAttribute]) -> bool {
    attributes.iter().any(|attribute| {
        matches!(
            attribute.type_,
            CKA_CERTIFICATE_TYPE
                | CKA_CLASS
                | CKA_ID
                | CKA_ISSUER
                | CKA_KEY_TYPE
                | CKA_LABEL
                | CKA_SERIAL_NUMBER
                | CKA_SIGN
                | CKA_SUBJECT
                | CKA_VERIFY
                | CKA_TRUST_CLIENT_AUTH
                | CKA_TRUST_CODE_SIGNING
                | CKA_TRUST_EMAIL_PROTECTION
                | CKA_TRUST_SERVER_AUTH
                | CKA_CERT_MD5_HASH
                | CKA_CERT_SHA1_HASH
                | CKA_VALUE
        )
    })
}

pub(crate) fn summarize_object_record(object: &ObjectRecord) -> String {
    let class = match object.class {
        ObjectClass::Certificate => "certificate",
        ObjectClass::PublicKey => "public-key",
        ObjectClass::PrivateKey => "private-key",
        ObjectClass::Trust => "trust",
        ObjectClass::Profile => "profile",
    };

    let mut output = format!(
        "handle={} class={} label={:?} id=0x{}",
        object.handle,
        class,
        object.label,
        hex_upper(&object.id)
    );

    match &object.data {
        ObjectData::Certificate { attributes, der } => {
            write!(
                &mut output,
                " serial=0x{} der_len={}",
                hex_upper(&attributes.serial_number),
                der.len()
            )
            .expect("write to string");
        }
        ObjectData::PublicKey {
            key_type,
            key_size_bits,
            ..
        } => {
            write!(&mut output, " key_type={key_type:?} bits={key_size_bits}")
                .expect("write to string");
        }
        ObjectData::PrivateKey {
            key_type,
            key_reference,
            key_size_bits,
            ..
        } => {
            write!(
                &mut output,
                " key_type={key_type:?} key_ref={:02X} bits={}",
                key_reference, key_size_bits
            )
            .expect("write to string");
        }
        ObjectData::Trust { attributes } => {
            write!(
                &mut output,
                " serial=0x{} sha1_len={} md5_len={} trust_level={}",
                hex_upper(&attributes.serial_number),
                attributes.sha1_hash.len(),
                attributes.md5_hash.len(),
                attributes.trust_level
            )
            .expect("write to string");
        }
        ObjectData::Profile { profile_id } => {
            write!(&mut output, " profile_id={profile_id}").expect("write to string");
        }
    }

    output
}

pub(crate) fn push_unique_mechanism(mechanisms: &mut Vec<Mechanism>, mechanism: Mechanism) {
    if !mechanisms.contains(&mechanism) {
        mechanisms.push(mechanism);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ParsedCertificateAttributes {
    pub(crate) subject: Vec<u8>,
    pub(crate) issuer: Vec<u8>,
    pub(crate) serial_number: Vec<u8>,
    pub(crate) modulus: Option<Vec<u8>>,
    pub(crate) public_exponent: Option<Vec<u8>>,
    pub(crate) trust_level: CkUlong,
}

pub(crate) fn load_extra_certificate_objects(required_subjects: &[Vec<u8>]) -> Vec<ObjectTemplate> {
    let mut objects = Vec::new();
    if required_subjects.is_empty() {
        return objects;
    }

    let search_paths = extra_certificate_search_paths();
    if search_paths.is_empty() {
        return objects;
    }

    let mut candidates = Vec::new();
    for path in &search_paths {
        match collect_certificate_blobs(path) {
            Ok(blobs) => {
                for blob in blobs {
                    match build_extra_certificate_candidate(path, &blob) {
                        Ok(candidate) => candidates.push(candidate),
                        Err(error) => trace(format!(
                            "load_extra_certificate_objects path={path:?} parse_error={error}"
                        )),
                    }
                }
            }
            Err(error) => trace(format!(
                "load_extra_certificate_objects path={path:?} read_error={error}"
            )),
        }
    }

    let mut pending_subjects = VecDeque::from(required_subjects.to_vec());
    let mut seen_subjects = BTreeSet::new();
    let mut loaded_ids = BTreeSet::new();
    while let Some(subject) = pending_subjects.pop_front() {
        if !seen_subjects.insert(subject.clone()) {
            continue;
        }

        for candidate in &candidates {
            if candidate.attributes.subject != subject {
                continue;
            }
            if !loaded_ids.insert(candidate.object_id.clone()) {
                continue;
            }

            trace(format!(
                "load_extra_certificate_objects path={:?} matched_subject=0x{} loaded_objects=2",
                candidate.source_path,
                hex_upper(&candidate.attributes.subject)
            ));

            objects.push(ObjectTemplate::certificate_with_attributes(
                candidate.label.clone(),
                candidate.object_id.clone(),
                candidate.der.clone(),
                CertificateAttributes {
                    subject: candidate.attributes.subject.clone(),
                    issuer: candidate.attributes.issuer.clone(),
                    serial_number: candidate.attributes.serial_number.clone(),
                },
            ));
            if let (Some(modulus), Some(public_exponent)) = (
                candidate.attributes.modulus.clone(),
                candidate.attributes.public_exponent.clone(),
            ) {
                objects.push(ObjectTemplate::public_key_with_attributes(
                    format!("{} Public Key", candidate.label),
                    candidate.object_id.clone(),
                    KeyType::Rsa,
                    modulus.len() * 8,
                    candidate.attributes.subject.clone(),
                    Some(modulus),
                    Some(public_exponent),
                ));
            }

            if candidate.attributes.issuer != candidate.attributes.subject {
                pending_subjects.push_back(candidate.attributes.issuer.clone());
            }
        }
    }

    objects
}

#[derive(Clone, Debug)]
struct ExtraCertificateCandidate {
    source_path: PathBuf,
    der: Vec<u8>,
    label: String,
    object_id: Vec<u8>,
    attributes: ParsedCertificateAttributes,
}

fn extra_certificate_search_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(value) = env::var_os("SMARTCARD_PKCS11_EXTRA_CERT_DIR") {
        paths.extend(env::split_paths(&value));
    }
    if paths.is_empty() {
        paths.extend(
            [
                "/etc/ssl/certs",
                "/etc/ssl/certs/ca-certificates.crt",
                "/etc/ssl/certs/ca-bundle.crt",
                "/etc/ssl/cert.pem",
                "/etc/pki/tls/certs/ca-bundle.crt",
            ]
            .into_iter()
            .map(PathBuf::from),
        );
    }
    paths
}

fn collect_certificate_blobs(path: &Path) -> Result<Vec<Vec<u8>>, SmartcardError> {
    if path.is_dir() {
        let mut entries = fs::read_dir(path)
            .map_err(|error| SmartcardError::protocol(error.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| SmartcardError::protocol(error.to_string()))?;
        entries.sort_by_key(|entry| entry.file_name());

        let mut certificates = Vec::new();
        for entry in entries {
            let entry_path = entry.path();
            if !entry_path.is_file() {
                continue;
            }
            match read_certificate_blobs_from_file(&entry_path) {
                Ok(mut blobs) => certificates.append(&mut blobs),
                Err(error) => trace(format!(
                    "load_extra_certificate_objects path={entry_path:?} file_error={error}"
                )),
            }
        }
        return Ok(certificates);
    }

    read_certificate_blobs_from_file(path)
}

fn read_certificate_blobs_from_file(path: &Path) -> Result<Vec<Vec<u8>>, SmartcardError> {
    let contents = fs::read(path).map_err(|error| SmartcardError::protocol(error.to_string()))?;
    if X509Certificate::from_der(&contents).is_ok() {
        return Ok(vec![contents]);
    }

    let mut certificates = Vec::new();
    for pem in Pem::iter_from_buffer(&contents) {
        let pem = pem.map_err(|error| SmartcardError::protocol(error.to_string()))?;
        if pem.label == "CERTIFICATE" {
            certificates.push(pem.contents);
        }
    }
    if certificates.is_empty() {
        return Err(SmartcardError::protocol(
            "unsupported certificate encoding".to_owned(),
        ));
    }
    Ok(certificates)
}

fn build_extra_certificate_candidate(
    path: &Path,
    certificate_der: &[u8],
) -> Result<ExtraCertificateCandidate, SmartcardError> {
    let (_, parsed) = X509Certificate::from_der(certificate_der)
        .map_err(|error| SmartcardError::protocol(error.to_string()))?;
    let attributes = parse_certificate_attributes(certificate_der)?;
    let object_id = Sha1::digest(certificate_der).to_vec();
    let label = parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|name| name.as_str().ok())
        .map(str::to_owned)
        .or_else(|| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "Imported Certificate".to_owned());

    Ok(ExtraCertificateCandidate {
        source_path: path.to_path_buf(),
        der: certificate_der.to_vec(),
        label,
        object_id,
        attributes,
    })
}

pub(crate) fn parse_certificate_attributes(
    der: &[u8],
) -> Result<ParsedCertificateAttributes, SmartcardError> {
    let (_, parsed) = X509Certificate::from_der(der)
        .map_err(|error| SmartcardError::protocol(error.to_string()))?;

    let (modulus, public_exponent) = match parsed.public_key().parsed() {
        Ok(PublicKey::RSA(rsa)) => (
            Some(trim_unsigned_integer(rsa.modulus)),
            Some(trim_unsigned_integer(rsa.exponent)),
        ),
        _ => (None, None),
    };

    Ok(ParsedCertificateAttributes {
        subject: parsed.subject().as_raw().to_vec(),
        issuer: parsed.issuer().as_raw().to_vec(),
        serial_number: der_encode_integer(parsed.tbs_certificate.raw_serial()),
        modulus,
        public_exponent,
        trust_level: if parsed.tbs_certificate.is_ca() {
            CKT_NSS_TRUSTED_DELEGATOR
        } else {
            CKT_NSS_MUST_VERIFY_TRUST
        },
    })
}

fn trim_unsigned_integer(bytes: &[u8]) -> Vec<u8> {
    if bytes.is_empty() {
        return Vec::new();
    }

    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    bytes[first_non_zero..].to_vec()
}

pub(crate) fn der_encode_integer(bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(bytes.len() + 6);
    output.push(0x02);
    output.extend(der_encode_length(bytes.len()));
    output.extend_from_slice(bytes);
    output
}

fn der_encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }

    let encoded = len.to_be_bytes();
    let first_non_zero = encoded
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(encoded.len() - 1);
    let length_bytes = &encoded[first_non_zero..];

    let mut output = Vec::with_capacity(length_bytes.len() + 1);
    output.push(0x80 | (length_bytes.len() as u8));
    output.extend_from_slice(length_bytes);
    output
}

pub(crate) fn private_key_descriptor(algorithm: SignAlgorithm) -> Option<(KeyType, usize)> {
    match algorithm {
        SignAlgorithm::Rsa1024 => Some((KeyType::Rsa, 1024)),
        SignAlgorithm::Rsa2048 => Some((KeyType::Rsa, 2048)),
        SignAlgorithm::Rsa3072 => Some((KeyType::Rsa, 3072)),
        SignAlgorithm::Rsa4096 => Some((KeyType::Rsa, 4096)),
        SignAlgorithm::EccP256 | SignAlgorithm::EccP384 => None,
    }
}

pub(crate) fn sign_algorithm_for_private_key(
    key_type: KeyType,
    key_size_bits: usize,
) -> Option<SignAlgorithm> {
    match (key_type, key_size_bits) {
        (KeyType::Rsa, 1024) => Some(SignAlgorithm::Rsa1024),
        (KeyType::Rsa, 2048) => Some(SignAlgorithm::Rsa2048),
        (KeyType::Rsa, 3072) => Some(SignAlgorithm::Rsa3072),
        (KeyType::Rsa, 4096) => Some(SignAlgorithm::Rsa4096),
        (KeyType::Ec, 256) => Some(SignAlgorithm::EccP256),
        (KeyType::Ec, 384) => Some(SignAlgorithm::EccP384),
        _ => None,
    }
}

pub(crate) fn ensure_piv_selected(
    runtime: &SmartcardRuntime,
    worker: &ReaderWorker,
) -> Result<(), CkRv> {
    let response = runtime
        .exchange(smartcard_piv::select_piv_application(), |apdu| {
            worker.transmit(apdu)
        })
        .map_err(map_smartcard_error)?;
    if response.status_word() != 0x9000 {
        return Err(CKR_TOKEN_NOT_PRESENT);
    }
    Ok(())
}

pub(crate) fn map_smartcard_error(error: SmartcardError) -> CkRv {
    match error {
        SmartcardError::InvalidArgument(_) => CKR_ARGUMENTS_BAD,
        SmartcardError::NotFound(_) => CKR_TOKEN_NOT_PRESENT,
        SmartcardError::Timeout { .. }
        | SmartcardError::Transport(_)
        | SmartcardError::Protocol(_)
        | SmartcardError::WorkerClosed
        | SmartcardError::Unsupported(_) => CKR_DEVICE_ERROR,
    }
}

pub(crate) fn map_piv_error(error: PivError) -> CkRv {
    match error {
        PivError::EmptyPin => CKR_PIN_INVALID,
        PivError::PinTooLong(_) => CKR_PIN_LEN_RANGE,
        PivError::NonAsciiPin => CKR_PIN_INVALID,
        PivError::InvalidDigestLength { .. } => CKR_DATA_LEN_RANGE,
        PivError::UnsupportedSigningAlgorithm(_) => CKR_MECHANISM_INVALID,
        PivError::UnexpectedStatusWord { .. }
        | PivError::MalformedTlv(_)
        | PivError::InvalidSelectResponse(_)
        | PivError::InvalidCertificateObject(_)
        | PivError::InvalidCertificateDer(_)
        | PivError::InvalidSignatureResponse(_)
        | PivError::SignatureVerificationFailed(_)
        | PivError::SecurityStatusNotSatisfied(_)
        | PivError::MissingDataObject(_)
        | PivError::InvalidDataObject(_, _) => CKR_DEVICE_ERROR,
    }
}

pub(crate) fn map_provider_error(error: ProviderError) -> CkRv {
    match error {
        ProviderError::SlotNotFound(_) => CKR_SLOT_ID_INVALID,
        ProviderError::SessionNotFound(_) => CKR_SESSION_HANDLE_INVALID,
        ProviderError::ObjectNotFound(_) => CKR_OBJECT_HANDLE_INVALID,
        ProviderError::TokenNotPresent(_) => CKR_TOKEN_NOT_PRESENT,
        ProviderError::UserTypeNotSupported(_) => CKR_USER_TYPE_INVALID,
        ProviderError::LoginRequired(_) => CKR_USER_NOT_LOGGED_IN,
        ProviderError::MechanismNotSupported(_) => CKR_MECHANISM_INVALID,
        ProviderError::ObjectClassMismatch { .. } => CKR_KEY_HANDLE_INVALID,
        ProviderError::ObjectSlotMismatch { .. } => CKR_OBJECT_HANDLE_INVALID,
    }
}

pub(crate) fn mechanism_from_ck(mechanism: CkMechanismType) -> Result<Mechanism, CkRv> {
    match mechanism {
        CKM_RSA_PKCS => Ok(Mechanism::RsaPkcs),
        CKM_RSA_PKCS_PSS => Ok(Mechanism::RsaPkcsPss),
        CKM_SHA256_RSA_PKCS => Ok(Mechanism::Sha256RsaPkcs),
        CKM_SHA256_RSA_PKCS_PSS => Ok(Mechanism::Sha256RsaPkcsPss),
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

pub(crate) fn ck_mechanism_from_internal(mechanism: Mechanism) -> CkMechanismType {
    match mechanism {
        Mechanism::RsaPkcs => CKM_RSA_PKCS,
        Mechanism::RsaPkcsPss => CKM_RSA_PKCS_PSS,
        Mechanism::Sha256RsaPkcs => CKM_SHA256_RSA_PKCS,
        Mechanism::Sha256RsaPkcsPss => CKM_SHA256_RSA_PKCS_PSS,
    }
}

pub(crate) fn validate_sign_mechanism(mechanism: &CkMechanism) -> Result<Mechanism, CkRv> {
    let internal = mechanism_from_ck(mechanism.mechanism)?;
    match internal {
        Mechanism::RsaPkcsPss | Mechanism::Sha256RsaPkcsPss => {
            if mechanism.ul_parameter_len != std::mem::size_of::<CkRsaPkcsPssParams>() as CkUlong
                || mechanism.p_parameter.is_null()
            {
                return Err(CKR_MECHANISM_PARAM_INVALID);
            }
            let params = unsafe { &*(mechanism.p_parameter.cast::<CkRsaPkcsPssParams>()) };
            if params.hash_alg != CKM_SHA256 || params.mgf != CKG_MGF1_SHA256 || params.s_len != 32
            {
                return Err(CKR_MECHANISM_PARAM_INVALID);
            }
        }
        Mechanism::RsaPkcs | Mechanism::Sha256RsaPkcs => {
            if mechanism.ul_parameter_len != 0 || !mechanism.p_parameter.is_null() {
                return Err(CKR_MECHANISM_PARAM_INVALID);
            }
        }
    }

    Ok(internal)
}

pub(crate) fn certificate_slot_for_key_reference(key_reference: u8) -> Option<CertificateSlot> {
    PRIMARY_CERTIFICATE_SLOTS
        .iter()
        .copied()
        .find(|slot| slot.key_reference == key_reference)
}

pub(crate) fn prepare_raw_rsa_pkcs1_v1_5_input(
    algorithm: SignAlgorithm,
    data: &[u8],
) -> Result<Vec<u8>, CkRv> {
    let modulus_len = match algorithm {
        SignAlgorithm::Rsa1024
        | SignAlgorithm::Rsa2048
        | SignAlgorithm::Rsa3072
        | SignAlgorithm::Rsa4096 => algorithm.key_size_bytes(),
        SignAlgorithm::EccP256 | SignAlgorithm::EccP384 => return Err(CKR_KEY_TYPE_INCONSISTENT),
    };

    if data.len() + 11 > modulus_len {
        return Err(CKR_DATA_LEN_RANGE);
    }

    let padding_len = modulus_len - data.len() - 3;
    let mut block = Vec::with_capacity(modulus_len);
    block.push(0x00);
    block.push(0x01);
    block.extend(std::iter::repeat_n(0xFF, padding_len));
    block.push(0x00);
    block.extend_from_slice(data);
    Ok(block)
}

pub(crate) fn prepare_sha256_rsa_pss_input(
    algorithm: SignAlgorithm,
    data: &[u8],
    salt_len: usize,
) -> Result<Vec<u8>, CkRv> {
    let message_hash = Sha256::digest(data);
    prepare_pss_encoding(algorithm, message_hash.as_ref(), salt_len)
}

pub(crate) fn prepare_prehashed_rsa_pss_input(
    algorithm: SignAlgorithm,
    digest: &[u8],
    salt_len: usize,
) -> Result<Vec<u8>, CkRv> {
    if digest.len() != 32 {
        return Err(CKR_DATA_LEN_RANGE);
    }
    prepare_pss_encoding(algorithm, digest, salt_len)
}

fn prepare_pss_encoding(
    algorithm: SignAlgorithm,
    message_hash: &[u8],
    salt_len: usize,
) -> Result<Vec<u8>, CkRv> {
    let em_len = match algorithm {
        SignAlgorithm::Rsa1024
        | SignAlgorithm::Rsa2048
        | SignAlgorithm::Rsa3072
        | SignAlgorithm::Rsa4096 => algorithm.key_size_bytes(),
        SignAlgorithm::EccP256 | SignAlgorithm::EccP384 => return Err(CKR_KEY_TYPE_INCONSISTENT),
    };

    let hash_len = message_hash.len();
    if em_len < hash_len + salt_len + 2 {
        return Err(CKR_DATA_LEN_RANGE);
    }

    let mut salt = vec![0u8; salt_len];
    fill_random_bytes(&mut salt)?;

    let mut prefix = Vec::with_capacity(8 + hash_len + salt_len);
    prefix.extend_from_slice(&[0u8; 8]);
    prefix.extend_from_slice(message_hash.as_ref());
    prefix.extend_from_slice(&salt);
    let h = Sha256::digest(&prefix);

    let db_len = em_len - hash_len - 1;
    let mut db = vec![0u8; db_len];
    db[db_len - salt_len - 1] = 0x01;
    db[(db_len - salt_len)..].copy_from_slice(&salt);

    let db_mask = mgf1_sha256(h.as_ref(), db_len);
    for (byte, mask) in db.iter_mut().zip(db_mask) {
        *byte ^= mask;
    }
    db[0] &= 0x7F;

    let mut result = Vec::with_capacity(em_len);
    result.extend_from_slice(&db);
    result.extend_from_slice(h.as_ref());
    result.push(0xBC);
    Ok(result)
}

pub(crate) fn encode_ulong(value: CkUlong) -> Vec<u8> {
    value.to_ne_bytes().to_vec()
}

pub(crate) fn encode_bool(value: bool) -> [u8; 1] {
    [if value { CK_TRUE } else { CK_FALSE }]
}

pub(crate) fn populate_padded(destination: &mut [u8], value: &[u8]) {
    destination.fill(b' ');
    let count = value.len().min(destination.len());
    destination[..count].copy_from_slice(&value[..count]);
}

pub(crate) fn build_find_template_key(attributes: &[CkAttribute]) -> Result<FindTemplateKey, CkRv> {
    let mut predicates = Vec::with_capacity(attributes.len());
    for attribute in attributes {
        predicates.push(FindTemplatePredicate {
            type_: attribute.type_,
            value: unsafe { attribute_value_bytes(attribute)? }.to_vec(),
        });
    }
    Ok(FindTemplateKey(predicates))
}

pub(crate) fn object_matches_template(
    object: &ObjectRecord,
    attribute: &CkAttribute,
) -> Result<bool, CkRv> {
    let value = unsafe { attribute_value_bytes(attribute)? };
    match attribute.type_ {
        CKA_CLASS => Ok(parse_ulong(value)? == object_class_value(object.class)),
        CKA_TOKEN => Ok(parse_bool(value)?),
        CKA_PRIVATE => Ok(parse_bool(value)? == matches!(object.class, ObjectClass::PrivateKey)),
        CKA_LABEL => Ok(value == object.label.as_bytes()),
        CKA_ID => Ok(value == object.id.as_slice()),
        CKA_VALUE => match &object.data {
            ObjectData::Certificate { der, .. } => Ok(value == der.as_slice()),
            _ => Ok(false),
        },
        CKA_CERTIFICATE_TYPE => match object.class {
            ObjectClass::Certificate => Ok(parse_ulong(value)? == CKC_X_509),
            _ => Ok(false),
        },
        CKA_ISSUER => match &object.data {
            ObjectData::Certificate { attributes, .. } => Ok(value == attributes.issuer.as_slice()),
            ObjectData::Trust { attributes } => Ok(value == attributes.issuer.as_slice()),
            _ => Ok(false),
        },
        CKA_SERIAL_NUMBER => match &object.data {
            ObjectData::Certificate { attributes, .. } => {
                Ok(value == attributes.serial_number.as_slice())
            }
            ObjectData::Trust { attributes } => Ok(value == attributes.serial_number.as_slice()),
            _ => Ok(false),
        },
        CKA_KEY_TYPE => match &object.data {
            ObjectData::PublicKey { key_type, .. } => {
                Ok(parse_ulong(value)? == key_type_value(*key_type))
            }
            ObjectData::PrivateKey { key_type, .. } => {
                Ok(parse_ulong(value)? == key_type_value(*key_type))
            }
            _ => Ok(false),
        },
        CKA_PROFILE_ID => match &object.data {
            ObjectData::Profile { profile_id } => Ok(parse_ulong(value)? == *profile_id as CkUlong),
            _ => Ok(false),
        },
        CKA_SUBJECT => match &object.data {
            ObjectData::Certificate { attributes, .. } => {
                Ok(value == attributes.subject.as_slice())
            }
            ObjectData::PublicKey { subject, .. } => Ok(value == subject.as_slice()),
            ObjectData::PrivateKey { subject, .. } => Ok(value == subject.as_slice()),
            ObjectData::Trust { .. } | ObjectData::Profile { .. } => Ok(false),
        },
        CKA_ENCRYPT => match object.class {
            ObjectClass::PublicKey => Ok(parse_bool(value)? == false),
            _ => Ok(false),
        },
        CKA_SIGN => match object.class {
            ObjectClass::PrivateKey => Ok(parse_bool(value)?),
            _ => Ok(false),
        },
        CKA_VERIFY => match object.class {
            ObjectClass::PublicKey => Ok(parse_bool(value)?),
            _ => Ok(false),
        },
        CKA_MODULUS => match &object.data {
            ObjectData::PublicKey {
                modulus: Some(modulus),
                ..
            } => Ok(value == modulus.as_slice()),
            ObjectData::PrivateKey {
                modulus: Some(modulus),
                ..
            } => Ok(value == modulus.as_slice()),
            _ => Ok(false),
        },
        CKA_MODULUS_BITS => match &object.data {
            ObjectData::PublicKey {
                key_type: KeyType::Rsa,
                key_size_bits,
                ..
            } => Ok(parse_ulong(value)? == *key_size_bits as CkUlong),
            ObjectData::PrivateKey {
                key_type: KeyType::Rsa,
                key_size_bits,
                ..
            } => Ok(parse_ulong(value)? == *key_size_bits as CkUlong),
            _ => Ok(false),
        },
        CKA_PUBLIC_EXPONENT => match &object.data {
            ObjectData::PublicKey {
                public_exponent: Some(public_exponent),
                ..
            } => Ok(value == public_exponent.as_slice()),
            ObjectData::PrivateKey {
                public_exponent: Some(public_exponent),
                ..
            } => Ok(value == public_exponent.as_slice()),
            _ => Ok(false),
        },
        CKA_ALWAYS_AUTHENTICATE => match &object.data {
            ObjectData::PrivateKey {
                always_authenticate,
                ..
            } => Ok(parse_bool(value)? == *always_authenticate),
            _ => Ok(false),
        },
        CKA_CERT_SHA1_HASH => match &object.data {
            ObjectData::Trust { attributes } => Ok(value == attributes.sha1_hash.as_slice()),
            _ => Ok(false),
        },
        CKA_CERT_MD5_HASH => match &object.data {
            ObjectData::Trust { attributes } => Ok(value == attributes.md5_hash.as_slice()),
            _ => Ok(false),
        },
        CKA_TRUST_DIGITAL_SIGNATURE
        | CKA_TRUST_NON_REPUDIATION
        | CKA_TRUST_KEY_ENCIPHERMENT
        | CKA_TRUST_DATA_ENCIPHERMENT
        | CKA_TRUST_KEY_AGREEMENT
        | CKA_TRUST_KEY_CERT_SIGN
        | CKA_TRUST_CRL_SIGN
        | CKA_TRUST_SERVER_AUTH
        | CKA_TRUST_CLIENT_AUTH
        | CKA_TRUST_CODE_SIGNING
        | CKA_TRUST_EMAIL_PROTECTION
        | CKA_TRUST_IPSEC_END_SYSTEM
        | CKA_TRUST_IPSEC_TUNNEL
        | CKA_TRUST_IPSEC_USER
        | CKA_TRUST_TIME_STAMPING => match &object.data {
            ObjectData::Trust { attributes } => Ok(parse_ulong(value)? == attributes.trust_level),
            _ => Ok(false),
        },
        CKA_TRUST_STEP_UP_APPROVED => match &object.data {
            ObjectData::Trust { .. } => Ok(parse_bool(value)? == false),
            _ => Ok(false),
        },
        _ => Err(CKR_ATTRIBUTE_TYPE_INVALID),
    }
}

unsafe fn attribute_value_bytes<'a>(attribute: &CkAttribute) -> Result<&'a [u8], CkRv> {
    if attribute.ul_value_len == 0 {
        return Ok(&[]);
    }
    if attribute.p_value.is_null() {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    Ok(unsafe {
        slice::from_raw_parts(
            attribute.p_value.cast::<u8>(),
            attribute.ul_value_len as usize,
        )
    })
}

fn parse_ulong(bytes: &[u8]) -> Result<CkUlong, CkRv> {
    if bytes.len() != std::mem::size_of::<CkUlong>() {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    let mut encoded = [0u8; std::mem::size_of::<CkUlong>()];
    encoded.copy_from_slice(bytes);
    Ok(CkUlong::from_ne_bytes(encoded))
}

fn parse_bool(bytes: &[u8]) -> Result<bool, CkRv> {
    match bytes {
        [value] => Ok(*value != CK_FALSE),
        _ => Err(CKR_ATTRIBUTE_VALUE_INVALID),
    }
}

pub(crate) fn object_class_value(class: ObjectClass) -> CkObjectClass {
    match class {
        ObjectClass::Certificate => CKO_CERTIFICATE,
        ObjectClass::PublicKey => CKO_PUBLIC_KEY,
        ObjectClass::PrivateKey => CKO_PRIVATE_KEY,
        ObjectClass::Trust => CKO_NSS_TRUST,
        ObjectClass::Profile => CKO_PROFILE,
    }
}

pub(crate) fn key_type_value(key_type: KeyType) -> CkKeyType {
    match key_type {
        KeyType::Rsa => CKK_RSA,
        KeyType::Ec => CKK_EC,
    }
}

pub(crate) unsafe fn write_attribute(attribute: &mut CkAttribute, value: &[u8], rv: &mut CkRv) {
    let required = value.len() as CkUlong;
    if attribute.p_value.is_null() {
        attribute.ul_value_len = required;
        return;
    }
    if attribute.ul_value_len < required {
        attribute.ul_value_len = required;
        if *rv == CKR_OK {
            *rv = CKR_BUFFER_TOO_SMALL;
        }
        return;
    }

    unsafe {
        ptr::copy_nonoverlapping(value.as_ptr(), attribute.p_value.cast::<u8>(), value.len());
    }
    attribute.ul_value_len = required;
}

pub(crate) unsafe fn read_bytes<'a>(pointer: *const u8, len: CkUlong) -> Result<&'a [u8], CkRv> {
    if len == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    Ok(unsafe { slice::from_raw_parts(pointer, len as usize) })
}

fn mgf1_sha256(seed: &[u8], mask_len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(mask_len);
    let mut counter = 0u32;
    while output.len() < mask_len {
        let mut input = Vec::with_capacity(seed.len() + 4);
        input.extend_from_slice(seed);
        input.extend_from_slice(&counter.to_be_bytes());
        let block = Sha256::digest(&input);
        let remaining = mask_len - output.len();
        output.extend_from_slice(&block[..remaining.min(block.len())]);
        counter = counter.wrapping_add(1);
    }
    output
}

fn fill_random_bytes(output: &mut [u8]) -> Result<(), CkRv> {
    let mut file = File::open("/dev/urandom").map_err(|_| CKR_DEVICE_ERROR)?;
    file.read_exact(output).map_err(|_| CKR_DEVICE_ERROR)
}
