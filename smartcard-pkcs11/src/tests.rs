use smartcard_core::{ReaderHealth, ReaderInfo};

use crate::abi::{
    CKA_CERTIFICATE_TYPE, CKA_CLASS, CKA_ID, CKA_ISSUER, CKA_MODULUS, CKA_PROFILE_ID,
    CKA_PUBLIC_EXPONENT, CKA_SERIAL_NUMBER, CKA_SIGN, CKA_SUBJECT, CKA_TOKEN,
    CKA_TRUST_CLIENT_AUTH, CKA_VERIFY, CKC_X_509, CKO_CERTIFICATE, CKO_PROFILE, CKO_PUBLIC_KEY,
    CKP_PUBLIC_CERTIFICATES_TOKEN, CKT_NSS_TRUSTED_DELEGATOR,
};
use crate::provider::{
    CertificateAttributes, FindTemplateKey, FindTemplatePredicate, KeyType, Mechanism, ObjectClass,
    ObjectData, ObjectRecord, ObjectTemplate, Provider, ProviderConfig, ProviderError,
    ProviderStatus, SessionState, TokenTemplate, TrustAttributes, UserType,
};
use crate::util::{
    der_encode_integer, derive_token_metadata, encode_bool, encode_ulong, object_matches_template,
    parse_certificate_attributes, prepare_sha256_rsa_pss_input,
};
use smartcard_piv::{PRIMARY_CERTIFICATE_SLOTS, SignAlgorithm};

fn reader(name: &str) -> ReaderInfo {
    ReaderInfo::new(name).with_health(ReaderHealth::Healthy)
}

fn token_template() -> TokenTemplate {
    TokenTemplate {
        label: "PIV Card".to_owned(),
        manufacturer: "Example".to_owned(),
        model: "PIV".to_owned(),
        serial_number: "123456".to_owned(),
        login_required: true,
        mechanisms: vec![
            Mechanism::RsaPkcs,
            Mechanism::Sha256RsaPkcs,
            Mechanism::Sha256RsaPkcsPss,
        ],
    }
}

#[test]
fn derive_token_metadata_prefers_certificate_identity_over_applet_identity() {
    let certificate = sample_certificate_der();
    let metadata = derive_token_metadata(
        &[(PRIMARY_CERTIFICATE_SLOTS[0], certificate)],
        Some("HID Global ActivID Applet 2.7.4"),
        &[0x3B, 0xD8, 0x18, 0x00, 0x80, 0x1F, 0x07, 0x80],
        "Reader A",
    );

    assert_eq!(metadata.label, "test-piv");
    assert_eq!(metadata.manufacturer, "piv_II");
    assert_eq!(metadata.model, "PKCS#15 emulated");
    assert_eq!(metadata.serial_number, "3BD81800801F0780");
}

fn sample_certificate_der() -> Vec<u8> {
    hex_to_bytes("308202023082016BA00302010202145C5ABC72AC965906A865793E0C10EE5E563A86DE300D06092A864886F70D01010B050030133111300F06035504030C08746573742D706976301E170D3236303430343033323932375A170D3236303430353033323932375A30133111300F06035504030C08746573742D70697630819F300D06092A864886F70D010101050003818D0030818902818100D4DDD9D9D9A93CF9417A8FD5590BE4F2A1EA09234C4CAF46330D3A9F703C0FD8F83C95D35DD63707FDF949FCFE2BCF0FE457ACE975D5B4A8A687591FD5152B4D4E4676BC17C67DDD624209E6A786419833C8EBF6DF4C48892E928DF8674EF0B1538C72EE9B951C06F8D388D048F14729D4BA7EF8EF15DC8D33EA4C74DACFB1010203010001A3533051301D0603551D0E041604146AAAD17C5666B545B18DD72EFACDC24E36E66189301F0603551D230418301680146AAAD17C5666B545B18DD72EFACDC24E36E66189300F0603551D130101FF040530030101FF300D06092A864886F70D01010B0500038181008360210CF5FC6EA893D014165C10912D49262498A8837DB9705F317110CDAA2D364C0457FD845FA096A9595CB89B3516E76214E9185D3756B8D8EE00585DA10A949E36A7472AD961D96D9F4F1848188AA8811CB8938ABC275B47E5F6B70073AA624EC9EF15DE4E5E7D84351696C4AE888CF00D72281D13B4CA2B6770764C5D8A").unwrap()
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("hex string must have an even length".to_owned());
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(chunk).map_err(|error| error.to_string())?;
        let value = u8::from_str_radix(pair, 16).map_err(|error| error.to_string())?;
        bytes.push(value);
    }
    Ok(bytes)
}

#[test]
fn sync_readers_preserves_slot_ids_by_reader_name() {
    let mut provider = Provider::new(ProviderConfig::default());
    provider.sync_readers(&[reader("Reader A"), reader("Reader B")]);

    let slot_a = provider.slot_for_reader("Reader A").unwrap();
    let slot_b = provider.slot_for_reader("Reader B").unwrap();
    assert_eq!(
        provider.status(),
        ProviderStatus::Ready {
            slots: 2,
            tokens: 0,
            sessions: 0,
        }
    );

    provider.sync_readers(&[reader("Reader B"), reader("Reader A")]);
    assert_eq!(provider.slot_for_reader("Reader A"), Some(slot_a));
    assert_eq!(provider.slot_for_reader("Reader B"), Some(slot_b));

    provider.sync_readers(&[reader("Reader B")]);
    assert_eq!(provider.slot_for_reader("Reader A"), None);
    assert_eq!(provider.slot_for_reader("Reader B"), Some(slot_b));
    assert_eq!(provider.slot_ids(false), vec![slot_b]);
}

#[test]
fn publish_token_exposes_certificate_and_private_key_objects() {
    let mut provider = Provider::new(ProviderConfig::default());
    provider.sync_readers(&[reader("Reader A")]);
    let slot_id = provider.slot_for_reader("Reader A").unwrap();

    let objects = provider
        .publish_token(
            slot_id,
            token_template(),
            [
                ObjectTemplate::certificate("Cert 9C", [0x9C], vec![0x30, 0x82]),
                ObjectTemplate::private_key("Key 9C", [0x9C], KeyType::Rsa, 0x9C, 2048, false),
            ],
        )
        .unwrap();

    assert_eq!(objects.len(), 2);
    let session = provider.open_session(slot_id).unwrap();
    assert_eq!(provider.list_objects(session, None).unwrap(), objects);
    assert_eq!(
        provider
            .list_objects(session, Some(ObjectClass::Certificate))
            .unwrap(),
        vec![objects[0]]
    );
    assert_eq!(
        provider
            .list_objects(session, Some(ObjectClass::PrivateKey))
            .unwrap(),
        vec![objects[1]]
    );
}

#[test]
fn publish_token_exposes_public_key_objects() {
    let mut provider = Provider::new(ProviderConfig::default());
    provider.sync_readers(&[reader("Reader A")]);
    let slot_id = provider.slot_for_reader("Reader A").unwrap();
    let attributes = parse_certificate_attributes(&sample_certificate_der()).unwrap();

    let objects = provider
        .publish_token(
            slot_id,
            token_template(),
            [ObjectTemplate::public_key_with_attributes(
                "Cert 9A Public Key",
                [0x9A],
                KeyType::Rsa,
                1024,
                attributes.subject.clone(),
                attributes.modulus.clone(),
                attributes.public_exponent.clone(),
            )],
        )
        .unwrap();

    assert_eq!(objects.len(), 1);
    let session = provider.open_session(slot_id).unwrap();
    assert_eq!(
        provider
            .list_objects(session, Some(ObjectClass::PublicKey))
            .unwrap(),
        objects
    );
}

#[test]
fn publish_token_exposes_profile_object() {
    let mut provider = Provider::new(ProviderConfig::default());
    provider.sync_readers(&[reader("Reader A")]);
    let slot_id = provider.slot_for_reader("Reader A").unwrap();

    let objects = provider
        .publish_token(
            slot_id,
            token_template(),
            [ObjectTemplate::profile(
                "PKCS#11 Profile",
                b"profile".to_vec(),
                CKP_PUBLIC_CERTIFICATES_TOKEN as u64,
            )],
        )
        .unwrap();

    assert_eq!(objects.len(), 1);
    let object = provider.object(objects[0]).unwrap();
    assert_eq!(object.class, ObjectClass::Profile);
    assert!(
        object_matches_template(
            object,
            &crate::abi::CkAttribute {
                type_: CKA_CLASS,
                p_value: (&CKO_PROFILE as *const _ as *mut _),
                ul_value_len: std::mem::size_of_val(&CKO_PROFILE) as _,
            },
        )
        .unwrap()
    );
    assert!(
        object_matches_template(
            object,
            &crate::abi::CkAttribute {
                type_: CKA_PROFILE_ID,
                p_value: (&CKP_PUBLIC_CERTIFICATES_TOKEN as *const _ as *mut _),
                ul_value_len: std::mem::size_of_val(&CKP_PUBLIC_CERTIFICATES_TOKEN) as _,
            },
        )
        .unwrap()
    );
}

#[test]
fn parsed_ca_certificates_use_delegator_trust() {
    let attributes = parse_certificate_attributes(&sample_certificate_der()).unwrap();
    assert_eq!(attributes.trust_level, CKT_NSS_TRUSTED_DELEGATOR);
}

#[test]
fn trust_object_matches_stored_trust_level() {
    let object = ObjectRecord {
        handle: 1,
        slot_id: 1,
        class: ObjectClass::Trust,
        label: "Trust".to_owned(),
        id: vec![0x9A],
        data: ObjectData::Trust {
            attributes: TrustAttributes {
                issuer: vec![0x30, 0x00],
                serial_number: vec![0x02, 0x01, 0x01],
                sha1_hash: vec![0xAA; 20],
                md5_hash: vec![0xBB; 16],
                trust_level: CKT_NSS_TRUSTED_DELEGATOR,
            },
        },
    };

    let trust_value = encode_ulong(CKT_NSS_TRUSTED_DELEGATOR);
    assert!(
        object_matches_template(
            &object,
            &crate::abi::CkAttribute {
                type_: CKA_TRUST_CLIENT_AUTH,
                p_value: trust_value.as_ptr() as *mut _,
                ul_value_len: trust_value.len() as _,
            },
        )
        .unwrap()
    );
}

#[test]
fn publish_token_reuses_handles_for_stable_objects() {
    let mut provider = Provider::new(ProviderConfig::default());
    provider.sync_readers(&[reader("Reader A")]);
    let slot_id = provider.slot_for_reader("Reader A").unwrap();

    let first = provider
        .publish_token(
            slot_id,
            token_template(),
            [
                ObjectTemplate::certificate("Cert 9C", [0x9C], vec![0x30, 0x82]),
                ObjectTemplate::private_key("Key 9C", [0x9C], KeyType::Rsa, 0x9C, 2048, false),
            ],
        )
        .unwrap();

    let second = provider
        .publish_token(
            slot_id,
            token_template(),
            [
                ObjectTemplate::certificate("Cert 9C", [0x9C], vec![0x30, 0x83]),
                ObjectTemplate::private_key("Key 9C", [0x9C], KeyType::Rsa, 0x9C, 2048, false),
            ],
        )
        .unwrap();

    assert_eq!(first, second);
    assert!(provider.object(first[0]).is_some());
    assert!(provider.object(first[1]).is_some());
}

#[test]
fn sign_init_requires_logged_in_user_and_private_key() {
    let mut provider = Provider::new(ProviderConfig::default());
    provider.sync_readers(&[reader("Reader A")]);
    let slot_id = provider.slot_for_reader("Reader A").unwrap();

    let objects = provider
        .publish_token(
            slot_id,
            token_template(),
            [
                ObjectTemplate::certificate("Cert 9C", [0x9C], vec![0x30, 0x82]),
                ObjectTemplate::private_key("Key 9C", [0x9C], KeyType::Rsa, 0x9C, 2048, false),
            ],
        )
        .unwrap();

    let session = provider.open_session(slot_id).unwrap();
    let error = provider
        .sign_init(session, Mechanism::Sha256RsaPkcs, objects[1])
        .unwrap_err();
    assert_eq!(error, ProviderError::LoginRequired(session));

    provider
        .login(session, UserType::User, "123456".to_owned())
        .unwrap();
    assert_eq!(
        provider.session(session).unwrap().state,
        SessionState::ReadOnlyUser
    );

    let error = provider
        .sign_init(session, Mechanism::Sha256RsaPkcs, objects[0])
        .unwrap_err();
    assert_eq!(
        error,
        ProviderError::ObjectClassMismatch {
            handle: objects[0],
            expected: ObjectClass::PrivateKey,
            actual: ObjectClass::Certificate,
        }
    );

    provider
        .sign_init(session, Mechanism::Sha256RsaPkcs, objects[1])
        .unwrap();
    let sign = provider.take_active_sign(session).unwrap().unwrap();
    assert_eq!(sign.key_handle, objects[1]);
    assert_eq!(sign.mechanism, Mechanism::Sha256RsaPkcs);
    assert!(provider.active_sign(session).unwrap().is_none());
}

#[test]
fn multipart_signing_buffers_data_for_sign_final() {
    let mut provider = Provider::new(ProviderConfig::default());
    provider.sync_readers(&[reader("Reader A")]);
    let slot_id = provider.slot_for_reader("Reader A").unwrap();

    let objects = provider
        .publish_token(
            slot_id,
            token_template(),
            [ObjectTemplate::private_key(
                "Key 9A",
                [0x9A],
                KeyType::Rsa,
                0x9A,
                2048,
                false,
            )],
        )
        .unwrap();

    let session = provider.open_session(slot_id).unwrap();
    provider
        .login(session, UserType::User, "123456".to_owned())
        .unwrap();
    provider
        .sign_init(session, Mechanism::Sha256RsaPkcsPss, objects[0])
        .unwrap();

    assert!(provider.append_sign_data(session, b"hello ").unwrap());
    assert!(provider.append_sign_data(session, b"world").unwrap());

    let sign = provider.active_sign(session).unwrap().unwrap();
    assert_eq!(sign.mechanism, Mechanism::Sha256RsaPkcsPss);
    assert_eq!(sign.data, b"hello world");
}

#[test]
fn removing_reader_drops_slot_objects_and_sessions() {
    let mut provider = Provider::new(ProviderConfig::default());
    provider.sync_readers(&[reader("Reader A"), reader("Reader B")]);
    let slot_a = provider.slot_for_reader("Reader A").unwrap();

    let objects = provider
        .publish_token(
            slot_a,
            token_template(),
            [ObjectTemplate::private_key(
                "Key 9A",
                [0x9A],
                KeyType::Rsa,
                0x9A,
                2048,
                false,
            )],
        )
        .unwrap();
    let session = provider.open_session(slot_a).unwrap();
    provider
        .login(session, UserType::User, "123456".to_owned())
        .unwrap();

    provider.sync_readers(&[reader("Reader B")]);

    assert!(provider.session(session).is_none());
    assert!(provider.object(objects[0]).is_none());
    assert_eq!(provider.slot(slot_a), None);
}

#[test]
fn token_login_is_shared_across_sessions_on_the_same_slot() {
    let mut provider = Provider::new(ProviderConfig::default());
    provider.sync_readers(&[reader("Reader A")]);
    let slot_id = provider.slot_for_reader("Reader A").unwrap();

    provider
        .publish_token(
            slot_id,
            token_template(),
            [ObjectTemplate::private_key(
                "Key 9C",
                [0x9C],
                KeyType::Rsa,
                0x9C,
                2048,
                false,
            )],
        )
        .unwrap();

    let session_a = provider.open_session(slot_id).unwrap();
    let session_b = provider.open_session(slot_id).unwrap();

    provider
        .login(session_a, UserType::User, "123456".to_owned())
        .unwrap();

    assert_eq!(
        provider.session(session_a).unwrap().state,
        SessionState::ReadOnlyUser
    );
    assert_eq!(
        provider.session(session_b).unwrap().state,
        SessionState::ReadOnlyUser
    );
    assert_eq!(provider.session_pin(session_b).unwrap(), Some("123456"));

    let session_c = provider.open_session(slot_id).unwrap();
    assert_eq!(
        provider.session(session_c).unwrap().state,
        SessionState::ReadOnlyUser
    );
    assert_eq!(provider.session_pin(session_c).unwrap(), Some("123456"));

    provider.logout(session_b).unwrap();

    assert_eq!(
        provider.session(session_a).unwrap().state,
        SessionState::ReadOnlyPublic
    );
    assert_eq!(
        provider.session(session_b).unwrap().state,
        SessionState::ReadOnlyPublic
    );
    assert_eq!(
        provider.session(session_c).unwrap().state,
        SessionState::ReadOnlyPublic
    );
    assert_eq!(provider.session_pin(session_a).unwrap(), None);
    assert_eq!(provider.session_pin(session_b).unwrap(), None);
    assert_eq!(provider.session_pin(session_c).unwrap(), None);
}

#[test]
fn parse_certificate_attributes_extracts_pkcs11_identity_fields() {
    let attributes = parse_certificate_attributes(&sample_certificate_der()).unwrap();

    assert_eq!(
        attributes.subject,
        hex_to_bytes("30133111300F06035504030C08746573742D706976").unwrap()
    );
    assert_eq!(
        attributes.issuer,
        hex_to_bytes("30133111300F06035504030C08746573742D706976").unwrap()
    );
    assert_eq!(
        attributes.serial_number,
        der_encode_integer(&hex_to_bytes("5C5ABC72AC965906A865793E0C10EE5E563A86DE").unwrap())
    );
    assert_eq!(
        attributes.modulus,
        Some(hex_to_bytes("D4DDD9D9D9A93CF9417A8FD5590BE4F2A1EA09234C4CAF46330D3A9F703C0FD8F83C95D35DD63707FDF949FCFE2BCF0FE457ACE975D5B4A8A687591FD5152B4D4E4676BC17C67DDD624209E6A786419833C8EBF6DF4C48892E928DF8674EF0B1538C72EE9B951C06F8D388D048F14729D4BA7EF8EF15DC8D33EA4C74DACFB101").unwrap())
    );
    assert_eq!(attributes.public_exponent, Some(vec![0x01, 0x00, 0x01]));
}

#[test]
fn object_matching_supports_certificate_identity_filters() {
    let cert_der = sample_certificate_der();
    let attributes = parse_certificate_attributes(&cert_der).unwrap();
    let object = ObjectRecord {
        handle: 1,
        slot_id: 1,
        class: ObjectClass::Certificate,
        label: "Digital Signature".to_owned(),
        id: vec![0x9C],
        data: ObjectData::Certificate {
            der: cert_der,
            attributes: CertificateAttributes {
                subject: attributes.subject.clone(),
                issuer: attributes.issuer.clone(),
                serial_number: attributes.serial_number.clone(),
            },
        },
    };

    let class_bytes = encode_ulong(CKO_CERTIFICATE);
    let token_bytes = encode_bool(true);
    let cert_type_bytes = encode_ulong(CKC_X_509);

    let subject_attr = crate::abi::CkAttribute {
        type_: CKA_SUBJECT,
        p_value: attributes.subject.as_ptr().cast_mut().cast(),
        ul_value_len: attributes.subject.len() as _,
    };
    let issuer_attr = crate::abi::CkAttribute {
        type_: CKA_ISSUER,
        p_value: attributes.issuer.as_ptr().cast_mut().cast(),
        ul_value_len: attributes.issuer.len() as _,
    };
    let serial_attr = crate::abi::CkAttribute {
        type_: CKA_SERIAL_NUMBER,
        p_value: attributes.serial_number.as_ptr().cast_mut().cast(),
        ul_value_len: attributes.serial_number.len() as _,
    };
    let class_attr = crate::abi::CkAttribute {
        type_: CKA_CLASS,
        p_value: class_bytes.as_ptr().cast_mut().cast(),
        ul_value_len: class_bytes.len() as _,
    };
    let token_attr = crate::abi::CkAttribute {
        type_: CKA_TOKEN,
        p_value: token_bytes.as_ptr().cast_mut().cast(),
        ul_value_len: token_bytes.len() as _,
    };
    let id_attr = crate::abi::CkAttribute {
        type_: CKA_ID,
        p_value: object.id.as_ptr().cast_mut().cast(),
        ul_value_len: object.id.len() as _,
    };
    let cert_type_attr = crate::abi::CkAttribute {
        type_: CKA_CERTIFICATE_TYPE,
        p_value: cert_type_bytes.as_ptr().cast_mut().cast(),
        ul_value_len: cert_type_bytes.len() as _,
    };

    assert!(object_matches_template(&object, &class_attr).unwrap());
    assert!(object_matches_template(&object, &token_attr).unwrap());
    assert!(object_matches_template(&object, &id_attr).unwrap());
    assert!(object_matches_template(&object, &cert_type_attr).unwrap());
    assert!(object_matches_template(&object, &subject_attr).unwrap());
    assert!(object_matches_template(&object, &issuer_attr).unwrap());
    assert!(object_matches_template(&object, &serial_attr).unwrap());
}

#[test]
fn object_matching_supports_private_key_rsa_public_attributes() {
    let cert_der = sample_certificate_der();
    let attributes = parse_certificate_attributes(&cert_der).unwrap();
    let object = ObjectRecord {
        handle: 2,
        slot_id: 1,
        class: ObjectClass::PrivateKey,
        label: "Digital Signature".to_owned(),
        id: vec![0x9C],
        data: ObjectData::PrivateKey {
            key_type: KeyType::Rsa,
            key_reference: 0x9C,
            key_size_bits: 1024,
            always_authenticate: false,
            subject: attributes.subject.clone(),
            modulus: attributes.modulus.clone(),
            public_exponent: attributes.public_exponent.clone(),
        },
    };

    let sign_bytes = encode_bool(true);
    let subject_attr = crate::abi::CkAttribute {
        type_: CKA_SUBJECT,
        p_value: attributes.subject.as_ptr().cast_mut().cast(),
        ul_value_len: attributes.subject.len() as _,
    };
    let modulus = attributes.modulus.unwrap();
    let exponent = attributes.public_exponent.unwrap();
    let modulus_attr = crate::abi::CkAttribute {
        type_: CKA_MODULUS,
        p_value: modulus.as_ptr().cast_mut().cast(),
        ul_value_len: modulus.len() as _,
    };
    let exponent_attr = crate::abi::CkAttribute {
        type_: CKA_PUBLIC_EXPONENT,
        p_value: exponent.as_ptr().cast_mut().cast(),
        ul_value_len: exponent.len() as _,
    };
    let sign_attr = crate::abi::CkAttribute {
        type_: CKA_SIGN,
        p_value: sign_bytes.as_ptr().cast_mut().cast(),
        ul_value_len: sign_bytes.len() as _,
    };

    assert!(object_matches_template(&object, &subject_attr).unwrap());
    assert!(object_matches_template(&object, &modulus_attr).unwrap());
    assert!(object_matches_template(&object, &exponent_attr).unwrap());
    assert!(object_matches_template(&object, &sign_attr).unwrap());
}

#[test]
fn object_matching_supports_public_key_rsa_attributes() {
    let cert_der = sample_certificate_der();
    let attributes = parse_certificate_attributes(&cert_der).unwrap();
    let object = ObjectRecord {
        handle: 3,
        slot_id: 1,
        class: ObjectClass::PublicKey,
        label: "PIV Authentication Public Key".to_owned(),
        id: vec![0x9A],
        data: ObjectData::PublicKey {
            key_type: KeyType::Rsa,
            key_size_bits: 1024,
            subject: attributes.subject.clone(),
            modulus: attributes.modulus.clone(),
            public_exponent: attributes.public_exponent.clone(),
        },
    };

    let verify_bytes = encode_bool(true);
    let class_bytes = encode_ulong(CKO_PUBLIC_KEY);
    let subject_attr = crate::abi::CkAttribute {
        type_: CKA_SUBJECT,
        p_value: attributes.subject.as_ptr().cast_mut().cast(),
        ul_value_len: attributes.subject.len() as _,
    };
    let modulus = attributes.modulus.unwrap();
    let exponent = attributes.public_exponent.unwrap();
    let modulus_attr = crate::abi::CkAttribute {
        type_: CKA_MODULUS,
        p_value: modulus.as_ptr().cast_mut().cast(),
        ul_value_len: modulus.len() as _,
    };
    let exponent_attr = crate::abi::CkAttribute {
        type_: CKA_PUBLIC_EXPONENT,
        p_value: exponent.as_ptr().cast_mut().cast(),
        ul_value_len: exponent.len() as _,
    };
    let class_attr = crate::abi::CkAttribute {
        type_: CKA_CLASS,
        p_value: class_bytes.as_ptr().cast_mut().cast(),
        ul_value_len: class_bytes.len() as _,
    };
    let verify_attr = crate::abi::CkAttribute {
        type_: CKA_VERIFY,
        p_value: verify_bytes.as_ptr().cast_mut().cast(),
        ul_value_len: verify_bytes.len() as _,
    };

    assert!(object_matches_template(&object, &class_attr).unwrap());
    assert!(object_matches_template(&object, &subject_attr).unwrap());
    assert!(object_matches_template(&object, &modulus_attr).unwrap());
    assert!(object_matches_template(&object, &exponent_attr).unwrap());
    assert!(object_matches_template(&object, &verify_attr).unwrap());
}

#[test]
fn find_result_cache_is_reused_for_identical_templates() {
    let mut provider = Provider::new(ProviderConfig::default());
    provider.sync_readers(&[reader("Reader A")]);
    let slot_id = provider.slot_for_reader("Reader A").unwrap();
    provider
        .publish_token(
            slot_id,
            token_template(),
            [
                ObjectTemplate::certificate("PIV Authentication", [0x9A], sample_certificate_der()),
                ObjectTemplate::private_key(
                    "PIV Authentication",
                    [0x9A],
                    KeyType::Rsa,
                    0x9A,
                    1024,
                    false,
                ),
            ],
        )
        .unwrap();

    let session = provider.open_session(slot_id).unwrap();
    let template = FindTemplateKey(vec![
        FindTemplatePredicate {
            type_: CKA_TOKEN,
            value: encode_bool(true).to_vec(),
        },
        FindTemplatePredicate {
            type_: CKA_CLASS,
            value: encode_ulong(CKO_CERTIFICATE),
        },
    ]);
    let expected = provider
        .list_objects(session, Some(ObjectClass::Certificate))
        .unwrap();

    assert_eq!(
        provider.cached_find_results(session, &template).unwrap(),
        None
    );

    provider
        .cache_find_results(session, template.clone(), expected.clone())
        .unwrap();

    assert_eq!(
        provider.cached_find_results(session, &template).unwrap(),
        Some(expected.clone())
    );

    provider.clear_token(slot_id).unwrap();
    assert_eq!(
        provider.cached_find_results(session, &template).unwrap(),
        None
    );
}

#[test]
fn prepare_sha256_rsa_pss_input_returns_rsa_encoded_block() {
    let block = prepare_sha256_rsa_pss_input(SignAlgorithm::Rsa2048, b"hello", 32).unwrap();

    assert_eq!(block.len(), 256);
    assert_eq!(block.last(), Some(&0xBC));
    assert_eq!(block[0] & 0x80, 0);
    assert!(block.iter().any(|byte| *byte != 0));
}
