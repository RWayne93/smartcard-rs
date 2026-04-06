#![allow(dead_code)]

use std::os::raw::{c_ulong, c_void};

pub type CkByte = u8;
pub type CkChar = u8;
pub type CkUtf8Char = u8;
pub type CkBbool = u8;
pub type CkUlong = c_ulong;
pub type CkFlags = CkUlong;
pub type CkSlotId = CkUlong;
pub type CkSessionHandle = CkUlong;
pub type CkObjectHandle = CkUlong;
pub type CkUserType = CkUlong;
pub type CkState = CkUlong;
pub type CkObjectClass = CkUlong;
pub type CkKeyType = CkUlong;
pub type CkCertificateType = CkUlong;
pub type CkAttributeType = CkUlong;
pub type CkMechanismType = CkUlong;
pub type CkRv = CkUlong;
pub type CkVoidPtr = *mut c_void;
pub type CkBytePtr = *mut CkByte;
pub type CkCharPtr = *mut CkChar;
pub type CkUtf8CharPtr = *mut CkUtf8Char;
pub type CkUlongPtr = *mut CkUlong;
pub type CkSlotIdPtr = *mut CkSlotId;
pub type CkSessionHandlePtr = *mut CkSessionHandle;
pub type CkObjectHandlePtr = *mut CkObjectHandle;
pub type CkFunctionListPtrPtr = *mut *const CkFunctionList;
pub type CkNotify = Option<
    unsafe extern "C" fn(
        h_session: CkSessionHandle,
        event: CkUlong,
        p_application: CkVoidPtr,
    ) -> CkRv,
>;
pub type GenericFn = unsafe extern "C" fn();

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CkVersion {
    pub major: CkByte,
    pub minor: CkByte,
}

#[repr(C)]
pub struct CkInfo {
    pub cryptoki_version: CkVersion,
    pub manufacturer_id: [CkUtf8Char; 32],
    pub flags: CkFlags,
    pub library_description: [CkUtf8Char; 32],
    pub library_version: CkVersion,
}

#[repr(C)]
pub struct CkSlotInfo {
    pub slot_description: [CkUtf8Char; 64],
    pub manufacturer_id: [CkUtf8Char; 32],
    pub flags: CkFlags,
    pub hardware_version: CkVersion,
    pub firmware_version: CkVersion,
}

#[repr(C)]
pub struct CkTokenInfo {
    pub label: [CkUtf8Char; 32],
    pub manufacturer_id: [CkUtf8Char; 32],
    pub model: [CkUtf8Char; 16],
    pub serial_number: [CkChar; 16],
    pub flags: CkFlags,
    pub ul_max_session_count: CkUlong,
    pub ul_session_count: CkUlong,
    pub ul_max_rw_session_count: CkUlong,
    pub ul_rw_session_count: CkUlong,
    pub ul_max_pin_len: CkUlong,
    pub ul_min_pin_len: CkUlong,
    pub ul_total_public_memory: CkUlong,
    pub ul_free_public_memory: CkUlong,
    pub ul_total_private_memory: CkUlong,
    pub ul_free_private_memory: CkUlong,
    pub hardware_version: CkVersion,
    pub firmware_version: CkVersion,
    pub utc_time: [CkChar; 16],
}

#[repr(C)]
pub struct CkSessionInfo {
    pub slot_id: CkSlotId,
    pub state: CkState,
    pub flags: CkFlags,
    pub ul_device_error: CkUlong,
}

#[repr(C)]
pub struct CkAttribute {
    pub type_: CkAttributeType,
    pub p_value: CkVoidPtr,
    pub ul_value_len: CkUlong,
}

#[repr(C)]
pub struct CkMechanism {
    pub mechanism: CkMechanismType,
    pub p_parameter: CkVoidPtr,
    pub ul_parameter_len: CkUlong,
}

#[repr(C)]
pub struct CkMechanismInfo {
    pub ul_min_key_size: CkUlong,
    pub ul_max_key_size: CkUlong,
    pub flags: CkFlags,
}

pub type CkRsaPkcsMgfType = CkUlong;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CkRsaPkcsPssParams {
    pub hash_alg: CkMechanismType,
    pub mgf: CkRsaPkcsMgfType,
    pub s_len: CkUlong,
}

#[repr(C)]
pub struct CkFunctionList {
    pub version: CkVersion,
    pub c_initialize: Option<GenericFn>,
    pub c_finalize: Option<GenericFn>,
    pub c_get_info: Option<GenericFn>,
    pub c_get_function_list: Option<GenericFn>,
    pub c_get_slot_list: Option<GenericFn>,
    pub c_get_slot_info: Option<GenericFn>,
    pub c_get_token_info: Option<GenericFn>,
    pub c_get_mechanism_list: Option<GenericFn>,
    pub c_get_mechanism_info: Option<GenericFn>,
    pub c_init_token: Option<GenericFn>,
    pub c_init_pin: Option<GenericFn>,
    pub c_set_pin: Option<GenericFn>,
    pub c_open_session: Option<GenericFn>,
    pub c_close_session: Option<GenericFn>,
    pub c_close_all_sessions: Option<GenericFn>,
    pub c_get_session_info: Option<GenericFn>,
    pub c_get_operation_state: Option<GenericFn>,
    pub c_set_operation_state: Option<GenericFn>,
    pub c_login: Option<GenericFn>,
    pub c_logout: Option<GenericFn>,
    pub c_create_object: Option<GenericFn>,
    pub c_copy_object: Option<GenericFn>,
    pub c_destroy_object: Option<GenericFn>,
    pub c_get_object_size: Option<GenericFn>,
    pub c_get_attribute_value: Option<GenericFn>,
    pub c_set_attribute_value: Option<GenericFn>,
    pub c_find_objects_init: Option<GenericFn>,
    pub c_find_objects: Option<GenericFn>,
    pub c_find_objects_final: Option<GenericFn>,
    pub c_encrypt_init: Option<GenericFn>,
    pub c_encrypt: Option<GenericFn>,
    pub c_encrypt_update: Option<GenericFn>,
    pub c_encrypt_final: Option<GenericFn>,
    pub c_decrypt_init: Option<GenericFn>,
    pub c_decrypt: Option<GenericFn>,
    pub c_decrypt_update: Option<GenericFn>,
    pub c_decrypt_final: Option<GenericFn>,
    pub c_digest_init: Option<GenericFn>,
    pub c_digest: Option<GenericFn>,
    pub c_digest_update: Option<GenericFn>,
    pub c_digest_key: Option<GenericFn>,
    pub c_digest_final: Option<GenericFn>,
    pub c_sign_init: Option<GenericFn>,
    pub c_sign: Option<GenericFn>,
    pub c_sign_update: Option<GenericFn>,
    pub c_sign_final: Option<GenericFn>,
    pub c_sign_recover_init: Option<GenericFn>,
    pub c_sign_recover: Option<GenericFn>,
    pub c_verify_init: Option<GenericFn>,
    pub c_verify: Option<GenericFn>,
    pub c_verify_update: Option<GenericFn>,
    pub c_verify_final: Option<GenericFn>,
    pub c_verify_recover_init: Option<GenericFn>,
    pub c_verify_recover: Option<GenericFn>,
    pub c_digest_encrypt_update: Option<GenericFn>,
    pub c_decrypt_digest_update: Option<GenericFn>,
    pub c_sign_encrypt_update: Option<GenericFn>,
    pub c_decrypt_verify_update: Option<GenericFn>,
    pub c_generate_key: Option<GenericFn>,
    pub c_generate_key_pair: Option<GenericFn>,
    pub c_wrap_key: Option<GenericFn>,
    pub c_unwrap_key: Option<GenericFn>,
    pub c_derive_key: Option<GenericFn>,
    pub c_seed_random: Option<GenericFn>,
    pub c_generate_random: Option<GenericFn>,
    pub c_get_function_status: Option<GenericFn>,
    pub c_cancel_function: Option<GenericFn>,
    pub c_wait_for_slot_event: Option<GenericFn>,
}

pub const CK_FALSE: CkBbool = 0;
pub const CK_TRUE: CkBbool = 1;
pub const CK_UNAVAILABLE_INFORMATION: CkUlong = !0;
pub const CK_INVALID_HANDLE: CkUlong = 0;

pub const CKF_TOKEN_PRESENT: CkFlags = 0x0000_0001;
pub const CKF_REMOVABLE_DEVICE: CkFlags = 0x0000_0002;
pub const CKF_HW_SLOT: CkFlags = 0x0000_0004;
pub const CKF_LOGIN_REQUIRED: CkFlags = 0x0000_0004;
pub const CKF_USER_PIN_INITIALIZED: CkFlags = 0x0000_0008;
pub const CKF_TOKEN_INITIALIZED: CkFlags = 0x0000_0400;
pub const CKF_SERIAL_SESSION: CkFlags = 0x0000_0004;
pub const CKF_RW_SESSION: CkFlags = 0x0000_0002;
pub const CKF_SIGN: CkFlags = 0x0000_0800;
pub const CKF_VERIFY: CkFlags = 0x0000_2000;

pub const CKR_OK: CkRv = 0x0000_0000;
pub const CKR_GENERAL_ERROR: CkRv = 0x0000_0005;
pub const CKR_ARGUMENTS_BAD: CkRv = 0x0000_0007;
pub const CKR_FUNCTION_NOT_SUPPORTED: CkRv = 0x0000_0054;
pub const CKR_KEY_HANDLE_INVALID: CkRv = 0x0000_0060;
pub const CKR_KEY_TYPE_INCONSISTENT: CkRv = 0x0000_0063;
pub const CKR_MECHANISM_INVALID: CkRv = 0x0000_0070;
pub const CKR_MECHANISM_PARAM_INVALID: CkRv = 0x0000_0071;
pub const CKR_OBJECT_HANDLE_INVALID: CkRv = 0x0000_0082;
pub const CKR_OPERATION_ACTIVE: CkRv = 0x0000_0090;
pub const CKR_OPERATION_NOT_INITIALIZED: CkRv = 0x0000_0091;
pub const CKR_PIN_INCORRECT: CkRv = 0x0000_00A0;
pub const CKR_PIN_INVALID: CkRv = 0x0000_00A1;
pub const CKR_PIN_LEN_RANGE: CkRv = 0x0000_00A2;
pub const CKR_PIN_LOCKED: CkRv = 0x0000_00A4;
pub const CKR_SESSION_CLOSED: CkRv = 0x0000_00B0;
pub const CKR_SESSION_HANDLE_INVALID: CkRv = 0x0000_00B3;
pub const CKR_SESSION_PARALLEL_NOT_SUPPORTED: CkRv = 0x0000_00B4;
pub const CKR_SIGNATURE_INVALID: CkRv = 0x0000_00C0;
pub const CKR_SIGNATURE_LEN_RANGE: CkRv = 0x0000_00C1;
pub const CKR_TEMPLATE_INCONSISTENT: CkRv = 0x0000_00D1;
pub const CKR_TOKEN_NOT_PRESENT: CkRv = 0x0000_00E0;
pub const CKR_USER_ALREADY_LOGGED_IN: CkRv = 0x0000_0100;
pub const CKR_USER_NOT_LOGGED_IN: CkRv = 0x0000_0101;
pub const CKR_USER_TYPE_INVALID: CkRv = 0x0000_0103;
pub const CKR_BUFFER_TOO_SMALL: CkRv = 0x0000_0150;
pub const CKR_CRYPTOKI_NOT_INITIALIZED: CkRv = 0x0000_0190;
pub const CKR_CRYPTOKI_ALREADY_INITIALIZED: CkRv = 0x0000_0191;
pub const CKR_ATTRIBUTE_TYPE_INVALID: CkRv = 0x0000_0012;
pub const CKR_ATTRIBUTE_VALUE_INVALID: CkRv = 0x0000_0013;
pub const CKR_DEVICE_ERROR: CkRv = 0x0000_0030;
pub const CKR_DATA_LEN_RANGE: CkRv = 0x0000_0021;
pub const CKR_SLOT_ID_INVALID: CkRv = 0x0000_0003;
pub const CKR_NO_EVENT: CkRv = 0x0000_0008;

pub const CKU_USER: CkUserType = 1;

pub const CKS_RO_PUBLIC_SESSION: CkState = 0;
pub const CKS_RO_USER_FUNCTIONS: CkState = 1;
pub const CKS_RW_PUBLIC_SESSION: CkState = 2;
pub const CKS_RW_USER_FUNCTIONS: CkState = 3;

pub const CKO_VENDOR_DEFINED: CkObjectClass = 0x8000_0000;
pub const CKO_CERTIFICATE: CkObjectClass = 0x0000_0001;
pub const CKO_PUBLIC_KEY: CkObjectClass = 0x0000_0002;
pub const CKO_PRIVATE_KEY: CkObjectClass = 0x0000_0003;
pub const CKO_PROFILE: CkObjectClass = 0x0000_0009;
pub const NSSCK_VENDOR_NSS: CkUlong = 0x4E53_4350;
pub const CKO_NSS: CkObjectClass = CKO_VENDOR_DEFINED | NSSCK_VENDOR_NSS;
pub const CKO_NSS_TRUST: CkObjectClass = CKO_NSS + 3;
pub const CKO_NETSCAPE_TRUST: CkObjectClass = CKO_NSS_TRUST;

pub const CKK_RSA: CkKeyType = 0x0000_0000;
pub const CKK_EC: CkKeyType = 0x0000_0003;

pub const CKC_X_509: CkCertificateType = 0x0000_0000;

pub const CKA_VENDOR_DEFINED: CkAttributeType = 0x8000_0000;
pub const CKA_CLASS: CkAttributeType = 0x0000_0000;
pub const CKA_TOKEN: CkAttributeType = 0x0000_0001;
pub const CKA_PRIVATE: CkAttributeType = 0x0000_0002;
pub const CKA_LABEL: CkAttributeType = 0x0000_0003;
pub const CKA_VALUE: CkAttributeType = 0x0000_0011;
pub const CKA_CERTIFICATE_TYPE: CkAttributeType = 0x0000_0080;
pub const CKA_ISSUER: CkAttributeType = 0x0000_0081;
pub const CKA_SERIAL_NUMBER: CkAttributeType = 0x0000_0082;
pub const CKA_KEY_TYPE: CkAttributeType = 0x0000_0100;
pub const CKA_SUBJECT: CkAttributeType = 0x0000_0101;
pub const CKA_ID: CkAttributeType = 0x0000_0102;
pub const CKA_ENCRYPT: CkAttributeType = 0x0000_0104;
pub const CKA_SIGN: CkAttributeType = 0x0000_0108;
pub const CKA_VERIFY: CkAttributeType = 0x0000_010A;
pub const CKA_MODULUS: CkAttributeType = 0x0000_0120;
pub const CKA_MODULUS_BITS: CkAttributeType = 0x0000_0121;
pub const CKA_PUBLIC_EXPONENT: CkAttributeType = 0x0000_0122;
pub const CKA_ALWAYS_AUTHENTICATE: CkAttributeType = 0x0000_0202;
pub const CKA_PROFILE_ID: CkAttributeType = 0x0000_0601;
pub const CKA_NSS: CkAttributeType = CKA_VENDOR_DEFINED | NSSCK_VENDOR_NSS;
pub const CKA_TRUST: CkAttributeType = CKA_NSS + 0x2000;
pub const CKA_TRUST_DIGITAL_SIGNATURE: CkAttributeType = CKA_TRUST + 1;
pub const CKA_TRUST_NON_REPUDIATION: CkAttributeType = CKA_TRUST + 2;
pub const CKA_TRUST_KEY_ENCIPHERMENT: CkAttributeType = CKA_TRUST + 3;
pub const CKA_TRUST_DATA_ENCIPHERMENT: CkAttributeType = CKA_TRUST + 4;
pub const CKA_TRUST_KEY_AGREEMENT: CkAttributeType = CKA_TRUST + 5;
pub const CKA_TRUST_KEY_CERT_SIGN: CkAttributeType = CKA_TRUST + 6;
pub const CKA_TRUST_CRL_SIGN: CkAttributeType = CKA_TRUST + 7;
pub const CKA_TRUST_SERVER_AUTH: CkAttributeType = CKA_TRUST + 8;
pub const CKA_TRUST_CLIENT_AUTH: CkAttributeType = CKA_TRUST + 9;
pub const CKA_TRUST_CODE_SIGNING: CkAttributeType = CKA_TRUST + 10;
pub const CKA_TRUST_EMAIL_PROTECTION: CkAttributeType = CKA_TRUST + 11;
pub const CKA_TRUST_IPSEC_END_SYSTEM: CkAttributeType = CKA_TRUST + 12;
pub const CKA_TRUST_IPSEC_TUNNEL: CkAttributeType = CKA_TRUST + 13;
pub const CKA_TRUST_IPSEC_USER: CkAttributeType = CKA_TRUST + 14;
pub const CKA_TRUST_TIME_STAMPING: CkAttributeType = CKA_TRUST + 15;
pub const CKA_TRUST_STEP_UP_APPROVED: CkAttributeType = CKA_TRUST + 16;
pub const CKA_CERT_SHA1_HASH: CkAttributeType = CKA_TRUST + 100;
pub const CKA_CERT_MD5_HASH: CkAttributeType = CKA_TRUST + 101;

pub const CKT_VENDOR_DEFINED: CkUlong = 0x8000_0000;
pub const CKT_NSS: CkUlong = CKT_VENDOR_DEFINED | NSSCK_VENDOR_NSS;
pub const CKT_NSS_TRUSTED: CkUlong = CKT_NSS + 1;
pub const CKT_NSS_TRUSTED_DELEGATOR: CkUlong = CKT_NSS + 2;
pub const CKT_NSS_MUST_VERIFY_TRUST: CkUlong = CKT_NSS + 3;
pub const CKT_NSS_TRUST_UNKNOWN: CkUlong = CKT_NSS + 5;
pub const CKT_NSS_NOT_TRUSTED: CkUlong = CKT_NSS + 10;
pub const CKT_NSS_VALID_DELEGATOR: CkUlong = CKT_NSS + 11;

pub const CKP_AUTHENTICATION_TOKEN: CkUlong = 0x0000_0003;
pub const CKP_PUBLIC_CERTIFICATES_TOKEN: CkUlong = 0x0000_0004;

pub const CKM_RSA_PKCS: CkMechanismType = 0x0000_0001;
pub const CKM_RSA_PKCS_PSS: CkMechanismType = 0x0000_000D;
pub const CKM_SHA256_RSA_PKCS: CkMechanismType = 0x0000_0040;
pub const CKM_SHA256_RSA_PKCS_PSS: CkMechanismType = 0x0000_0043;
pub const CKM_SHA256: CkMechanismType = 0x0000_0250;
pub const CKG_MGF1_SHA256: CkRsaPkcsMgfType = 0x0000_0002;
