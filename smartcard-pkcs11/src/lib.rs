mod abi;
mod provider;
mod util;

#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};
use std::ptr;
use std::slice;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use abi::*;
pub use provider::*;
use sha2::{Digest, Sha256};
use smartcard_core::{RuntimeConfig, SmartcardError, SmartcardRuntime};
use smartcard_pcsc::PcscTransport;
use smartcard_piv::{
    CertificateSlot, PRIMARY_CERTIFICATE_SLOTS, SignAlgorithm, VerifyPinStatus,
    build_sign_commands, infer_sign_algorithm, parse_certificate_response, parse_select_response,
    parse_sign_response, parse_verify_pin_response, prepare_signing_input_sha256,
    read_certificate_command, select_piv_application, verify_pin_command,
};
use smartcard_worker::ReaderWorker;
use util::*;

struct ModuleLifecycle {
    state: Option<ModuleState>,
}

struct ModuleState {
    runtime: Option<SmartcardRuntime>,
    provider: Provider,
    workers: HashMap<String, ReaderWorker>,
    last_reader_refresh: Option<Instant>,
    last_token_refreshes: HashMap<SlotId, Instant>,
}

impl ModuleState {
    fn new() -> Self {
        let mut state = Self {
            runtime: None,
            provider: Provider::new(ProviderConfig::default()),
            workers: HashMap::new(),
            last_reader_refresh: None,
            last_token_refreshes: HashMap::new(),
        };
        let _ = state.refresh_slots();
        state
    }

    fn refresh_slots(&mut self) -> Result<(), SmartcardError> {
        if self.ensure_runtime().is_none() {
            trace("refresh_slots runtime unavailable; publishing zero tokens");
            self.provider.sync_readers(&[]);
            self.workers.clear();
            self.last_reader_refresh = Some(Instant::now());
            self.last_token_refreshes.clear();
            return Ok(());
        }

        let reader_poll_interval = self.provider.config.reader_poll_interval;
        let token_cache_ttl = self.provider.config.token_cache_ttl;
        let reader_refresh_due = self
            .last_reader_refresh
            .is_none_or(|last_refresh| last_refresh.elapsed() >= reader_poll_interval);

        if reader_refresh_due {
            let runtime = self.runtime_for_io()?;
            let readers = runtime.list_readers()?;
            self.provider.sync_readers(&readers);

            let known_readers: HashSet<String> =
                readers.into_iter().map(|reader| reader.name).collect();
            self.workers
                .retain(|reader_name, _| known_readers.contains(reader_name));
            self.last_token_refreshes
                .retain(|slot_id, _| self.provider.slot(*slot_id).is_some());
            self.last_reader_refresh = Some(Instant::now());
        }

        for slot_id in self.provider.slot_ids(false) {
            let Some(slot) = self.provider.slot(slot_id) else {
                continue;
            };
            let token_present = slot.token.is_some();
            let token_refresh_due =
                self.last_token_refreshes
                    .get(&slot_id)
                    .is_none_or(|last_refresh| {
                        let ttl = if token_present {
                            token_cache_ttl
                        } else {
                            reader_poll_interval
                        };
                        last_refresh.elapsed() >= ttl
                    });
            if !token_refresh_due {
                continue;
            }

            let reader_name = slot.reader.name.clone();
            if token_present {
                match self.probe_piv_token(&reader_name) {
                    Ok(true) => {}
                    Ok(false) | Err(_) => {
                        trace(format!(
                            "refresh_slots probe reader={reader_name:?} token_present=false; clearing token"
                        ));
                        let _ = self.provider.clear_token(slot_id);
                    }
                }
            } else {
                match self.inspect_piv_token(&reader_name) {
                    Ok(Some((token, objects))) => {
                        trace(format!(
                            "refresh_slots inspect reader={reader_name:?} published token label={:?} objects={} mechanisms={}",
                            token.label,
                            objects.len(),
                            token.mechanisms.len()
                        ));
                        let _ = self.provider.publish_token(slot_id, token, objects);
                    }
                    Ok(None) => {
                        trace(format!(
                            "refresh_slots inspect reader={reader_name:?} found no token"
                        ));
                        let _ = self.provider.clear_token(slot_id);
                    }
                    Err(error) => {
                        trace(format!(
                            "refresh_slots inspect reader={reader_name:?} error={error}"
                        ));
                        let _ = self.provider.clear_token(slot_id);
                    }
                }
            }
            self.last_token_refreshes.insert(slot_id, Instant::now());
        }
        Ok(())
    }

    fn ensure_runtime(&mut self) -> Option<&SmartcardRuntime> {
        if self.runtime.is_none() {
            let transport = PcscTransport::establish_user().ok()?;
            self.runtime = Some(SmartcardRuntime::new(transport, RuntimeConfig::default()));
        }
        self.runtime.as_ref()
    }

    fn inspect_piv_token(
        &mut self,
        reader_name: &str,
    ) -> Result<Option<(TokenTemplate, Vec<ObjectTemplate>)>, SmartcardError> {
        trace(format!("inspect_piv_token reader={reader_name:?} begin"));
        let runtime = self.runtime_for_io()?;
        let worker = self.worker_for_reader(reader_name)?;
        let response =
            runtime.exchange(select_piv_application(), |command| worker.transmit(command))?;

        if response.status_word() != 0x9000 {
            trace(format!(
                "inspect_piv_token reader={reader_name:?} select_sw={:04X}",
                response.status_word()
            ));
            return Ok(None);
        }

        let select = parse_select_response(&response.data)
            .map_err(|error| SmartcardError::protocol(error.to_string()))?;
        let atr = worker.snapshot().atr.unwrap_or_default();

        let mut objects = Vec::new();
        let mut mechanisms = Vec::new();
        let mut token_certificates = Vec::new();

        for slot in PRIMARY_CERTIFICATE_SLOTS {
            let response = runtime.exchange(read_certificate_command(slot), |command| {
                worker.transmit(command)
            })?;
            let Some(certificate) = parse_certificate_response(slot, &response)
                .map_err(|error| SmartcardError::protocol(error.to_string()))?
            else {
                trace(format!(
                    "inspect_piv_token reader={reader_name:?} slot={:02X} certificate=missing",
                    slot.key_reference
                ));
                continue;
            };
            trace(format!(
                "inspect_piv_token reader={reader_name:?} slot={:02X} certificate_len={}",
                slot.key_reference,
                certificate.der.len()
            ));
            let attributes = parse_certificate_attributes(&certificate.der)?;
            token_certificates.push((slot, certificate.der.clone()));

            let object_id = vec![slot.key_reference];
            objects.push(ObjectTemplate::certificate_with_attributes(
                slot.label,
                object_id.clone(),
                certificate.der.clone(),
                CertificateAttributes {
                    subject: attributes.subject.clone(),
                    issuer: attributes.issuer.clone(),
                    serial_number: attributes.serial_number.clone(),
                },
            ));
            let Ok(algorithm) = infer_sign_algorithm(&certificate) else {
                continue;
            };
            let Some((key_type, key_size_bits)) = private_key_descriptor(algorithm) else {
                continue;
            };

            if let (Some(modulus), Some(public_exponent)) = (
                attributes.modulus.clone(),
                attributes.public_exponent.clone(),
            ) {
                objects.push(ObjectTemplate::public_key_with_attributes(
                    format!("{} Public Key", slot.label),
                    object_id.clone(),
                    key_type,
                    key_size_bits,
                    attributes.subject.clone(),
                    Some(modulus),
                    Some(public_exponent),
                ));
            }

            push_unique_mechanism(&mut mechanisms, Mechanism::RsaPkcs);
            push_unique_mechanism(&mut mechanisms, Mechanism::RsaPkcsPss);
            push_unique_mechanism(&mut mechanisms, Mechanism::Sha256RsaPkcs);
            push_unique_mechanism(&mut mechanisms, Mechanism::Sha256RsaPkcsPss);
            objects.push(ObjectTemplate::private_key_with_attributes(
                slot.label,
                object_id,
                key_type,
                slot.key_reference,
                key_size_bits,
                false,
                attributes.subject,
                attributes.modulus,
                attributes.public_exponent,
            ));
        }

        if objects.is_empty() {
            trace(format!(
                "inspect_piv_token reader={reader_name:?} no publishable objects"
            ));
            return Ok(None);
        }
        trace(format!(
            "inspect_piv_token reader={reader_name:?} success label={:?} objects={}",
            select.label.as_deref().unwrap_or("PIV Token"),
            objects.len()
        ));
        let token_metadata = derive_token_metadata(
            &token_certificates,
            select.label.as_deref(),
            &atr,
            reader_name,
        );
        Ok(Some((
            TokenTemplate {
                label: token_metadata.label,
                manufacturer: token_metadata.manufacturer,
                model: token_metadata.model,
                serial_number: token_metadata.serial_number,
                login_required: true,
                mechanisms,
            },
            objects,
        )))
    }

    fn probe_piv_token(&mut self, reader_name: &str) -> Result<bool, SmartcardError> {
        let runtime = self.runtime_for_io()?;
        let worker = self.worker_for_reader(reader_name)?;
        let response =
            runtime.exchange(select_piv_application(), |command| worker.transmit(command))?;
        let present = response.status_word() == 0x9000;
        trace(format!(
            "probe_piv_token reader={reader_name:?} sw={:04X} present={present}",
            response.status_word()
        ));
        Ok(present)
    }

    fn runtime_for_io(&self) -> Result<SmartcardRuntime, SmartcardError> {
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| SmartcardError::transport("PC/SC runtime is unavailable"))?;
        Ok(SmartcardRuntime::from_shared(
            runtime.transport(),
            runtime.config().clone(),
        ))
    }

    fn worker_for_reader(&mut self, reader_name: &str) -> Result<&ReaderWorker, SmartcardError> {
        if !self.workers.contains_key(reader_name) {
            let runtime = self.runtime_for_io()?;
            let worker = ReaderWorker::start(
                runtime.transport(),
                reader_name.to_owned(),
                runtime.config().connect_timeout,
                self.provider.config.command_timeout,
                runtime.config().slow_call_threshold,
            )?;
            self.workers.insert(reader_name.to_owned(), worker);
        }

        self.workers.get(reader_name).ok_or_else(|| {
            SmartcardError::transport(format!("reader worker for {reader_name:?} is unavailable"))
        })
    }

    fn verify_pin_on_card(
        &mut self,
        reader_name: &str,
        pin: &str,
    ) -> Result<VerifyPinStatus, CkRv> {
        let started = Instant::now();
        trace(format!(
            "verify_pin_on_card reader={reader_name:?} pin_len={}",
            pin.len()
        ));
        let runtime = self.runtime_for_io().map_err(map_smartcard_error)?;
        let worker = self
            .worker_for_reader(reader_name)
            .map_err(map_smartcard_error)?;
        ensure_piv_selected(&runtime, worker)?;
        let command = verify_pin_command(pin).map_err(map_piv_error)?;
        let response = runtime
            .exchange(command, |apdu| worker.transmit(apdu))
            .map_err(map_smartcard_error)?;
        let status = parse_verify_pin_response(&response).map_err(map_piv_error)?;
        trace(format!(
            "verify_pin_on_card reader={reader_name:?} status={status:?} elapsed_ms={}",
            started.elapsed().as_millis()
        ));
        Ok(status)
    }

    fn sign_with_piv(
        &mut self,
        reader_name: &str,
        certificate_slot: CertificateSlot,
        algorithm: SignAlgorithm,
        mechanism: Mechanism,
        data: &[u8],
        pin: &str,
    ) -> Result<Vec<u8>, CkRv> {
        let started = Instant::now();
        trace(format!(
            "sign_with_piv reader={reader_name:?} slot={:02X} mechanism={mechanism:?} data_len={}",
            certificate_slot.key_reference,
            data.len()
        ));
        let runtime = self.runtime_for_io().map_err(map_smartcard_error)?;
        let worker = self
            .worker_for_reader(reader_name)
            .map_err(map_smartcard_error)?;
        ensure_piv_selected(&runtime, worker)?;
        trace(format!(
            "sign_with_piv slot={:02X} algorithm={algorithm:?}",
            certificate_slot.key_reference,
        ));

        let signing_input = match mechanism {
            Mechanism::Sha256RsaPkcs => {
                let digest = Sha256::digest(data);
                prepare_signing_input_sha256(algorithm, digest.as_ref()).map_err(map_piv_error)?
            }
            Mechanism::RsaPkcs => prepare_raw_rsa_pkcs1_v1_5_input(algorithm, data)?,
            Mechanism::RsaPkcsPss => prepare_prehashed_rsa_pss_input(algorithm, data, 32)?,
            Mechanism::Sha256RsaPkcsPss => prepare_sha256_rsa_pss_input(algorithm, data, 32)?,
        };

        match Self::verify_pin_on_existing_worker(&runtime, worker, pin)? {
            VerifyPinStatus::Verified => {}
            VerifyPinStatus::Incorrect { .. } => return Err(CKR_PIN_INCORRECT),
            VerifyPinStatus::Blocked => return Err(CKR_PIN_LOCKED),
        }
        trace(format!(
            "sign_with_piv slot={:02X} pin_verified signing_input_len={}",
            certificate_slot.key_reference,
            signing_input.len()
        ));

        let commands = build_sign_commands(certificate_slot, algorithm, &signing_input)
            .map_err(map_piv_error)?;
        if commands.is_empty() {
            return Err(CKR_GENERAL_ERROR);
        }
        trace(format!(
            "sign_with_piv slot={:02X} apdu_count={}",
            certificate_slot.key_reference,
            commands.len()
        ));

        for (index, command) in commands[..commands.len() - 1].iter().enumerate() {
            let chunk_started = Instant::now();
            let response = worker
                .transmit(command.clone())
                .map_err(map_smartcard_error)?;
            trace(format!(
                "sign_with_piv slot={:02X} chunk={} sw={:02X}{:02X} elapsed_ms={}",
                certificate_slot.key_reference,
                index,
                response.sw1,
                response.sw2,
                chunk_started.elapsed().as_millis()
            ));
            if response.status_word() != 0x9000 {
                return Err(CKR_DEVICE_ERROR);
            }
        }

        let final_started = Instant::now();
        let response = runtime
            .exchange(
                commands.last().expect("commands is not empty").clone(),
                |apdu| worker.transmit(apdu),
            )
            .map_err(map_smartcard_error)?;
        trace(format!(
            "sign_with_piv slot={:02X} final_sw={:02X}{:02X} elapsed_ms={}",
            certificate_slot.key_reference,
            response.sw1,
            response.sw2,
            final_started.elapsed().as_millis()
        ));
        let signature = parse_sign_response(&response).map_err(map_piv_error)?;
        trace(format!(
            "sign_with_piv slot={:02X} signature_len={} total_elapsed_ms={}",
            certificate_slot.key_reference,
            signature.len(),
            started.elapsed().as_millis()
        ));
        Ok(signature)
    }

    fn verify_pin_on_existing_worker(
        runtime: &SmartcardRuntime,
        worker: &ReaderWorker,
        pin: &str,
    ) -> Result<VerifyPinStatus, CkRv> {
        let started = Instant::now();
        let command = verify_pin_command(pin).map_err(map_piv_error)?;
        let response = runtime
            .exchange(command, |apdu| worker.transmit(apdu))
            .map_err(map_smartcard_error)?;
        let status = parse_verify_pin_response(&response).map_err(map_piv_error)?;
        trace(format!(
            "verify_pin_on_existing_worker status={status:?} elapsed_ms={}",
            started.elapsed().as_millis()
        ));
        Ok(status)
    }
}

static MODULE: OnceLock<Mutex<ModuleLifecycle>> = OnceLock::new();
static FUNCTION_LIST: OnceLock<CkFunctionList> = OnceLock::new();

fn lifecycle() -> &'static Mutex<ModuleLifecycle> {
    MODULE.get_or_init(|| Mutex::new(ModuleLifecycle { state: None }))
}

fn with_module<T>(f: impl FnOnce(&mut ModuleState) -> Result<T, CkRv>) -> Result<T, CkRv> {
    let mut guard = lifecycle().lock().map_err(|_| CKR_GENERAL_ERROR)?;
    let state = guard.state.as_mut().ok_or(CKR_CRYPTOKI_NOT_INITIALIZED)?;
    f(state)
}

fn complete_sign(
    module: &mut ModuleState,
    session_handle: SessionHandle,
    input: &[u8],
    signature: CkBytePtr,
    signature_len: CkUlongPtr,
) -> Result<(u8, usize), CkRv> {
    let active_sign = module
        .provider
        .active_sign(session_handle)
        .map_err(map_provider_error)?
        .cloned()
        .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
    let session_ref = module
        .provider
        .session(session_handle)
        .ok_or(CKR_SESSION_HANDLE_INVALID)?;
    let pin = module
        .provider
        .session_pin(session_handle)
        .map_err(map_provider_error)?
        .ok_or(CKR_USER_NOT_LOGGED_IN)?
        .to_owned();
    let reader_name = module
        .provider
        .slot(session_ref.slot_id)
        .ok_or(CKR_SLOT_ID_INVALID)?
        .reader
        .name
        .clone();
    let object = module
        .provider
        .object(active_sign.key_handle)
        .ok_or(CKR_KEY_HANDLE_INVALID)?;
    let (key_reference, key_type, key_size_bits) = match object.data {
        ObjectData::PublicKey { .. } => {
            return Err(CKR_KEY_HANDLE_INVALID);
        }
        ObjectData::PrivateKey {
            key_type,
            key_reference,
            key_size_bits,
            ..
        } => (key_reference, key_type, key_size_bits),
        ObjectData::Certificate { .. } | ObjectData::Trust { .. } | ObjectData::Profile { .. } => {
            return Err(CKR_KEY_HANDLE_INVALID);
        }
    };
    let algorithm =
        sign_algorithm_for_private_key(key_type, key_size_bits).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;

    let expected_len = (key_size_bits / 8) as CkUlong;
    if signature.is_null() {
        unsafe { ptr::write(signature_len, expected_len) };
        return Ok((key_reference, 0));
    }
    let caller_len = unsafe { *signature_len };
    if caller_len < expected_len {
        unsafe { ptr::write(signature_len, expected_len) };
        return Err(CKR_BUFFER_TOO_SMALL);
    }

    let mut sign_input = active_sign.data;
    sign_input.extend_from_slice(input);

    let certificate_slot =
        certificate_slot_for_key_reference(key_reference).ok_or(CKR_KEY_HANDLE_INVALID)?;
    let signature_bytes = module.sign_with_piv(
        &reader_name,
        certificate_slot,
        algorithm,
        active_sign.mechanism,
        &sign_input,
        &pin,
    )?;
    unsafe {
        ptr::copy_nonoverlapping(
            signature_bytes.as_ptr(),
            signature.cast::<u8>(),
            signature_bytes.len(),
        );
        ptr::write(signature_len, signature_bytes.len() as CkUlong);
    }
    module
        .provider
        .clear_sign(session_handle)
        .map_err(map_provider_error)?;
    Ok((key_reference, signature_bytes.len()))
}

fn function_list() -> &'static CkFunctionList {
    FUNCTION_LIST.get_or_init(|| CkFunctionList {
        version: CkVersion {
            major: 2,
            minor: 40,
        },
        c_initialize: Some(unsafe { erase_fn(C_Initialize as *const ()) }),
        c_finalize: Some(unsafe { erase_fn(C_Finalize as *const ()) }),
        c_get_info: Some(unsafe { erase_fn(C_GetInfo as *const ()) }),
        c_get_function_list: Some(unsafe { erase_fn(C_GetFunctionList as *const ()) }),
        c_get_slot_list: Some(unsafe { erase_fn(C_GetSlotList as *const ()) }),
        c_get_slot_info: Some(unsafe { erase_fn(C_GetSlotInfo as *const ()) }),
        c_get_token_info: Some(unsafe { erase_fn(C_GetTokenInfo as *const ()) }),
        c_get_mechanism_list: Some(unsafe { erase_fn(C_GetMechanismList as *const ()) }),
        c_get_mechanism_info: Some(unsafe { erase_fn(C_GetMechanismInfo as *const ()) }),
        c_init_token: None,
        c_init_pin: None,
        c_set_pin: None,
        c_open_session: Some(unsafe { erase_fn(C_OpenSession as *const ()) }),
        c_close_session: Some(unsafe { erase_fn(C_CloseSession as *const ()) }),
        c_close_all_sessions: Some(unsafe { erase_fn(C_CloseAllSessions as *const ()) }),
        c_get_session_info: Some(unsafe { erase_fn(C_GetSessionInfo as *const ()) }),
        c_get_operation_state: None,
        c_set_operation_state: None,
        c_login: Some(unsafe { erase_fn(C_Login as *const ()) }),
        c_logout: Some(unsafe { erase_fn(C_Logout as *const ()) }),
        c_create_object: None,
        c_copy_object: None,
        c_destroy_object: None,
        c_get_object_size: None,
        c_get_attribute_value: Some(unsafe { erase_fn(C_GetAttributeValue as *const ()) }),
        c_set_attribute_value: None,
        c_find_objects_init: Some(unsafe { erase_fn(C_FindObjectsInit as *const ()) }),
        c_find_objects: Some(unsafe { erase_fn(C_FindObjects as *const ()) }),
        c_find_objects_final: Some(unsafe { erase_fn(C_FindObjectsFinal as *const ()) }),
        c_encrypt_init: None,
        c_encrypt: None,
        c_encrypt_update: None,
        c_encrypt_final: None,
        c_decrypt_init: None,
        c_decrypt: None,
        c_decrypt_update: None,
        c_decrypt_final: None,
        c_digest_init: None,
        c_digest: None,
        c_digest_update: None,
        c_digest_key: None,
        c_digest_final: None,
        c_sign_init: Some(unsafe { erase_fn(C_SignInit as *const ()) }),
        c_sign: Some(unsafe { erase_fn(C_Sign as *const ()) }),
        c_sign_update: Some(unsafe { erase_fn(C_SignUpdate as *const ()) }),
        c_sign_final: Some(unsafe { erase_fn(C_SignFinal as *const ()) }),
        c_sign_recover_init: None,
        c_sign_recover: None,
        c_verify_init: None,
        c_verify: None,
        c_verify_update: None,
        c_verify_final: None,
        c_verify_recover_init: None,
        c_verify_recover: None,
        c_digest_encrypt_update: None,
        c_decrypt_digest_update: None,
        c_sign_encrypt_update: None,
        c_decrypt_verify_update: None,
        c_generate_key: None,
        c_generate_key_pair: None,
        c_wrap_key: None,
        c_unwrap_key: None,
        c_derive_key: None,
        c_seed_random: None,
        c_generate_random: None,
        c_get_function_status: None,
        c_cancel_function: None,
        c_wait_for_slot_event: None,
    })
}

unsafe fn erase_fn(pointer: *const ()) -> GenericFn {
    unsafe { std::mem::transmute(pointer) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Initialize(_init_args: CkVoidPtr) -> CkRv {
    let mut guard = match lifecycle().lock() {
        Ok(guard) => guard,
        Err(_) => return CKR_GENERAL_ERROR,
    };

    if guard.state.is_some() {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    guard.state = Some(ModuleState::new());
    CKR_OK
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Finalize(_reserved: CkVoidPtr) -> CkRv {
    let mut guard = match lifecycle().lock() {
        Ok(guard) => guard,
        Err(_) => return CKR_GENERAL_ERROR,
    };

    if guard.state.is_none() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    guard.state = None;
    CKR_OK
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetInfo(info: *mut CkInfo) -> CkRv {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let mut value = CkInfo {
        cryptoki_version: CkVersion {
            major: 2,
            minor: 40,
        },
        manufacturer_id: [b' '; 32],
        flags: 0,
        library_description: [b' '; 32],
        library_version: CkVersion { major: 0, minor: 1 },
    };
    populate_padded(&mut value.manufacturer_id, b"smartcard-rs");
    populate_padded(&mut value.library_description, b"smartcard-rs pkcs11");
    unsafe { ptr::write(info, value) };
    CKR_OK
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(functions: CkFunctionListPtrPtr) -> CkRv {
    if functions.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe { ptr::write(functions, function_list()) };
    CKR_OK
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSlotList(
    token_present: CkBbool,
    slot_list: CkSlotIdPtr,
    count: CkUlongPtr,
) -> CkRv {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match with_module(|module| {
        module.refresh_slots().map_err(map_smartcard_error)?;
        let slots = module.provider.slot_ids(token_present != CK_FALSE);
        if slot_list.is_null() {
            unsafe { ptr::write(count, slots.len() as CkUlong) };
            return Ok(());
        }

        let capacity = unsafe { *count } as usize;
        unsafe { ptr::write(count, slots.len() as CkUlong) };
        if capacity < slots.len() {
            return Err(CKR_BUFFER_TOO_SMALL);
        }

        for (index, slot_id) in slots.iter().enumerate() {
            unsafe { ptr::write(slot_list.add(index), *slot_id as CkSlotId) };
        }
        Ok(())
    }) {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSlotInfo(slot_id: CkSlotId, info: *mut CkSlotInfo) -> CkRv {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match with_module(|module| {
        module.refresh_slots().map_err(map_smartcard_error)?;
        let slot = module
            .provider
            .slot(slot_id as SlotId)
            .ok_or(CKR_SLOT_ID_INVALID)?;

        let mut value = CkSlotInfo {
            slot_description: [b' '; 64],
            manufacturer_id: [b' '; 32],
            flags: CKF_REMOVABLE_DEVICE | CKF_HW_SLOT,
            hardware_version: CkVersion { major: 0, minor: 1 },
            firmware_version: CkVersion { major: 0, minor: 1 },
        };
        populate_padded(&mut value.slot_description, slot.reader.name.as_bytes());
        populate_padded(&mut value.manufacturer_id, b"smartcard-rs");
        if slot.token.is_some() {
            value.flags |= CKF_TOKEN_PRESENT;
        }
        unsafe { ptr::write(info, value) };
        Ok(())
    }) {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetTokenInfo(slot_id: CkSlotId, info: *mut CkTokenInfo) -> CkRv {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match with_module(|module| {
        module.refresh_slots().map_err(map_smartcard_error)?;
        let slot = module
            .provider
            .slot(slot_id as SlotId)
            .ok_or(CKR_SLOT_ID_INVALID)?;
        let token = slot.token.as_ref().ok_or(CKR_TOKEN_NOT_PRESENT)?;
        let session_count = module
            .provider
            .sessions
            .values()
            .filter(|session| session.slot_id == slot.id)
            .count() as CkUlong;

        let mut value = CkTokenInfo {
            label: [b' '; 32],
            manufacturer_id: [b' '; 32],
            model: [b' '; 16],
            serial_number: [b' '; 16],
            flags: CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED,
            ul_max_session_count: CK_UNAVAILABLE_INFORMATION,
            ul_session_count: session_count,
            ul_max_rw_session_count: CK_UNAVAILABLE_INFORMATION,
            ul_rw_session_count: 0,
            ul_max_pin_len: 8,
            ul_min_pin_len: 1,
            ul_total_public_memory: CK_UNAVAILABLE_INFORMATION,
            ul_free_public_memory: CK_UNAVAILABLE_INFORMATION,
            ul_total_private_memory: CK_UNAVAILABLE_INFORMATION,
            ul_free_private_memory: CK_UNAVAILABLE_INFORMATION,
            hardware_version: CkVersion { major: 0, minor: 1 },
            firmware_version: CkVersion { major: 0, minor: 1 },
            utc_time: [b' '; 16],
        };

        populate_padded(&mut value.label, token.label.as_bytes());
        populate_padded(&mut value.manufacturer_id, token.manufacturer.as_bytes());
        populate_padded(&mut value.model, token.model.as_bytes());
        populate_padded(&mut value.serial_number, token.serial_number.as_bytes());
        if token.login_required {
            value.flags |= CKF_LOGIN_REQUIRED;
        }

        unsafe { ptr::write(info, value) };
        Ok(())
    }) {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetMechanismList(
    slot_id: CkSlotId,
    mechanisms: *mut CkMechanismType,
    count: CkUlongPtr,
) -> CkRv {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match with_module(|module| {
        module.refresh_slots().map_err(map_smartcard_error)?;
        let slot = module
            .provider
            .slot(slot_id as SlotId)
            .ok_or(CKR_SLOT_ID_INVALID)?;
        let token = slot.token.as_ref().ok_or(CKR_TOKEN_NOT_PRESENT)?;
        let mechanism_list: Vec<CkMechanismType> = token
            .mechanisms
            .iter()
            .copied()
            .map(ck_mechanism_from_internal)
            .collect();

        if mechanisms.is_null() {
            unsafe { ptr::write(count, mechanism_list.len() as CkUlong) };
            return Ok(());
        }

        let capacity = unsafe { *count } as usize;
        unsafe { ptr::write(count, mechanism_list.len() as CkUlong) };
        if capacity < mechanism_list.len() {
            return Err(CKR_BUFFER_TOO_SMALL);
        }

        for (index, mechanism) in mechanism_list.iter().enumerate() {
            unsafe { ptr::write(mechanisms.add(index), *mechanism) };
        }
        Ok(())
    }) {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetMechanismInfo(
    slot_id: CkSlotId,
    mechanism: CkMechanismType,
    info: *mut CkMechanismInfo,
) -> CkRv {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match with_module(|module| {
        module.refresh_slots().map_err(map_smartcard_error)?;
        let slot = module
            .provider
            .slot(slot_id as SlotId)
            .ok_or(CKR_SLOT_ID_INVALID)?;
        let token = slot.token.as_ref().ok_or(CKR_TOKEN_NOT_PRESENT)?;
        let internal = mechanism_from_ck(mechanism)?;
        if !token.mechanisms.contains(&internal) {
            return Err(CKR_MECHANISM_INVALID);
        }

        let mut min_bits = CkUlong::MAX;
        let mut max_bits = 0;
        for handle in &token.object_handles {
            let Some(object) = module.provider.object(*handle) else {
                continue;
            };
            if let ObjectData::PrivateKey {
                key_type: KeyType::Rsa,
                key_size_bits,
                ..
            } = object.data
            {
                let bits = key_size_bits as CkUlong;
                min_bits = min_bits.min(bits);
                max_bits = max_bits.max(bits);
            }
        }

        if max_bits == 0 {
            return Err(CKR_MECHANISM_INVALID);
        }

        let value = CkMechanismInfo {
            ul_min_key_size: min_bits,
            ul_max_key_size: max_bits,
            flags: CKF_SIGN | CKF_VERIFY,
        };
        unsafe { ptr::write(info, value) };
        Ok(())
    }) {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_OpenSession(
    slot_id: CkSlotId,
    flags: CkFlags,
    _application: CkVoidPtr,
    _notify: CkNotify,
    session: CkSessionHandlePtr,
) -> CkRv {
    if session.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if (flags & CKF_SERIAL_SESSION) == 0 {
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    }

    match with_module(|module| {
        module.refresh_slots().map_err(map_smartcard_error)?;
        if module
            .provider
            .slot(slot_id as SlotId)
            .and_then(|slot| slot.token.as_ref())
            .is_none()
        {
            return Err(CKR_TOKEN_NOT_PRESENT);
        }

        let handle = module
            .provider
            .open_session(slot_id as SlotId)
            .map_err(map_provider_error)?;
        unsafe { ptr::write(session, handle as CkSessionHandle) };
        Ok(())
    }) {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_CloseSession(session: CkSessionHandle) -> CkRv {
    match with_module(|module| {
        module
            .provider
            .close_session(session as SessionHandle)
            .map_err(map_provider_error)
    }) {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_CloseAllSessions(slot_id: CkSlotId) -> CkRv {
    match with_module(|module| {
        module
            .provider
            .close_all_sessions(slot_id as SlotId)
            .map_err(map_provider_error)
    }) {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSessionInfo(
    session: CkSessionHandle,
    info: *mut CkSessionInfo,
) -> CkRv {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match with_module(|module| {
        let session = module
            .provider
            .session(session as SessionHandle)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        let state = match session.state {
            SessionState::ReadOnlyPublic => CKS_RO_PUBLIC_SESSION,
            SessionState::ReadOnlyUser => CKS_RO_USER_FUNCTIONS,
        };
        let value = CkSessionInfo {
            slot_id: session.slot_id as CkSlotId,
            state,
            flags: CKF_SERIAL_SESSION,
            ul_device_error: 0,
        };
        unsafe { ptr::write(info, value) };
        Ok(())
    }) {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Login(
    session: CkSessionHandle,
    user_type: CkUserType,
    pin: CkUtf8CharPtr,
    pin_len: CkUlong,
) -> CkRv {
    trace(format!(
        "C_Login session={session} user_type={user_type} pin_len={pin_len}"
    ));
    let started = Instant::now();
    if user_type != CKU_USER {
        return CKR_USER_TYPE_INVALID;
    }

    let pin_bytes = match unsafe { read_bytes(pin.cast::<u8>(), pin_len) } {
        Ok(bytes) => bytes,
        Err(rv) => return rv,
    };
    let pin_string = match std::str::from_utf8(pin_bytes) {
        Ok(pin) => pin.to_owned(),
        Err(_) => return CKR_PIN_INVALID,
    };

    match with_module(|module| {
        let existing = module
            .provider
            .session(session as SessionHandle)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        let slot_id = existing.slot_id;
        let already_logged_in = module.provider.sessions.values().any(|session| {
            session.slot_id == slot_id && session.state == SessionState::ReadOnlyUser
        });
        if already_logged_in {
            return Err(CKR_USER_ALREADY_LOGGED_IN);
        }
        let reader_name = module
            .provider
            .slot(slot_id)
            .ok_or(CKR_SLOT_ID_INVALID)?
            .reader
            .name
            .clone();

        match module.verify_pin_on_card(&reader_name, &pin_string)? {
            VerifyPinStatus::Verified => module
                .provider
                .login(session as SessionHandle, UserType::User, pin_string)
                .map_err(map_provider_error),
            VerifyPinStatus::Incorrect { .. } => Err(CKR_PIN_INCORRECT),
            VerifyPinStatus::Blocked => Err(CKR_PIN_LOCKED),
        }
    }) {
        Ok(()) => {
            trace(format!(
                "C_Login session={session} rv=CKR_OK elapsed_ms={}",
                started.elapsed().as_millis()
            ));
            CKR_OK
        }
        Err(rv) => {
            trace(format!(
                "C_Login session={session} rv=0x{rv:08X} elapsed_ms={}",
                started.elapsed().as_millis()
            ));
            rv
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Logout(session: CkSessionHandle) -> CkRv {
    match with_module(|module| {
        let session_ref = module
            .provider
            .session(session as SessionHandle)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        if session_ref.state != SessionState::ReadOnlyUser {
            return Err(CKR_USER_NOT_LOGGED_IN);
        }
        module
            .provider
            .logout(session as SessionHandle)
            .map_err(map_provider_error)
    }) {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjectsInit(
    session: CkSessionHandle,
    template: *mut CkAttribute,
    count: CkUlong,
) -> CkRv {
    match with_module(|module| {
        let attributes = if template.is_null() {
            if count == 0 {
                &[][..]
            } else {
                return Err(CKR_ARGUMENTS_BAD);
            }
        } else {
            unsafe { slice::from_raw_parts(template.cast::<CkAttribute>(), count as usize) }
        };
        let should_trace_template = should_trace_find_template(attributes);
        let template_summary = if should_trace_template {
            Some(summarize_find_template(attributes)?)
        } else {
            None
        };
        let template_key = build_find_template_key(attributes)?;

        if let Some(results) = module
            .provider
            .cached_find_results(session as SessionHandle, &template_key)
            .map_err(map_provider_error)?
        {
            if let Some(template_summary) = &template_summary {
                trace_certs(format!(
                    "C_FindObjectsInit session={session} template_count={count} cache_hit=true result_count={} template={template_summary}",
                    results.len(),
                ));
            }
            return module
                .provider
                .set_find_results(session as SessionHandle, results)
                .map_err(map_provider_error);
        }

        let handles = module
            .provider
            .list_objects(session as SessionHandle, None)
            .map_err(map_provider_error)?;

        let mut results = Vec::new();
        'objects: for handle in handles {
            let object = module
                .provider
                .object(handle)
                .ok_or(CKR_OBJECT_HANDLE_INVALID)?;
            for attribute in attributes {
                if !object_matches_template(object, attribute)? {
                    continue 'objects;
                }
            }
            results.push(handle);
        }
        module
            .provider
            .cache_find_results(session as SessionHandle, template_key, results.clone())
            .map_err(map_provider_error)?;

        if let Some(template_summary) = &template_summary {
            trace_certs(format!(
                "C_FindObjectsInit session={session} template_count={count} cache_hit=false result_count={} template={template_summary}",
                results.len(),
            ));
        }

        module
            .provider
            .set_find_results(session as SessionHandle, results)
            .map_err(map_provider_error)
    }) {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjects(
    session: CkSessionHandle,
    object: CkObjectHandlePtr,
    max_object_count: CkUlong,
    object_count: CkUlongPtr,
) -> CkRv {
    if object_count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if max_object_count > 0 && object.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    match with_module(|module| {
        let results = module
            .provider
            .next_find_results(session as SessionHandle, max_object_count as usize)
            .map_err(map_provider_error)?;

        for (index, handle) in results.iter().enumerate() {
            unsafe { ptr::write(object.add(index), *handle as CkObjectHandle) };
        }
        unsafe { ptr::write(object_count, results.len() as CkUlong) };
        Ok(())
    }) {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjectsFinal(session: CkSessionHandle) -> CkRv {
    match with_module(|module| {
        module
            .provider
            .clear_find_results(session as SessionHandle)
            .map_err(map_provider_error)
    }) {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetAttributeValue(
    session: CkSessionHandle,
    object: CkObjectHandle,
    template: *mut CkAttribute,
    count: CkUlong,
) -> CkRv {
    if template.is_null() && count != 0 {
        return CKR_ARGUMENTS_BAD;
    }

    match with_module(|module| {
        let session = module
            .provider
            .session(session as SessionHandle)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        let object = module
            .provider
            .object(object as ObjectHandle)
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?;
        if object.slot_id != session.slot_id {
            return Err(CKR_OBJECT_HANDLE_INVALID);
        }
        let attributes = if count == 0 {
            &mut [][..]
        } else {
            unsafe { slice::from_raw_parts_mut(template, count as usize) }
        };
        let should_trace_attributes = should_trace_attribute_types(attributes);
        let requested_attributes = if should_trace_attributes {
            Some(summarize_attribute_types(attributes))
        } else {
            None
        };
        let object_summary = if should_trace_attributes {
            Some(summarize_object_record(object))
        } else {
            None
        };
        let mut rv = CKR_OK;

        for attribute in attributes {
            match attribute.type_ {
                CKA_CLASS => {
                    let value = encode_ulong(object_class_value(object.class));
                    unsafe { write_attribute(attribute, &value, &mut rv) };
                }
                CKA_TOKEN => {
                    let value = encode_bool(true);
                    unsafe { write_attribute(attribute, &value, &mut rv) };
                }
                CKA_PRIVATE => {
                    let value = encode_bool(matches!(object.class, ObjectClass::PrivateKey));
                    unsafe { write_attribute(attribute, &value, &mut rv) };
                }
                CKA_LABEL => unsafe {
                    write_attribute(attribute, object.label.as_bytes(), &mut rv);
                },
                CKA_ID => unsafe {
                    write_attribute(attribute, &object.id, &mut rv);
                },
                CKA_VALUE => match &object.data {
                    ObjectData::Certificate { der, .. } => unsafe {
                        write_attribute(attribute, der, &mut rv);
                    },
                    ObjectData::PublicKey { .. }
                    | ObjectData::PrivateKey { .. }
                    | ObjectData::Trust { .. }
                    | ObjectData::Profile { .. } => {
                        attribute.ul_value_len = CK_UNAVAILABLE_INFORMATION;
                        if rv == CKR_OK {
                            rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        }
                    }
                },
                CKA_CERTIFICATE_TYPE => match object.class {
                    ObjectClass::Certificate => {
                        let value = encode_ulong(CKC_X_509);
                        unsafe { write_attribute(attribute, &value, &mut rv) };
                    }
                    _ => {
                        attribute.ul_value_len = CK_UNAVAILABLE_INFORMATION;
                        if rv == CKR_OK {
                            rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        }
                    }
                },
                CKA_KEY_TYPE => match &object.data {
                    ObjectData::PublicKey { key_type, .. } => {
                        let value = encode_ulong(key_type_value(*key_type));
                        unsafe { write_attribute(attribute, &value, &mut rv) };
                    }
                    ObjectData::PrivateKey { key_type, .. } => {
                        let value = encode_ulong(key_type_value(*key_type));
                        unsafe { write_attribute(attribute, &value, &mut rv) };
                    }
                    _ => {
                        attribute.ul_value_len = CK_UNAVAILABLE_INFORMATION;
                        if rv == CKR_OK {
                            rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        }
                    }
                },
                CKA_PROFILE_ID => match &object.data {
                    ObjectData::Profile { profile_id } => {
                        let value = encode_ulong(*profile_id as CkUlong);
                        unsafe { write_attribute(attribute, &value, &mut rv) };
                    }
                    _ => {
                        attribute.ul_value_len = CK_UNAVAILABLE_INFORMATION;
                        if rv == CKR_OK {
                            rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        }
                    }
                },
                CKA_ISSUER => match &object.data {
                    ObjectData::Certificate { attributes, .. } => unsafe {
                        write_attribute(attribute, &attributes.issuer, &mut rv);
                    },
                    ObjectData::Trust { attributes } => unsafe {
                        write_attribute(attribute, &attributes.issuer, &mut rv);
                    },
                    _ => {
                        attribute.ul_value_len = CK_UNAVAILABLE_INFORMATION;
                        if rv == CKR_OK {
                            rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        }
                    }
                },
                CKA_SERIAL_NUMBER => match &object.data {
                    ObjectData::Certificate { attributes, .. } => unsafe {
                        write_attribute(attribute, &attributes.serial_number, &mut rv);
                    },
                    ObjectData::Trust { attributes } => unsafe {
                        write_attribute(attribute, &attributes.serial_number, &mut rv);
                    },
                    _ => {
                        attribute.ul_value_len = CK_UNAVAILABLE_INFORMATION;
                        if rv == CKR_OK {
                            rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        }
                    }
                },
                CKA_SUBJECT => match &object.data {
                    ObjectData::Certificate { attributes, .. } => unsafe {
                        write_attribute(attribute, &attributes.subject, &mut rv);
                    },
                    ObjectData::PublicKey { subject, .. } => unsafe {
                        write_attribute(attribute, subject, &mut rv);
                    },
                    ObjectData::PrivateKey { subject, .. } => unsafe {
                        write_attribute(attribute, subject, &mut rv);
                    },
                    ObjectData::Trust { .. } | ObjectData::Profile { .. } => {
                        attribute.ul_value_len = CK_UNAVAILABLE_INFORMATION;
                        if rv == CKR_OK {
                            rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        }
                    }
                },
                CKA_SIGN => match object.class {
                    ObjectClass::PrivateKey => {
                        let value = encode_bool(true);
                        unsafe { write_attribute(attribute, &value, &mut rv) };
                    }
                    _ => {
                        attribute.ul_value_len = CK_UNAVAILABLE_INFORMATION;
                        if rv == CKR_OK {
                            rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        }
                    }
                },
                CKA_ENCRYPT => match object.class {
                    ObjectClass::PublicKey => {
                        let value = encode_bool(false);
                        unsafe { write_attribute(attribute, &value, &mut rv) };
                    }
                    _ => {
                        attribute.ul_value_len = CK_UNAVAILABLE_INFORMATION;
                        if rv == CKR_OK {
                            rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        }
                    }
                },
                CKA_VERIFY => match object.class {
                    ObjectClass::PublicKey => {
                        let value = encode_bool(true);
                        unsafe { write_attribute(attribute, &value, &mut rv) };
                    }
                    _ => {
                        attribute.ul_value_len = CK_UNAVAILABLE_INFORMATION;
                        if rv == CKR_OK {
                            rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        }
                    }
                },
                CKA_MODULUS => match &object.data {
                    ObjectData::PublicKey {
                        modulus: Some(modulus),
                        ..
                    } => unsafe {
                        write_attribute(attribute, modulus, &mut rv);
                    },
                    ObjectData::PrivateKey {
                        modulus: Some(modulus),
                        ..
                    } => unsafe {
                        write_attribute(attribute, modulus, &mut rv);
                    },
                    _ => {
                        attribute.ul_value_len = CK_UNAVAILABLE_INFORMATION;
                        if rv == CKR_OK {
                            rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        }
                    }
                },
                CKA_MODULUS_BITS => match &object.data {
                    ObjectData::PublicKey {
                        key_type: KeyType::Rsa,
                        key_size_bits,
                        ..
                    } => {
                        let value = encode_ulong(*key_size_bits as CkUlong);
                        unsafe { write_attribute(attribute, &value, &mut rv) };
                    }
                    ObjectData::PrivateKey {
                        key_type: KeyType::Rsa,
                        key_size_bits,
                        ..
                    } => {
                        let value = encode_ulong(*key_size_bits as CkUlong);
                        unsafe { write_attribute(attribute, &value, &mut rv) };
                    }
                    _ => {
                        attribute.ul_value_len = CK_UNAVAILABLE_INFORMATION;
                        if rv == CKR_OK {
                            rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        }
                    }
                },
                CKA_PUBLIC_EXPONENT => match &object.data {
                    ObjectData::PublicKey {
                        public_exponent: Some(public_exponent),
                        ..
                    } => unsafe {
                        write_attribute(attribute, public_exponent, &mut rv);
                    },
                    ObjectData::PrivateKey {
                        public_exponent: Some(public_exponent),
                        ..
                    } => unsafe {
                        write_attribute(attribute, public_exponent, &mut rv);
                    },
                    _ => {
                        attribute.ul_value_len = CK_UNAVAILABLE_INFORMATION;
                        if rv == CKR_OK {
                            rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        }
                    }
                },
                CKA_ALWAYS_AUTHENTICATE => match &object.data {
                    ObjectData::PrivateKey {
                        always_authenticate,
                        ..
                    } => {
                        let value = encode_bool(*always_authenticate);
                        unsafe { write_attribute(attribute, &value, &mut rv) };
                    }
                    _ => {
                        attribute.ul_value_len = CK_UNAVAILABLE_INFORMATION;
                        if rv == CKR_OK {
                            rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        }
                    }
                },
                CKA_CERT_SHA1_HASH => match &object.data {
                    ObjectData::Trust { attributes } => unsafe {
                        write_attribute(attribute, &attributes.sha1_hash, &mut rv);
                    },
                    _ => {
                        attribute.ul_value_len = CK_UNAVAILABLE_INFORMATION;
                        if rv == CKR_OK {
                            rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        }
                    }
                },
                CKA_CERT_MD5_HASH => match &object.data {
                    ObjectData::Trust { attributes } => unsafe {
                        write_attribute(attribute, &attributes.md5_hash, &mut rv);
                    },
                    _ => {
                        attribute.ul_value_len = CK_UNAVAILABLE_INFORMATION;
                        if rv == CKR_OK {
                            rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        }
                    }
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
                    ObjectData::Trust { attributes } => {
                        let value = encode_ulong(attributes.trust_level);
                        unsafe { write_attribute(attribute, &value, &mut rv) };
                    }
                    _ => {
                        attribute.ul_value_len = CK_UNAVAILABLE_INFORMATION;
                        if rv == CKR_OK {
                            rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        }
                    }
                },
                CKA_TRUST_STEP_UP_APPROVED => match &object.data {
                    ObjectData::Trust { .. } => {
                        let value = encode_bool(false);
                        unsafe { write_attribute(attribute, &value, &mut rv) };
                    }
                    _ => {
                        attribute.ul_value_len = CK_UNAVAILABLE_INFORMATION;
                        if rv == CKR_OK {
                            rv = CKR_ATTRIBUTE_TYPE_INVALID;
                        }
                    }
                },
                _ => {
                    attribute.ul_value_len = CK_UNAVAILABLE_INFORMATION;
                    if rv == CKR_OK {
                        rv = CKR_ATTRIBUTE_TYPE_INVALID;
                    }
                }
            }
        }

        if let (Some(object_summary), Some(requested_attributes)) =
            (object_summary.as_ref(), requested_attributes.as_ref())
        {
            let rv_name = if rv == CKR_OK {
                "CKR_OK".to_owned()
            } else {
                format!("0x{rv:08X}")
            };
            trace_certs(format!(
                "C_GetAttributeValue session={} object={} attrs={} rv={rv_name}",
                session.handle, object_summary, requested_attributes,
            ));
        }

        if rv == CKR_OK { Ok(()) } else { Err(rv) }
    }) {
        Ok(()) => CKR_OK,
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_SignInit(
    session: CkSessionHandle,
    mechanism: *mut CkMechanism,
    key: CkObjectHandle,
) -> CkRv {
    if mechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let mechanism_type = unsafe { (*mechanism).mechanism };
    trace(format!(
        "C_SignInit session={session} key={key} mechanism=0x{mechanism_type:08X}"
    ));
    let started = Instant::now();
    match with_module(|module| {
        if module
            .provider
            .active_sign(session as SessionHandle)
            .map_err(map_provider_error)?
            .is_some()
        {
            return Err(CKR_OPERATION_ACTIVE);
        }

        let mechanism = unsafe { &*mechanism };
        let mechanism = validate_sign_mechanism(mechanism)?;
        let object = module
            .provider
            .object(key as ObjectHandle)
            .ok_or(CKR_OBJECT_HANDLE_INVALID)?;
        trace_certs(format!(
            "C_SignInit session={session} mechanism={mechanism:?} object={}",
            summarize_object_record(object),
        ));
        module
            .provider
            .sign_init(session as SessionHandle, mechanism, key as ObjectHandle)
            .map_err(map_provider_error)
    }) {
        Ok(()) => {
            trace(format!(
                "C_SignInit session={session} key={key} rv=CKR_OK elapsed_ms={}",
                started.elapsed().as_millis()
            ));
            CKR_OK
        }
        Err(rv) => {
            trace(format!(
                "C_SignInit session={session} key={key} rv=0x{rv:08X} elapsed_ms={}",
                started.elapsed().as_millis()
            ));
            rv
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Sign(
    session: CkSessionHandle,
    data: CkBytePtr,
    data_len: CkUlong,
    signature: CkBytePtr,
    signature_len: CkUlongPtr,
) -> CkRv {
    if signature_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let requested_sig_len = if signature.is_null() {
        None
    } else {
        Some(unsafe { *signature_len })
    };
    trace(format!(
        "C_Sign session={session} data_len={data_len} signature_ptr_null={} requested_sig_len={}",
        signature.is_null(),
        requested_sig_len
            .map(|len| len.to_string())
            .unwrap_or_else(|| "<query>".to_owned())
    ));
    let started = Instant::now();
    let input = match unsafe { read_bytes(data.cast::<u8>(), data_len) } {
        Ok(bytes) => bytes,
        Err(rv) => return rv,
    };

    match with_module(|module| {
        let (key_reference, signature_size) = complete_sign(
            module,
            session as SessionHandle,
            input,
            signature,
            signature_len,
        )?;
        if signature.is_null() {
            trace(format!(
                "C_Sign session={session} length_query expected_len={} elapsed_ms={}",
                unsafe { *signature_len },
                started.elapsed().as_millis()
            ));
        } else {
            trace(format!(
                "C_Sign session={session} key_ref={:02X} signature_len={} elapsed_ms={}",
                key_reference,
                signature_size,
                started.elapsed().as_millis()
            ));
        }
        Ok(())
    }) {
        Ok(()) => CKR_OK,
        Err(rv) => {
            trace(format!(
                "C_Sign session={session} rv=0x{rv:08X} elapsed_ms={}",
                started.elapsed().as_millis()
            ));
            rv
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_SignUpdate(
    session: CkSessionHandle,
    part: CkBytePtr,
    part_len: CkUlong,
) -> CkRv {
    trace(format!(
        "C_SignUpdate session={session} part_len={part_len}"
    ));
    let started = Instant::now();
    let input = match unsafe { read_bytes(part.cast::<u8>(), part_len) } {
        Ok(bytes) => bytes,
        Err(rv) => return rv,
    };

    match with_module(|module| {
        if !module
            .provider
            .append_sign_data(session as SessionHandle, input)
            .map_err(map_provider_error)?
        {
            return Err(CKR_OPERATION_NOT_INITIALIZED);
        }
        Ok(())
    }) {
        Ok(()) => {
            trace(format!(
                "C_SignUpdate session={session} rv=CKR_OK elapsed_ms={}",
                started.elapsed().as_millis()
            ));
            CKR_OK
        }
        Err(rv) => {
            trace(format!(
                "C_SignUpdate session={session} rv=0x{rv:08X} elapsed_ms={}",
                started.elapsed().as_millis()
            ));
            rv
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_SignFinal(
    session: CkSessionHandle,
    signature: CkBytePtr,
    signature_len: CkUlongPtr,
) -> CkRv {
    if signature_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let requested_sig_len = if signature.is_null() {
        None
    } else {
        Some(unsafe { *signature_len })
    };
    trace(format!(
        "C_SignFinal session={session} signature_ptr_null={} requested_sig_len={}",
        signature.is_null(),
        requested_sig_len
            .map(|len| len.to_string())
            .unwrap_or_else(|| "<query>".to_owned())
    ));
    let started = Instant::now();

    match with_module(|module| {
        let (key_reference, signature_size) = complete_sign(
            module,
            session as SessionHandle,
            &[],
            signature,
            signature_len,
        )?;
        if signature.is_null() {
            trace(format!(
                "C_SignFinal session={session} length_query expected_len={} elapsed_ms={}",
                unsafe { *signature_len },
                started.elapsed().as_millis()
            ));
        } else {
            trace(format!(
                "C_SignFinal session={session} key_ref={:02X} signature_len={} elapsed_ms={}",
                key_reference,
                signature_size,
                started.elapsed().as_millis()
            ));
        }
        Ok(())
    }) {
        Ok(()) => CKR_OK,
        Err(rv) => {
            trace(format!(
                "C_SignFinal session={session} rv=0x{rv:08X} elapsed_ms={}",
                started.elapsed().as_millis()
            ));
            rv
        }
    }
}
