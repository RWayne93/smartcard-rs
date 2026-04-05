mod abi;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::error::Error;
use std::fmt;
use std::ptr;
use std::slice;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use abi::*;
use sha2::{Digest, Sha256};
use smartcard_core::{ReaderInfo, RuntimeConfig, SmartcardError, SmartcardRuntime};
use smartcard_pcsc::PcscTransport;
use smartcard_piv::{
    CertificateSlot, PRIMARY_CERTIFICATE_SLOTS, PivError, SignAlgorithm, VerifyPinStatus,
    build_sign_commands, infer_sign_algorithm, parse_certificate_response, parse_select_response,
    parse_sign_response, parse_verify_pin_response, prepare_signing_input_sha256,
    read_certificate_command, select_piv_application, verify_pin_command,
};
use smartcard_worker::ReaderWorker;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

pub type SlotId = u64;
pub type SessionHandle = u64;
pub type ObjectHandle = u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderConfig {
    pub command_timeout: Duration,
    pub reader_poll_interval: Duration,
    pub token_cache_ttl: Duration,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            command_timeout: Duration::from_secs(10),
            reader_poll_interval: Duration::from_secs(2),
            token_cache_ttl: Duration::from_secs(60),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderStatus {
    Empty,
    Ready {
        slots: usize,
        tokens: usize,
        sessions: usize,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mechanism {
    RsaPkcs,
    Sha256RsaPkcs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObjectClass {
    Certificate,
    PrivateKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyType {
    Rsa,
    Ec,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserType {
    User,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    ReadOnlyPublic,
    ReadOnlyUser,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderCapabilities {
    pub browser_client_auth: bool,
    pub find_objects: bool,
    pub login: bool,
    pub sign: Vec<Mechanism>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Slot {
    pub id: SlotId,
    pub reader: ReaderInfo,
    pub token: Option<Token>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    pub serial_number: String,
    pub login_required: bool,
    pub mechanisms: Vec<Mechanism>,
    pub object_handles: Vec<ObjectHandle>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenTemplate {
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    pub serial_number: String,
    pub login_required: bool,
    pub mechanisms: Vec<Mechanism>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectRecord {
    pub handle: ObjectHandle,
    pub slot_id: SlotId,
    pub class: ObjectClass,
    pub label: String,
    pub id: Vec<u8>,
    pub data: ObjectData,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ObjectIdentity {
    slot_id: SlotId,
    class: ObjectClass,
    id: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateAttributes {
    pub subject: Vec<u8>,
    pub issuer: Vec<u8>,
    pub serial_number: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectData {
    Certificate {
        der: Vec<u8>,
        attributes: CertificateAttributes,
    },
    PrivateKey {
        key_type: KeyType,
        key_reference: u8,
        key_size_bits: usize,
        always_authenticate: bool,
        subject: Vec<u8>,
        modulus: Option<Vec<u8>>,
        public_exponent: Option<Vec<u8>>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectTemplate {
    Certificate {
        label: String,
        id: Vec<u8>,
        der: Vec<u8>,
        attributes: CertificateAttributes,
    },
    PrivateKey {
        label: String,
        id: Vec<u8>,
        key_type: KeyType,
        key_reference: u8,
        key_size_bits: usize,
        always_authenticate: bool,
        subject: Vec<u8>,
        modulus: Option<Vec<u8>>,
        public_exponent: Option<Vec<u8>>,
    },
}

impl ObjectTemplate {
    pub fn certificate(label: impl Into<String>, id: impl Into<Vec<u8>>, der: Vec<u8>) -> Self {
        Self::Certificate {
            label: label.into(),
            id: id.into(),
            der,
            attributes: CertificateAttributes {
                subject: Vec::new(),
                issuer: Vec::new(),
                serial_number: Vec::new(),
            },
        }
    }

    pub fn certificate_with_attributes(
        label: impl Into<String>,
        id: impl Into<Vec<u8>>,
        der: Vec<u8>,
        attributes: CertificateAttributes,
    ) -> Self {
        Self::Certificate {
            label: label.into(),
            id: id.into(),
            der,
            attributes,
        }
    }

    pub fn private_key(
        label: impl Into<String>,
        id: impl Into<Vec<u8>>,
        key_type: KeyType,
        key_reference: u8,
        key_size_bits: usize,
        always_authenticate: bool,
    ) -> Self {
        Self::PrivateKey {
            label: label.into(),
            id: id.into(),
            key_type,
            key_reference,
            key_size_bits,
            always_authenticate,
            subject: Vec::new(),
            modulus: None,
            public_exponent: None,
        }
    }

    pub fn private_key_with_attributes(
        label: impl Into<String>,
        id: impl Into<Vec<u8>>,
        key_type: KeyType,
        key_reference: u8,
        key_size_bits: usize,
        always_authenticate: bool,
        subject: Vec<u8>,
        modulus: Option<Vec<u8>>,
        public_exponent: Option<Vec<u8>>,
    ) -> Self {
        Self::PrivateKey {
            label: label.into(),
            id: id.into(),
            key_type,
            key_reference,
            key_size_bits,
            always_authenticate,
            subject,
            modulus,
            public_exponent,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub handle: SessionHandle,
    pub slot_id: SlotId,
    pub state: SessionState,
    pub authenticated_pin: Option<String>,
    pub active_sign: Option<SignContext>,
    pub find_results: Vec<ObjectHandle>,
    pub find_position: usize,
    pub cached_find_template: Option<FindTemplateKey>,
    pub cached_find_results: Vec<ObjectHandle>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignContext {
    pub mechanism: Mechanism,
    pub key_handle: ObjectHandle,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FindTemplateKey(pub Vec<FindTemplatePredicate>);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FindTemplatePredicate {
    pub type_: CkAttributeType,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderError {
    SlotNotFound(SlotId),
    SessionNotFound(SessionHandle),
    ObjectNotFound(ObjectHandle),
    TokenNotPresent(SlotId),
    UserTypeNotSupported(UserType),
    LoginRequired(SessionHandle),
    MechanismNotSupported(Mechanism),
    ObjectClassMismatch {
        handle: ObjectHandle,
        expected: ObjectClass,
        actual: ObjectClass,
    },
    ObjectSlotMismatch {
        session: SessionHandle,
        slot_id: SlotId,
        object_handle: ObjectHandle,
        object_slot_id: SlotId,
    },
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SlotNotFound(slot_id) => write!(f, "slot {slot_id} was not found"),
            Self::SessionNotFound(handle) => write!(f, "session {handle} was not found"),
            Self::ObjectNotFound(handle) => write!(f, "object {handle} was not found"),
            Self::TokenNotPresent(slot_id) => write!(f, "slot {slot_id} has no token present"),
            Self::UserTypeNotSupported(user_type) => {
                write!(f, "user type {user_type:?} is not supported")
            }
            Self::LoginRequired(handle) => write!(f, "session {handle} must be logged in"),
            Self::MechanismNotSupported(mechanism) => {
                write!(f, "mechanism {mechanism:?} is not supported")
            }
            Self::ObjectClassMismatch {
                handle,
                expected,
                actual,
            } => write!(
                f,
                "object {handle} has class {actual:?}, expected {expected:?}"
            ),
            Self::ObjectSlotMismatch {
                session,
                slot_id,
                object_handle,
                object_slot_id,
            } => write!(
                f,
                "session {session} is bound to slot {slot_id}, but object {object_handle} belongs to slot {object_slot_id}"
            ),
        }
    }
}

impl Error for ProviderError {}

pub struct Provider {
    config: ProviderConfig,
    slots: BTreeMap<SlotId, Slot>,
    objects: HashMap<ObjectHandle, ObjectRecord>,
    object_identities: HashMap<ObjectIdentity, ObjectHandle>,
    reader_slots: HashMap<String, SlotId>,
    sessions: HashMap<SessionHandle, Session>,
    next_slot_id: SlotId,
    next_session_handle: SessionHandle,
    next_object_handle: ObjectHandle,
}

impl Provider {
    pub fn new(config: ProviderConfig) -> Self {
        Self {
            config,
            slots: BTreeMap::new(),
            objects: HashMap::new(),
            object_identities: HashMap::new(),
            reader_slots: HashMap::new(),
            sessions: HashMap::new(),
            next_slot_id: 1,
            next_session_handle: 1,
            next_object_handle: 1,
        }
    }

    pub fn config(&self) -> &ProviderConfig {
        &self.config
    }

    pub fn status(&self) -> ProviderStatus {
        if self.slots.is_empty() {
            ProviderStatus::Empty
        } else {
            ProviderStatus::Ready {
                slots: self.slots.len(),
                tokens: self
                    .slots
                    .values()
                    .filter(|slot| slot.token.is_some())
                    .count(),
                sessions: self.sessions.len(),
            }
        }
    }

    pub fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            browser_client_auth: true,
            find_objects: true,
            login: true,
            sign: vec![Mechanism::RsaPkcs, Mechanism::Sha256RsaPkcs],
        }
    }

    pub fn sync_readers(&mut self, readers: &[ReaderInfo]) {
        let mut seen = HashSet::new();

        for reader in readers {
            let slot_id = self
                .reader_slots
                .get(&reader.name)
                .copied()
                .unwrap_or_else(|| {
                    let slot_id = self.next_slot_id;
                    self.next_slot_id += 1;
                    self.reader_slots.insert(reader.name.clone(), slot_id);
                    self.slots.insert(
                        slot_id,
                        Slot {
                            id: slot_id,
                            reader: reader.clone(),
                            token: None,
                        },
                    );
                    slot_id
                });

            seen.insert(reader.name.clone());
            if let Some(slot) = self.slots.get_mut(&slot_id) {
                slot.reader = reader.clone();
            }
        }

        let removed: Vec<(String, SlotId)> = self
            .reader_slots
            .iter()
            .filter(|(reader_name, _)| !seen.contains(*reader_name))
            .map(|(reader_name, slot_id)| (reader_name.clone(), *slot_id))
            .collect();

        for (reader_name, slot_id) in removed {
            self.reader_slots.remove(&reader_name);
            self.remove_slot(slot_id);
        }
    }

    pub fn slot_for_reader(&self, reader_name: &str) -> Option<SlotId> {
        self.reader_slots.get(reader_name).copied()
    }

    pub fn slot_ids(&self, token_present_only: bool) -> Vec<SlotId> {
        self.slots
            .values()
            .filter(|slot| !token_present_only || slot.token.is_some())
            .map(|slot| slot.id)
            .collect()
    }

    pub fn slot(&self, slot_id: SlotId) -> Option<&Slot> {
        self.slots.get(&slot_id)
    }

    pub fn object(&self, handle: ObjectHandle) -> Option<&ObjectRecord> {
        self.objects.get(&handle)
    }

    pub fn session(&self, handle: SessionHandle) -> Option<&Session> {
        self.sessions.get(&handle)
    }

    pub fn publish_token(
        &mut self,
        slot_id: SlotId,
        token: TokenTemplate,
        objects: impl IntoIterator<Item = ObjectTemplate>,
    ) -> Result<Vec<ObjectHandle>, ProviderError> {
        let slot = self
            .slots
            .get_mut(&slot_id)
            .ok_or(ProviderError::SlotNotFound(slot_id))?;

        let existing_handles: HashSet<ObjectHandle> = slot
            .token
            .take()
            .map(|existing| existing.object_handles.into_iter().collect())
            .unwrap_or_default();

        let mut object_handles = Vec::new();
        let mut retained_handles = HashSet::new();
        for object in objects {
            let identity = object_identity(slot_id, &object);
            let handle = self
                .object_identities
                .get(&identity)
                .copied()
                .filter(|handle| self.objects.contains_key(handle))
                .unwrap_or_else(|| {
                    let handle = self.next_object_handle;
                    self.next_object_handle += 1;
                    self.object_identities.insert(identity.clone(), handle);
                    handle
                });

            let record = match object {
                ObjectTemplate::Certificate {
                    label,
                    id,
                    der,
                    attributes,
                } => ObjectRecord {
                    handle,
                    slot_id,
                    class: ObjectClass::Certificate,
                    label,
                    id,
                    data: ObjectData::Certificate { der, attributes },
                },
                ObjectTemplate::PrivateKey {
                    label,
                    id,
                    key_type,
                    key_reference,
                    key_size_bits,
                    always_authenticate,
                    subject,
                    modulus,
                    public_exponent,
                } => ObjectRecord {
                    handle,
                    slot_id,
                    class: ObjectClass::PrivateKey,
                    label,
                    id,
                    data: ObjectData::PrivateKey {
                        key_type,
                        key_reference,
                        key_size_bits,
                        always_authenticate,
                        subject,
                        modulus,
                        public_exponent,
                    },
                },
            };

            self.objects.insert(handle, record);
            object_handles.push(handle);
            retained_handles.insert(handle);
        }

        for handle in existing_handles {
            if retained_handles.contains(&handle) {
                continue;
            }

            if let Some(record) = self.objects.remove(&handle) {
                self.object_identities
                    .remove(&object_identity_from_record(&record));
            }
        }

        slot.token = Some(Token {
            label: token.label,
            manufacturer: token.manufacturer,
            model: token.model,
            serial_number: token.serial_number,
            login_required: token.login_required,
            mechanisms: token.mechanisms,
            object_handles: object_handles.clone(),
        });

        for session in self.sessions.values_mut() {
            if session.slot_id == slot_id {
                session.find_results.clear();
                session.find_position = 0;
                session.cached_find_template = None;
                session.cached_find_results.clear();
            }
        }

        Ok(object_handles)
    }

    pub fn clear_token(&mut self, slot_id: SlotId) -> Result<(), ProviderError> {
        let slot = self
            .slots
            .get_mut(&slot_id)
            .ok_or(ProviderError::SlotNotFound(slot_id))?;

        if let Some(token) = slot.token.take() {
            for handle in token.object_handles {
                if let Some(record) = self.objects.remove(&handle) {
                    self.object_identities
                        .remove(&object_identity_from_record(&record));
                }
            }
        }

        for session in self.sessions.values_mut() {
            if session.slot_id == slot_id {
                session.state = SessionState::ReadOnlyPublic;
                session.authenticated_pin = None;
                session.active_sign = None;
                session.find_results.clear();
                session.find_position = 0;
                session.cached_find_template = None;
                session.cached_find_results.clear();
            }
        }

        Ok(())
    }

    pub fn open_session(&mut self, slot_id: SlotId) -> Result<SessionHandle, ProviderError> {
        if !self.slots.contains_key(&slot_id) {
            return Err(ProviderError::SlotNotFound(slot_id));
        }

        let logged_in_pin = self
            .slot_token(slot_id)
            .ok()
            .and_then(|token| self.authenticated_pin_for_slot(slot_id, token.login_required));

        let handle = self.next_session_handle;
        self.next_session_handle += 1;
        self.sessions.insert(
            handle,
            Session {
                handle,
                slot_id,
                state: if logged_in_pin.is_some() {
                    SessionState::ReadOnlyUser
                } else {
                    SessionState::ReadOnlyPublic
                },
                authenticated_pin: logged_in_pin,
                active_sign: None,
                find_results: Vec::new(),
                find_position: 0,
                cached_find_template: None,
                cached_find_results: Vec::new(),
            },
        );
        Ok(handle)
    }

    pub fn close_session(&mut self, handle: SessionHandle) -> Result<(), ProviderError> {
        self.sessions
            .remove(&handle)
            .map(|_| ())
            .ok_or(ProviderError::SessionNotFound(handle))
    }

    pub fn login(
        &mut self,
        handle: SessionHandle,
        user_type: UserType,
        pin: String,
    ) -> Result<(), ProviderError> {
        if user_type != UserType::User {
            return Err(ProviderError::UserTypeNotSupported(user_type));
        }

        let slot_id = self
            .sessions
            .get(&handle)
            .ok_or(ProviderError::SessionNotFound(handle))?
            .slot_id;
        self.slot_token(slot_id)?;

        for session in self.sessions.values_mut() {
            if session.slot_id == slot_id {
                session.state = SessionState::ReadOnlyUser;
                session.authenticated_pin = Some(pin.clone());
            }
        }
        Ok(())
    }

    pub fn logout(&mut self, handle: SessionHandle) -> Result<(), ProviderError> {
        let slot_id = self
            .sessions
            .get(&handle)
            .ok_or(ProviderError::SessionNotFound(handle))?
            .slot_id;

        for session in self.sessions.values_mut() {
            if session.slot_id == slot_id {
                session.state = SessionState::ReadOnlyPublic;
                session.authenticated_pin = None;
                session.active_sign = None;
                session.find_results.clear();
                session.find_position = 0;
                session.cached_find_template = None;
                session.cached_find_results.clear();
            }
        }
        Ok(())
    }

    pub fn session_pin(&self, handle: SessionHandle) -> Result<Option<&str>, ProviderError> {
        let session = self
            .sessions
            .get(&handle)
            .ok_or(ProviderError::SessionNotFound(handle))?;
        Ok(session.authenticated_pin.as_deref())
    }

    pub fn list_objects(
        &self,
        handle: SessionHandle,
        class: Option<ObjectClass>,
    ) -> Result<Vec<ObjectHandle>, ProviderError> {
        let session = self
            .sessions
            .get(&handle)
            .ok_or(ProviderError::SessionNotFound(handle))?;
        let token = self.slot_token(session.slot_id)?;

        Ok(token
            .object_handles
            .iter()
            .copied()
            .filter(|handle| {
                class.is_none_or(|class| {
                    self.objects
                        .get(handle)
                        .map(|object| object.class == class)
                        .unwrap_or(false)
                })
            })
            .collect())
    }

    pub fn sign_init(
        &mut self,
        handle: SessionHandle,
        mechanism: Mechanism,
        key_handle: ObjectHandle,
    ) -> Result<(), ProviderError> {
        let (slot_id, state) = {
            let session = self
                .sessions
                .get(&handle)
                .ok_or(ProviderError::SessionNotFound(handle))?;
            (session.slot_id, session.state)
        };
        let token = self.slot_token(slot_id)?;

        if !token.mechanisms.contains(&mechanism) {
            return Err(ProviderError::MechanismNotSupported(mechanism));
        }
        if token.login_required && state != SessionState::ReadOnlyUser {
            return Err(ProviderError::LoginRequired(handle));
        }

        let object = self
            .objects
            .get(&key_handle)
            .ok_or(ProviderError::ObjectNotFound(key_handle))?;

        if object.slot_id != slot_id {
            return Err(ProviderError::ObjectSlotMismatch {
                session: handle,
                slot_id,
                object_handle: key_handle,
                object_slot_id: object.slot_id,
            });
        }
        if object.class != ObjectClass::PrivateKey {
            return Err(ProviderError::ObjectClassMismatch {
                handle: key_handle,
                expected: ObjectClass::PrivateKey,
                actual: object.class,
            });
        }

        let session = self
            .sessions
            .get_mut(&handle)
            .ok_or(ProviderError::SessionNotFound(handle))?;
        session.active_sign = Some(SignContext {
            mechanism,
            key_handle,
        });
        Ok(())
    }

    pub fn active_sign(
        &self,
        handle: SessionHandle,
    ) -> Result<Option<&SignContext>, ProviderError> {
        let session = self
            .sessions
            .get(&handle)
            .ok_or(ProviderError::SessionNotFound(handle))?;
        Ok(session.active_sign.as_ref())
    }

    pub fn take_active_sign(
        &mut self,
        handle: SessionHandle,
    ) -> Result<Option<SignContext>, ProviderError> {
        let session = self
            .sessions
            .get_mut(&handle)
            .ok_or(ProviderError::SessionNotFound(handle))?;
        Ok(session.active_sign.take())
    }

    pub fn clear_sign(&mut self, handle: SessionHandle) -> Result<(), ProviderError> {
        let session = self
            .sessions
            .get_mut(&handle)
            .ok_or(ProviderError::SessionNotFound(handle))?;
        session.active_sign = None;
        Ok(())
    }

    pub fn close_all_sessions(&mut self, slot_id: SlotId) -> Result<(), ProviderError> {
        if !self.slots.contains_key(&slot_id) {
            return Err(ProviderError::SlotNotFound(slot_id));
        }

        self.sessions
            .retain(|_, session| session.slot_id != slot_id);
        Ok(())
    }

    pub fn set_find_results(
        &mut self,
        handle: SessionHandle,
        results: Vec<ObjectHandle>,
    ) -> Result<(), ProviderError> {
        let session = self
            .sessions
            .get_mut(&handle)
            .ok_or(ProviderError::SessionNotFound(handle))?;
        session.find_results = results;
        session.find_position = 0;
        Ok(())
    }

    pub fn cached_find_results(
        &self,
        handle: SessionHandle,
        template: &FindTemplateKey,
    ) -> Result<Option<Vec<ObjectHandle>>, ProviderError> {
        let session = self
            .sessions
            .get(&handle)
            .ok_or(ProviderError::SessionNotFound(handle))?;
        Ok((session.cached_find_template.as_ref() == Some(template))
            .then(|| session.cached_find_results.clone()))
    }

    pub fn cache_find_results(
        &mut self,
        handle: SessionHandle,
        template: FindTemplateKey,
        results: Vec<ObjectHandle>,
    ) -> Result<(), ProviderError> {
        let session = self
            .sessions
            .get_mut(&handle)
            .ok_or(ProviderError::SessionNotFound(handle))?;
        session.cached_find_template = Some(template);
        session.cached_find_results = results;
        Ok(())
    }

    pub fn next_find_results(
        &mut self,
        handle: SessionHandle,
        max_count: usize,
    ) -> Result<Vec<ObjectHandle>, ProviderError> {
        let session = self
            .sessions
            .get_mut(&handle)
            .ok_or(ProviderError::SessionNotFound(handle))?;

        let start = session.find_position;
        let end = (start + max_count).min(session.find_results.len());
        session.find_position = end;
        Ok(session.find_results[start..end].to_vec())
    }

    pub fn clear_find_results(&mut self, handle: SessionHandle) -> Result<(), ProviderError> {
        let session = self
            .sessions
            .get_mut(&handle)
            .ok_or(ProviderError::SessionNotFound(handle))?;
        session.find_results.clear();
        session.find_position = 0;
        Ok(())
    }

    fn remove_slot(&mut self, slot_id: SlotId) {
        if let Some(slot) = self.slots.remove(&slot_id)
            && let Some(token) = slot.token
        {
            for handle in token.object_handles {
                if let Some(record) = self.objects.remove(&handle) {
                    self.object_identities
                        .remove(&object_identity_from_record(&record));
                }
            }
        }

        self.sessions
            .retain(|_, session| session.slot_id != slot_id);
    }

    fn slot_token(&self, slot_id: SlotId) -> Result<&Token, ProviderError> {
        self.slots
            .get(&slot_id)
            .ok_or(ProviderError::SlotNotFound(slot_id))?
            .token
            .as_ref()
            .ok_or(ProviderError::TokenNotPresent(slot_id))
    }

    fn authenticated_pin_for_slot(&self, slot_id: SlotId, login_required: bool) -> Option<String> {
        if !login_required {
            return None;
        }

        self.sessions
            .values()
            .find(|session| {
                session.slot_id == slot_id && session.state == SessionState::ReadOnlyUser
            })
            .and_then(|session| session.authenticated_pin.clone())
    }
}

fn object_identity(slot_id: SlotId, template: &ObjectTemplate) -> ObjectIdentity {
    match template {
        ObjectTemplate::Certificate { id, .. } => ObjectIdentity {
            slot_id,
            class: ObjectClass::Certificate,
            id: id.clone(),
        },
        ObjectTemplate::PrivateKey { id, .. } => ObjectIdentity {
            slot_id,
            class: ObjectClass::PrivateKey,
            id: id.clone(),
        },
    }
}

fn object_identity_from_record(record: &ObjectRecord) -> ObjectIdentity {
    ObjectIdentity {
        slot_id: record.slot_id,
        class: record.class,
        id: record.id.clone(),
    }
}

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
                        let _ = self.provider.clear_token(slot_id);
                    }
                }
            } else {
                match self.inspect_piv_token(&reader_name) {
                    Ok(Some((token, objects))) => {
                        let _ = self.provider.publish_token(slot_id, token, objects);
                    }
                    Ok(None) | Err(_) => {
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
        let runtime = self.runtime_for_io()?;
        let worker = self.worker_for_reader(reader_name)?;
        let response =
            runtime.exchange(select_piv_application(), |command| worker.transmit(command))?;

        if response.status_word() != 0x9000 {
            return Ok(None);
        }

        let select = parse_select_response(&response.data)
            .map_err(|error| SmartcardError::protocol(error.to_string()))?;
        let atr = worker.snapshot().atr.unwrap_or_default();

        let mut objects = Vec::new();
        let mut mechanisms = Vec::new();

        for slot in PRIMARY_CERTIFICATE_SLOTS {
            let response = runtime.exchange(read_certificate_command(slot), |command| {
                worker.transmit(command)
            })?;
            let Some(certificate) = parse_certificate_response(slot, &response)
                .map_err(|error| SmartcardError::protocol(error.to_string()))?
            else {
                continue;
            };
            let attributes = parse_certificate_attributes(&certificate.der)?;

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

            push_unique_mechanism(&mut mechanisms, Mechanism::RsaPkcs);
            push_unique_mechanism(&mut mechanisms, Mechanism::Sha256RsaPkcs);
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
            return Ok(None);
        }
        Ok(Some((
            TokenTemplate {
                label: select.label.unwrap_or_else(|| "PIV Token".to_owned()),
                manufacturer: "smartcard-rs".to_owned(),
                model: "PIV".to_owned(),
                serial_number: token_serial(&atr, reader_name),
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
        Ok(response.status_word() == 0x9000)
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

fn trace_enabled() -> bool {
    static TRACE_ENABLED: OnceLock<bool> = OnceLock::new();
    *TRACE_ENABLED.get_or_init(|| {
        env::var("SMARTCARD_PKCS11_TRACE")
            .map(|value| value != "0")
            .unwrap_or(false)
    })
}

fn trace(message: impl AsRef<str>) {
    if trace_enabled() {
        eprintln!("[smartcard-pkcs11] {}", message.as_ref());
    }
}

fn with_module<T>(f: impl FnOnce(&mut ModuleState) -> Result<T, CkRv>) -> Result<T, CkRv> {
    let mut guard = lifecycle().lock().map_err(|_| CKR_GENERAL_ERROR)?;
    let state = guard.state.as_mut().ok_or(CKR_CRYPTOKI_NOT_INITIALIZED)?;
    f(state)
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
        c_sign_update: None,
        c_sign_final: None,
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

fn token_serial(atr: &[u8], reader_name: &str) -> String {
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

fn hex_upper(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0F) as usize] as char);
    }
    output
}

fn push_unique_mechanism(mechanisms: &mut Vec<Mechanism>, mechanism: Mechanism) {
    if !mechanisms.contains(&mechanism) {
        mechanisms.push(mechanism);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedCertificateAttributes {
    subject: Vec<u8>,
    issuer: Vec<u8>,
    serial_number: Vec<u8>,
    modulus: Option<Vec<u8>>,
    public_exponent: Option<Vec<u8>>,
}

fn parse_certificate_attributes(der: &[u8]) -> Result<ParsedCertificateAttributes, SmartcardError> {
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

fn der_encode_integer(bytes: &[u8]) -> Vec<u8> {
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

fn private_key_descriptor(algorithm: SignAlgorithm) -> Option<(KeyType, usize)> {
    match algorithm {
        SignAlgorithm::Rsa1024 => Some((KeyType::Rsa, 1024)),
        SignAlgorithm::Rsa2048 => Some((KeyType::Rsa, 2048)),
        SignAlgorithm::Rsa3072 => Some((KeyType::Rsa, 3072)),
        SignAlgorithm::Rsa4096 => Some((KeyType::Rsa, 4096)),
        SignAlgorithm::EccP256 | SignAlgorithm::EccP384 => None,
    }
}

fn sign_algorithm_for_private_key(
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

fn ensure_piv_selected(runtime: &SmartcardRuntime, worker: &ReaderWorker) -> Result<(), CkRv> {
    let response = runtime
        .exchange(select_piv_application(), |apdu| worker.transmit(apdu))
        .map_err(map_smartcard_error)?;
    if response.status_word() != 0x9000 {
        return Err(CKR_TOKEN_NOT_PRESENT);
    }
    Ok(())
}

fn map_smartcard_error(error: SmartcardError) -> CkRv {
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

fn map_piv_error(error: PivError) -> CkRv {
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

fn map_provider_error(error: ProviderError) -> CkRv {
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

fn mechanism_from_ck(mechanism: CkMechanismType) -> Result<Mechanism, CkRv> {
    match mechanism {
        CKM_RSA_PKCS => Ok(Mechanism::RsaPkcs),
        CKM_SHA256_RSA_PKCS => Ok(Mechanism::Sha256RsaPkcs),
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

fn ck_mechanism_from_internal(mechanism: Mechanism) -> CkMechanismType {
    match mechanism {
        Mechanism::RsaPkcs => CKM_RSA_PKCS,
        Mechanism::Sha256RsaPkcs => CKM_SHA256_RSA_PKCS,
    }
}

fn certificate_slot_for_key_reference(key_reference: u8) -> Option<CertificateSlot> {
    PRIMARY_CERTIFICATE_SLOTS
        .iter()
        .copied()
        .find(|slot| slot.key_reference == key_reference)
}

fn prepare_raw_rsa_pkcs1_v1_5_input(
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

fn encode_ulong(value: CkUlong) -> Vec<u8> {
    value.to_ne_bytes().to_vec()
}

fn encode_bool(value: bool) -> [u8; 1] {
    [if value { CK_TRUE } else { CK_FALSE }]
}

fn populate_padded(destination: &mut [u8], value: &[u8]) {
    destination.fill(b' ');
    let count = value.len().min(destination.len());
    destination[..count].copy_from_slice(&value[..count]);
}

fn build_find_template_key(attributes: &[CkAttribute]) -> Result<FindTemplateKey, CkRv> {
    let mut predicates = Vec::with_capacity(attributes.len());
    for attribute in attributes {
        predicates.push(FindTemplatePredicate {
            type_: attribute.type_,
            value: unsafe { attribute_value_bytes(attribute)? }.to_vec(),
        });
    }
    Ok(FindTemplateKey(predicates))
}

fn object_matches_template(object: &ObjectRecord, attribute: &CkAttribute) -> Result<bool, CkRv> {
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
            _ => Ok(false),
        },
        CKA_SERIAL_NUMBER => match &object.data {
            ObjectData::Certificate { attributes, .. } => {
                Ok(value == attributes.serial_number.as_slice())
            }
            _ => Ok(false),
        },
        CKA_KEY_TYPE => match &object.data {
            ObjectData::PrivateKey { key_type, .. } => {
                Ok(parse_ulong(value)? == key_type_value(*key_type))
            }
            _ => Ok(false),
        },
        CKA_SUBJECT => match &object.data {
            ObjectData::Certificate { attributes, .. } => {
                Ok(value == attributes.subject.as_slice())
            }
            ObjectData::PrivateKey { subject, .. } => Ok(value == subject.as_slice()),
        },
        CKA_SIGN => match object.class {
            ObjectClass::PrivateKey => Ok(parse_bool(value)?),
            _ => Ok(false),
        },
        CKA_MODULUS => match &object.data {
            ObjectData::PrivateKey {
                modulus: Some(modulus),
                ..
            } => Ok(value == modulus.as_slice()),
            _ => Ok(false),
        },
        CKA_MODULUS_BITS => match &object.data {
            ObjectData::PrivateKey {
                key_type: KeyType::Rsa,
                key_size_bits,
                ..
            } => Ok(parse_ulong(value)? == *key_size_bits as CkUlong),
            _ => Ok(false),
        },
        CKA_PUBLIC_EXPONENT => match &object.data {
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

fn object_class_value(class: ObjectClass) -> CkObjectClass {
    match class {
        ObjectClass::Certificate => CKO_CERTIFICATE,
        ObjectClass::PrivateKey => CKO_PRIVATE_KEY,
    }
}

fn key_type_value(key_type: KeyType) -> CkKeyType {
    match key_type {
        KeyType::Rsa => CKK_RSA,
        KeyType::Ec => CKK_EC,
    }
}

unsafe fn write_attribute(attribute: &mut CkAttribute, value: &[u8], rv: &mut CkRv) {
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

unsafe fn read_bytes<'a>(pointer: *const u8, len: CkUlong) -> Result<&'a [u8], CkRv> {
    if len == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    Ok(unsafe { slice::from_raw_parts(pointer, len as usize) })
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
            flags: CKF_REMOVABLE_DEVICE,
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
        let template_key = build_find_template_key(attributes)?;

        if let Some(results) = module
            .provider
            .cached_find_results(session as SessionHandle, &template_key)
            .map_err(map_provider_error)?
        {
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
                    ObjectData::PrivateKey { .. } => {
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
                CKA_ISSUER => match &object.data {
                    ObjectData::Certificate { attributes, .. } => unsafe {
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
                    ObjectData::PrivateKey { subject, .. } => unsafe {
                        write_attribute(attribute, subject, &mut rv);
                    },
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
                CKA_MODULUS => match &object.data {
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
                _ => {
                    attribute.ul_value_len = CK_UNAVAILABLE_INFORMATION;
                    if rv == CKR_OK {
                        rv = CKR_ATTRIBUTE_TYPE_INVALID;
                    }
                }
            }
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
        if mechanism.ul_parameter_len != 0 || !mechanism.p_parameter.is_null() {
            return Err(CKR_MECHANISM_PARAM_INVALID);
        }

        let mechanism = mechanism_from_ck(mechanism.mechanism)?;
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

    trace(format!(
        "C_Sign session={session} data_len={data_len} signature_ptr_null={} requested_sig_len={}",
        signature.is_null(),
        unsafe { *signature_len }
    ));
    let started = Instant::now();
    let input = match unsafe { read_bytes(data.cast::<u8>(), data_len) } {
        Ok(bytes) => bytes,
        Err(rv) => return rv,
    };

    match with_module(|module| {
        let active_sign = module
            .provider
            .active_sign(session as SessionHandle)
            .map_err(map_provider_error)?
            .cloned()
            .ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        let session_ref = module
            .provider
            .session(session as SessionHandle)
            .ok_or(CKR_SESSION_HANDLE_INVALID)?;
        let pin = module
            .provider
            .session_pin(session as SessionHandle)
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
            ObjectData::PrivateKey {
                key_type,
                key_reference,
                key_size_bits,
                ..
            } => (key_reference, key_type, key_size_bits),
            ObjectData::Certificate { .. } => return Err(CKR_KEY_HANDLE_INVALID),
        };
        let algorithm = sign_algorithm_for_private_key(key_type, key_size_bits)
            .ok_or(CKR_KEY_TYPE_INCONSISTENT)?;

        let expected_len = (key_size_bits / 8) as CkUlong;
        let caller_len = unsafe { *signature_len };
        if signature.is_null() {
            unsafe { ptr::write(signature_len, expected_len) };
            trace(format!(
                "C_Sign session={session} length_query expected_len={} elapsed_ms={}",
                expected_len,
                started.elapsed().as_millis()
            ));
            return Ok(());
        }
        if caller_len < expected_len {
            unsafe { ptr::write(signature_len, expected_len) };
            return Err(CKR_BUFFER_TOO_SMALL);
        }

        let certificate_slot =
            certificate_slot_for_key_reference(key_reference).ok_or(CKR_KEY_HANDLE_INVALID)?;
        let signature_bytes = module.sign_with_piv(
            &reader_name,
            certificate_slot,
            algorithm,
            active_sign.mechanism,
            input,
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
            .clear_sign(session as SessionHandle)
            .map_err(map_provider_error)?;
        trace(format!(
            "C_Sign session={session} key_ref={:02X} signature_len={} elapsed_ms={}",
            key_reference,
            signature_bytes.len(),
            started.elapsed().as_millis()
        ));
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

#[cfg(test)]
mod tests {
    use super::{
        CertificateAttributes, FindTemplateKey, FindTemplatePredicate, KeyType, Mechanism,
        ObjectClass, ObjectData, ObjectRecord, ObjectTemplate, Provider, ProviderConfig,
        ProviderError, ProviderStatus, SessionState, TokenTemplate, UserType, der_encode_integer,
        encode_bool, encode_ulong, object_matches_template, parse_certificate_attributes,
    };
    use crate::abi::{
        CKA_CERTIFICATE_TYPE, CKA_CLASS, CKA_ID, CKA_ISSUER, CKA_MODULUS, CKA_PUBLIC_EXPONENT,
        CKA_SERIAL_NUMBER, CKA_SIGN, CKA_SUBJECT, CKA_TOKEN, CKC_X_509, CKO_CERTIFICATE,
    };
    use smartcard_core::{ReaderHealth, ReaderInfo};

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
            mechanisms: vec![Mechanism::RsaPkcs, Mechanism::Sha256RsaPkcs],
        }
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
    fn find_result_cache_is_reused_for_identical_templates() {
        let mut provider = Provider::new(ProviderConfig::default());
        provider.sync_readers(&[reader("Reader A")]);
        let slot_id = provider.slot_for_reader("Reader A").unwrap();
        provider
            .publish_token(
                slot_id,
                token_template(),
                [
                    ObjectTemplate::certificate(
                        "PIV Authentication",
                        [0x9A],
                        sample_certificate_der(),
                    ),
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
}
