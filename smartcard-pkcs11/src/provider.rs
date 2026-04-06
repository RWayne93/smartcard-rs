use std::collections::{BTreeMap, HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::time::Duration;

use smartcard_core::ReaderInfo;

use crate::abi::CkAttributeType;

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
    RsaPkcsPss,
    Sha256RsaPkcs,
    Sha256RsaPkcsPss,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObjectClass {
    Certificate,
    PublicKey,
    PrivateKey,
    Trust,
    Profile,
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
pub struct TrustAttributes {
    pub issuer: Vec<u8>,
    pub serial_number: Vec<u8>,
    pub sha1_hash: Vec<u8>,
    pub md5_hash: Vec<u8>,
    pub trust_level: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectData {
    Certificate {
        der: Vec<u8>,
        attributes: CertificateAttributes,
    },
    PublicKey {
        key_type: KeyType,
        key_size_bits: usize,
        subject: Vec<u8>,
        modulus: Option<Vec<u8>>,
        public_exponent: Option<Vec<u8>>,
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
    Trust {
        attributes: TrustAttributes,
    },
    Profile {
        profile_id: u64,
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
    PublicKey {
        label: String,
        id: Vec<u8>,
        key_type: KeyType,
        key_size_bits: usize,
        subject: Vec<u8>,
        modulus: Option<Vec<u8>>,
        public_exponent: Option<Vec<u8>>,
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
    Trust {
        label: String,
        id: Vec<u8>,
        attributes: TrustAttributes,
    },
    Profile {
        label: String,
        id: Vec<u8>,
        profile_id: u64,
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

    pub fn public_key_with_attributes(
        label: impl Into<String>,
        id: impl Into<Vec<u8>>,
        key_type: KeyType,
        key_size_bits: usize,
        subject: Vec<u8>,
        modulus: Option<Vec<u8>>,
        public_exponent: Option<Vec<u8>>,
    ) -> Self {
        Self::PublicKey {
            label: label.into(),
            id: id.into(),
            key_type,
            key_size_bits,
            subject,
            modulus,
            public_exponent,
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

    pub fn trust(
        label: impl Into<String>,
        id: impl Into<Vec<u8>>,
        attributes: TrustAttributes,
    ) -> Self {
        Self::Trust {
            label: label.into(),
            id: id.into(),
            attributes,
        }
    }

    pub fn profile(label: impl Into<String>, id: impl Into<Vec<u8>>, profile_id: u64) -> Self {
        Self::Profile {
            label: label.into(),
            id: id.into(),
            profile_id,
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
    pub data: Vec<u8>,
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
    pub(crate) config: ProviderConfig,
    slots: BTreeMap<SlotId, Slot>,
    objects: HashMap<ObjectHandle, ObjectRecord>,
    object_identities: HashMap<ObjectIdentity, ObjectHandle>,
    reader_slots: HashMap<String, SlotId>,
    pub(crate) sessions: HashMap<SessionHandle, Session>,
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
            sign: vec![
                Mechanism::RsaPkcs,
                Mechanism::Sha256RsaPkcs,
                Mechanism::Sha256RsaPkcsPss,
            ],
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
                ObjectTemplate::PublicKey {
                    label,
                    id,
                    key_type,
                    key_size_bits,
                    subject,
                    modulus,
                    public_exponent,
                } => ObjectRecord {
                    handle,
                    slot_id,
                    class: ObjectClass::PublicKey,
                    label,
                    id,
                    data: ObjectData::PublicKey {
                        key_type,
                        key_size_bits,
                        subject,
                        modulus,
                        public_exponent,
                    },
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
                ObjectTemplate::Trust {
                    label,
                    id,
                    attributes,
                } => ObjectRecord {
                    handle,
                    slot_id,
                    class: ObjectClass::Trust,
                    label,
                    id,
                    data: ObjectData::Trust { attributes },
                },
                ObjectTemplate::Profile {
                    label,
                    id,
                    profile_id,
                } => ObjectRecord {
                    handle,
                    slot_id,
                    class: ObjectClass::Profile,
                    label,
                    id,
                    data: ObjectData::Profile { profile_id },
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
            data: Vec::new(),
        });
        Ok(())
    }

    pub fn append_sign_data(
        &mut self,
        handle: SessionHandle,
        data: &[u8],
    ) -> Result<bool, ProviderError> {
        let session = self
            .sessions
            .get_mut(&handle)
            .ok_or(ProviderError::SessionNotFound(handle))?;
        let Some(active_sign) = session.active_sign.as_mut() else {
            return Ok(false);
        };
        active_sign.data.extend_from_slice(data);
        Ok(true)
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
        ObjectTemplate::PublicKey { id, .. } => ObjectIdentity {
            slot_id,
            class: ObjectClass::PublicKey,
            id: id.clone(),
        },
        ObjectTemplate::PrivateKey { id, .. } => ObjectIdentity {
            slot_id,
            class: ObjectClass::PrivateKey,
            id: id.clone(),
        },
        ObjectTemplate::Trust { id, .. } => ObjectIdentity {
            slot_id,
            class: ObjectClass::Trust,
            id: id.clone(),
        },
        ObjectTemplate::Profile { id, .. } => ObjectIdentity {
            slot_id,
            class: ObjectClass::Profile,
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
