// IdP identity database: NameID generation and management
// (pysaml2 `IdentDB` equivalent).
//
// Maintains the bidirectional mapping between local user ids and the
// NameIDs issued to relying parties, generates transient/persistent
// NameIDs honoring an incoming `NameIDPolicy`, and implements the server
// side of the ManageNameID and NameIDMapping profiles on top of it.
//
// Transient NameIDs are minted fresh on every issuance and, by default, are
// *not* persisted to the store: per SAML Core §8.3.7 a transient identifier is
// one-time-use and MUST NOT be reused, so it has no reverse-lookup need in the
// SSO flow. Persisting them would grow the identity store without bound (the
// default per-SP format is transient, so every response would add an entry
// that is never read back). Persistent and other durable formats are stored.
// A deployment whose back-channel logout must resolve a transient NameID to its
// user opts in with `IdentDb::with_persist_transient`.
//
// The storage backend is pluggable via `IdentityStore`; the in-memory
// implementation suits single-instance deployments and tests.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::core::assertion::name_id::{NameId, NameIdPolicy};
use crate::core::constants;
use crate::core::protocol::name_id_mgmt::NewIdOrTerminate;
use crate::crypto::digest::sha256;

/// Errors from identity-database operations.
#[derive(Debug, thiserror::Error)]
pub enum IdentError {
    /// The NameID is not associated with any local principal.
    #[error("unknown NameID: no local principal for '{0}'")]
    UnknownNameId(String),

    /// The NameIDPolicy forbids creating a new identifier (AllowCreate).
    #[error("NameIDPolicy does not allow creating a new identifier")]
    CreateNotAllowed,

    /// No NameID format could be determined.
    #[error("no NameID format requested and no default configured")]
    NoFormat,

    /// The operation is not supported (e.g. NewEncryptedID).
    #[error("unsupported operation: {0}")]
    Unsupported(&'static str),

    /// The storage backend failed. This is an operational fault, not a
    /// refusal: callers must not turn it into a protocol denial.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// A storage backend failed (connection lost, timeout, query error, ...).
///
/// Distinct from a *conflict*: a NameID value that is already taken is an
/// expected outcome of the uniqueness constraints and is reported as
/// [`InsertError::ValueTaken`], which callers retry with a fresh value. A
/// `StoreError` is never retried blindly; it means the store could not answer,
/// and treating it as "not found" would, for example, mint a second
/// "stable" persistent identifier for a user who already has one.
#[derive(Debug, thiserror::Error)]
#[error("store backend error: {0}")]
pub struct StoreError(#[source] pub Box<dyn std::error::Error + Send + Sync>);

impl StoreError {
    /// Wrap a backend error.
    pub fn new(source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        StoreError(source.into())
    }
}

/// Why an insert into an [`IdentityStore`] did not happen.
#[derive(Debug, thiserror::Error)]
pub enum InsertError {
    /// The NameID value is already in use by another record.
    #[error("NameID value already in use")]
    ValueTaken,
    /// The backend failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Criteria for [`IdentityStore::find`] (pysaml2 `IdentDB.find_nameid`).
///
/// A `None` field matches any record. A `Some` field requires the record's
/// field to equal it exactly, so a record that lacks the field does not match.
/// This differs from [`IdentityStore::find_persistent`], where a `None`
/// qualifier means "the record has no such qualifier".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameIdFilter {
    /// Required NameID format.
    pub format: Option<String>,
    /// Required `SPNameQualifier`.
    pub sp_name_qualifier: Option<String>,
    /// Required `NameQualifier`.
    pub name_qualifier: Option<String>,
    /// Required `SPProvidedID`.
    pub sp_provided_id: Option<String>,
}

impl NameIdFilter {
    /// Whether `name_id` satisfies every field that is set.
    pub fn matches(&self, name_id: &NameId) -> bool {
        fn ok(wanted: &Option<String>, actual: &Option<String>) -> bool {
            wanted
                .as_deref()
                .is_none_or(|w| actual.as_deref() == Some(w))
        }
        ok(&self.format, &name_id.format)
            && ok(&self.sp_name_qualifier, &name_id.sp_name_qualifier)
            && ok(&self.name_qualifier, &name_id.name_qualifier)
            && ok(&self.sp_provided_id, &name_id.sp_provided_id)
    }
}

/// Plain key/value backend.
///
/// Used where a mapping needs no cross-record atomicity, such as
/// [`Eptid`](crate::idp::Eptid)'s deterministic eduPersonTargetedID cache.
/// NameID storage needs stronger guarantees and uses [`IdentityStore`].
pub trait KeyValueStore: Send + Sync {
    /// Fetch a value.
    fn get(&self, key: &str) -> Result<Option<String>, StoreError>;
    /// Store a value.
    fn set(&self, key: &str, value: String) -> Result<(), StoreError>;
    /// Remove a value.
    fn remove(&self, key: &str) -> Result<(), StoreError>;
}

/// In-memory [`KeyValueStore`].
#[derive(Debug, Default)]
pub struct InMemoryKeyValueStore {
    map: Mutex<HashMap<String, String>>,
}

impl InMemoryKeyValueStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyValueStore for InMemoryKeyValueStore {
    fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
        Ok(self.map.lock().unwrap().get(key).cloned())
    }

    fn set(&self, key: &str, value: String) -> Result<(), StoreError> {
        self.map.lock().unwrap().insert(key.to_string(), value);
        Ok(())
    }

    fn remove(&self, key: &str) -> Result<(), StoreError> {
        self.map.lock().unwrap().remove(key);
        Ok(())
    }
}

/// Pluggable backend for [`IdentDb`]: one record per (user, NameID)
/// association.
///
/// Implement this over your database (Mongo, SQL, ...). Each method is a
/// single-record operation, so there is nothing to coordinate across keys or
/// documents: atomicity comes from two uniqueness constraints the backend
/// must enforce.
///
/// * the NameID **value** is unique across all records, and
/// * among **persistent** records, `(user, sp_name_qualifier,
///   name_qualifier)` is unique.
///
/// Without them, two concurrent first requests for the same (user, SP) can
/// both insert and mint two different "stable" persistent identifiers, and
/// nothing in this crate can detect it - they must be real constraints in
/// the store (a unique index, a `UNIQUE` constraint), not application-level
/// checks. Run [`conformance`] against a real instance to check a backend.
///
/// There are deliberately no default write methods: a non-atomic default
/// would silently leave those races open on a multi-instance deployment.
///
/// Every method is fallible. A backend that cannot answer must return
/// [`StoreError`], never an empty result: "no record" and "could not look"
/// are different answers, and conflating them would mint a second persistent
/// identifier for a user who already has one.
pub trait IdentityStore: Send + Sync {
    /// Every NameID associated with `user_id`, in unspecified order.
    fn for_user(&self, user_id: &str) -> Result<Vec<NameId>, StoreError>;

    /// The user a NameID value belongs to.
    fn user_for(&self, value: &str) -> Result<Option<String>, StoreError>;

    /// Every NameID of `user_id` that satisfies `filter`, in unspecified order
    /// (pysaml2 `find_nameid`). Overridable to push the filter down to an
    /// index or query; the default filters [`for_user`](Self::for_user).
    fn find(&self, user_id: &str, filter: &NameIdFilter) -> Result<Vec<NameId>, StoreError> {
        Ok(self
            .for_user(user_id)?
            .into_iter()
            .filter(|n| filter.matches(n))
            .collect())
    }

    /// The user's persistent NameID for `(sp_name_qualifier,
    /// name_qualifier)`, if one exists. `None` for a qualifier means the
    /// record has no such qualifier. Overridable to push the lookup down to
    /// an index; the default filters [`for_user`](Self::for_user).
    fn find_persistent(
        &self,
        user_id: &str,
        sp_name_qualifier: Option<&str>,
        name_qualifier: Option<&str>,
    ) -> Result<Option<NameId>, StoreError> {
        Ok(self
            .for_user(user_id)?
            .into_iter()
            .find(|n| is_persistent_match(n, sp_name_qualifier, name_qualifier)))
    }

    /// Atomically return the user's existing persistent NameID with the same
    /// `(sp_name_qualifier, name_qualifier)` as `candidate`, or insert
    /// `candidate` and return it. `Err(InsertError::ValueTaken)` if the record
    /// would be inserted but its value is already in use.
    fn get_or_insert_persistent(
        &self,
        user_id: &str,
        candidate: NameId,
    ) -> Result<NameId, InsertError>;

    /// Insert a freshly minted NameID. `Err(InsertError::ValueTaken)` if any
    /// record already has this value.
    fn insert(&self, user_id: &str, name_id: NameId) -> Result<(), InsertError>;

    /// Insert or overwrite the record with this value, assigning it to
    /// `user_id`. Used to update an existing association (e.g. a
    /// ManageNameID `NewID`). Callers must not use it to create a second
    /// persistent record for a `(user, sp_name_qualifier, name_qualifier)`
    /// that already has one.
    fn replace(&self, user_id: &str, name_id: NameId) -> Result<(), StoreError>;

    /// Remove the record with this value, if any.
    fn remove(&self, value: &str) -> Result<(), StoreError>;

    /// Remove every record belonging to `user_id`.
    fn remove_all(&self, user_id: &str) -> Result<(), StoreError>;
}

/// Whether `nid` is a persistent NameID with exactly these qualifiers
/// (`None` matching only a record that has no such qualifier).
pub(crate) fn is_persistent_match(
    nid: &NameId,
    sp_name_qualifier: Option<&str>,
    name_qualifier: Option<&str>,
) -> bool {
    nid.format.as_deref() == Some(constants::NAMEID_PERSISTENT)
        && nid.sp_name_qualifier.as_deref() == sp_name_qualifier
        && nid.name_qualifier.as_deref() == name_qualifier
}

/// In-memory [`IdentityStore`] for tests, examples and single-instance
/// deployments. Every method takes one lock, so atomicity is trivial; lookups
/// are linear scans, which a real backend replaces with indexes.
#[derive(Debug, Default)]
pub struct InMemoryIdentityStore {
    records: Mutex<Vec<(String, NameId)>>,
}

impl InMemoryIdentityStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl IdentityStore for InMemoryIdentityStore {
    fn for_user(&self, user_id: &str) -> Result<Vec<NameId>, StoreError> {
        let records = self.records.lock().unwrap();
        Ok(records
            .iter()
            .filter(|(user, _)| user == user_id)
            .map(|(_, nid)| nid.clone())
            .collect())
    }

    fn user_for(&self, value: &str) -> Result<Option<String>, StoreError> {
        let records = self.records.lock().unwrap();
        Ok(records
            .iter()
            .find(|(_, nid)| nid.value == value)
            .map(|(user, _)| user.clone()))
    }

    fn get_or_insert_persistent(
        &self,
        user_id: &str,
        candidate: NameId,
    ) -> Result<NameId, InsertError> {
        let mut records = self.records.lock().unwrap();
        if let Some((_, existing)) = records.iter().find(|(user, nid)| {
            user == user_id
                && is_persistent_match(
                    nid,
                    candidate.sp_name_qualifier.as_deref(),
                    candidate.name_qualifier.as_deref(),
                )
        }) {
            return Ok(existing.clone());
        }
        if records.iter().any(|(_, nid)| nid.value == candidate.value) {
            return Err(InsertError::ValueTaken);
        }
        records.push((user_id.to_string(), candidate.clone()));
        Ok(candidate)
    }

    fn insert(&self, user_id: &str, name_id: NameId) -> Result<(), InsertError> {
        let mut records = self.records.lock().unwrap();
        if records.iter().any(|(_, nid)| nid.value == name_id.value) {
            return Err(InsertError::ValueTaken);
        }
        records.push((user_id.to_string(), name_id));
        Ok(())
    }

    fn replace(&self, user_id: &str, name_id: NameId) -> Result<(), StoreError> {
        let mut records = self.records.lock().unwrap();
        match records
            .iter_mut()
            .find(|(_, nid)| nid.value == name_id.value)
        {
            Some(slot) => *slot = (user_id.to_string(), name_id),
            None => records.push((user_id.to_string(), name_id)),
        }
        Ok(())
    }

    fn remove(&self, value: &str) -> Result<(), StoreError> {
        self.records
            .lock()
            .unwrap()
            .retain(|(_, nid)| nid.value != value);
        Ok(())
    }

    fn remove_all(&self, user_id: &str) -> Result<(), StoreError> {
        self.records
            .lock()
            .unwrap()
            .retain(|(user, _)| user != user_id);
        Ok(())
    }
}

// ── NameID coding (pysaml2 `code()` / `decode()`) ──────────────────────────

const CODE_FIELDS: usize = 5;

fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '%' => out.push_str("%25"),
            ' ' => out.push_str("%20"),
            ',' => out.push_str("%2C"),
            '=' => out.push_str("%3D"),
            _ => out.push(c),
        }
    }
    out
}

fn unquote(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();

    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }

        let Some(a) = chars.next() else {
            out.push('%');
            break;
        };
        let Some(b) = chars.next() else {
            out.push('%');
            out.push(a);
            break;
        };

        match (a.to_ascii_uppercase(), b.to_ascii_uppercase()) {
            ('2', '0') => out.push(' '),
            ('2', '5') => out.push('%'),
            ('2', 'C') => out.push(','),
            ('3', 'D') => out.push('='),
            _ => {
                out.push('%');
                out.push(a);
                out.push(b);
            }
        }
    }

    out
}

/// Serialize a NameID into the compact storage form
/// (`index=value` pairs, comma separated; pysaml2-compatible field order).
pub fn code_name_id(name_id: &NameId) -> String {
    let fields: [Option<&str>; CODE_FIELDS] = [
        name_id.name_qualifier.as_deref(),
        name_id.sp_name_qualifier.as_deref(),
        name_id.format.as_deref(),
        name_id.sp_provided_id.as_deref(),
        Some(name_id.value.as_str()),
    ];
    fields
        .iter()
        .enumerate()
        .filter_map(|(i, v)| {
            v.filter(|v| !v.is_empty())
                .map(|v| format!("{i}={}", quote(v)))
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Parse the compact storage form back into a NameID.
pub fn decode_name_id(coded: &str) -> NameId {
    let mut fields: [Option<String>; CODE_FIELDS] = Default::default();
    for part in coded.split(',') {
        if let Some((idx, value)) = part.split_once('=') {
            if let Ok(i) = idx.parse::<usize>() {
                if i < CODE_FIELDS {
                    fields[i] = Some(unquote(value));
                }
            }
        }
    }
    let [name_qualifier, sp_name_qualifier, format, sp_provided_id, value] = fields;
    NameId {
        value: value.unwrap_or_default(),
        format,
        name_qualifier,
        sp_name_qualifier,
        sp_provided_id,
    }
}

// ── IdentDb ─────────────────────────────────────────────────────────────────

/// The identity database (pysaml2 `IdentDB`).
pub struct IdentDb<S: IdentityStore = InMemoryIdentityStore> {
    store: S,
    /// The IdP entity ID, used as the default NameQualifier.
    name_qualifier: String,
    /// Domain appended to generated email-format NameIDs.
    domain: Option<String>,
    /// Also store transient NameIDs (off by default; see
    /// [`with_persist_transient`](Self::with_persist_transient)).
    persist_transient: bool,
}

impl IdentDb<InMemoryIdentityStore> {
    /// Create an in-memory identity database.
    pub fn in_memory(idp_entity_id: impl Into<String>) -> Self {
        IdentDb::new(InMemoryIdentityStore::new(), idp_entity_id)
    }
}

impl<S: IdentityStore> IdentDb<S> {
    /// Create an identity database over a custom store.
    pub fn new(store: S, idp_entity_id: impl Into<String>) -> Self {
        IdentDb {
            store,
            name_qualifier: idp_entity_id.into(),
            domain: None,
            persist_transient: false,
        }
    }

    /// Set the domain used for email-format NameIDs.
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Also store transient NameIDs (default: off).
    ///
    /// By default a transient NameID is minted and returned without being
    /// stored. It is one-time-use (SAML Core §8.3.7) and the default per-SP
    /// format is transient, so storing every one would grow the store without
    /// bound. The cost of that default is that
    /// [`find_local_id`](Self::find_local_id) cannot resolve a transient
    /// NameID, which a back-channel (SOAP) LogoutRequest carrying one needs in
    /// order to find the user.
    ///
    /// Turning this on makes each transient NameID a record, so it resolves.
    /// Three consequences:
    ///
    /// - The record trait has no expiry. A transient record is useless once
    ///   its session ends, so the backend must expire them (a TTL index, a
    ///   periodic purge), or the store grows by one record per response.
    /// - Issuing a transient NameID then needs the store to be reachable.
    /// - A stored transient is still one-time-use: a NameIDMapping request
    ///   never reuses one.
    pub fn with_persist_transient(mut self, persist: bool) -> Self {
        self.persist_transient = persist;
        self
    }

    /// The NameIDs stored for a local user that satisfy `filter` (pysaml2
    /// `find_nameid()`).
    pub fn find_nameid(
        &self,
        user_id: &str,
        filter: &NameIdFilter,
    ) -> Result<Vec<NameId>, StoreError> {
        self.store.find(user_id, filter)
    }

    /// All NameIDs stored for a local user.
    pub fn name_ids_for(&self, user_id: &str) -> Result<Vec<NameId>, StoreError> {
        self.store.for_user(user_id)
    }

    /// Associate a NameID with a local user (pysaml2 `store()`), replacing
    /// any record that already has the same value.
    pub fn store(&self, user_id: &str, name_id: &NameId) -> Result<(), StoreError> {
        self.store.replace(user_id, name_id.clone())
    }

    /// The local user a NameID was issued to (pysaml2 `find_local_id()`).
    pub fn find_local_id(&self, name_id: &NameId) -> Result<Option<String>, StoreError> {
        self.store.user_for(&name_id.value)
    }

    /// Find an existing *persistent* NameID for (user, SP, IdP) (pysaml2
    /// `IdentMDB.match_local_id()` — the production Mongo-backed store eduID
    /// runs, which filters on `name_id.format == NAMEID_FORMAT_PERSISTENT`
    /// explicitly, not pysaml2's looser shelve-backed base `IdentDB`, which
    /// merely excludes transient).
    ///
    /// Matching on "not transient" instead of "is persistent" would return
    /// any other previously-issued non-transient NameID for this (user, SP,
    /// IdP) — e.g. an `email`-format one — labeled with *that* format, not
    /// persistent, even though the caller asked for a persistent identifier.
    pub fn match_local_id(
        &self,
        user_id: &str,
        sp_name_qualifier: Option<&str>,
        name_qualifier: Option<&str>,
    ) -> Result<Option<NameId>, StoreError> {
        self.store
            .find_persistent(user_id, sp_name_qualifier, name_qualifier)
    }

    /// Generate a fresh opaque identifier value (pysaml2 `create_id()`).
    ///
    /// The free-check here is only an optimisation: the store's `insert` /
    /// `get_or_insert_persistent` enforce value uniqueness atomically, and a
    /// collision that slips in between is retried by the caller. It is skipped
    /// (`check_free = false`) for identifiers that are never stored, so issuing
    /// one does not depend on the store being reachable.
    fn create_id(
        &self,
        format: &str,
        name_qualifier: Option<&str>,
        sp_name_qualifier: Option<&str>,
        check_free: bool,
    ) -> Result<String, StoreError> {
        loop {
            let mut seed = [0u8; 32];
            rand::fill(&mut seed);
            let mut input = seed.to_vec();
            input.extend_from_slice(format.as_bytes());
            input.extend_from_slice(name_qualifier.unwrap_or("").as_bytes());
            input.extend_from_slice(sp_name_qualifier.unwrap_or("").as_bytes());
            let digest = sha256(&input).expect("SHA-256 is always available");
            let id = to_hex(&digest);
            // Build the final stored value (email format appends `@domain`)
            // *before* the collision check, so the check tests the value
            // that is actually stored.
            let value = if format == constants::NAMEID_EMAIL {
                let domain = self.domain.as_deref().unwrap_or("idp.example.org");
                format!("{id}@{domain}")
            } else {
                id
            };
            if !check_free || self.store.user_for(&value)?.is_none() {
                return Ok(value);
            }
        }
    }

    /// Create a new NameID of the given format (pysaml2 `get_nameid()`);
    /// persistent format reuses an existing association when one exists.
    ///
    /// Transient identifiers are minted fresh and, unless
    /// [`with_persist_transient`](Self::with_persist_transient) is set,
    /// returned *without* being
    /// stored: they are one-time-use (SAML Core §8.3.7) and never need a
    /// reverse lookup, so persisting them would only grow the store without
    /// bound (the default per-SP format is transient, so every response
    /// would otherwise add an entry that is never read back). All other
    /// formats are stored so they can be looked up and reused. The rule is
    /// "persist iff the identifier is ever reverse-looked-up or reused"; if a
    /// future one-time-use format is added, generalize the transient check
    /// to a set of non-persisted formats.
    pub fn get_nameid(
        &self,
        user_id: &str,
        format: &str,
        sp_name_qualifier: Option<&str>,
        name_qualifier: Option<&str>,
    ) -> Result<NameId, StoreError> {
        // Persistent identifiers must stay stable per (user, SP): reuse an
        // existing association instead of minting a new value (E78). The
        // read is the fast path for a returning user; the atomic
        // get-or-insert below is what makes two concurrent *first* requests
        // converge on one identifier.
        if format == constants::NAMEID_PERSISTENT {
            if let Some(existing) =
                self.store
                    .find_persistent(user_id, sp_name_qualifier, name_qualifier)?
            {
                return Ok(existing);
            }
        }

        let stored = format != constants::NAMEID_TRANSIENT || self.persist_transient;
        loop {
            let value = self.create_id(format, name_qualifier, sp_name_qualifier, stored)?;
            let name_id = NameId {
                value,
                format: Some(format.to_string()),
                name_qualifier: name_qualifier.map(str::to_string),
                sp_name_qualifier: sp_name_qualifier.map(str::to_string),
                sp_provided_id: None,
            };

            if format == constants::NAMEID_PERSISTENT {
                match self.store.get_or_insert_persistent(user_id, name_id) {
                    Ok(winner) => return Ok(winner),
                    Err(InsertError::ValueTaken) => continue,
                    Err(InsertError::Store(e)) => return Err(e),
                }
            }
            if !stored {
                return Ok(name_id);
            }
            match self.store.insert(user_id, name_id.clone()) {
                Ok(()) => return Ok(name_id),
                Err(InsertError::ValueTaken) => continue,
                Err(InsertError::Store(e)) => return Err(e),
            }
        }
    }

    /// Generate a transient NameID (pysaml2 `transient_nameid()`).
    pub fn transient_nameid(
        &self,
        user_id: &str,
        sp_name_qualifier: Option<&str>,
    ) -> Result<NameId, StoreError> {
        self.get_nameid(
            user_id,
            constants::NAMEID_TRANSIENT,
            sp_name_qualifier,
            Some(self.name_qualifier.as_str()),
        )
    }

    /// Get-or-create a persistent NameID (pysaml2 `persistent_nameid()`).
    pub fn persistent_nameid(
        &self,
        user_id: &str,
        sp_name_qualifier: Option<&str>,
    ) -> Result<NameId, StoreError> {
        self.get_nameid(
            user_id,
            constants::NAMEID_PERSISTENT,
            sp_name_qualifier,
            Some(self.name_qualifier.as_str()),
        )
    }

    /// Construct a NameID for `user_id` honoring the request's
    /// `NameIDPolicy` (pysaml2 `construct_nameid()`).
    ///
    /// - Format: `NameIDPolicy/@Format`, else `default_format` (typically
    ///   from the [release policy](crate::idp::policy::ReleasePolicy)).
    /// - SPNameQualifier: `NameIDPolicy/@SPNameQualifier`, else the SP
    ///   entity ID.
    /// - NameQualifier: this IdP's entity ID.
    /// - AllowCreate (E14): when an explicit `NameIDPolicy` sets it to false,
    ///   only an existing identifier may be returned for the persistent
    ///   format. A request with *no* `NameIDPolicy` at all does not impose
    ///   that constraint - the IdP's configured default format applies and the
    ///   IdP is permitted to mint it.
    pub fn construct_nameid(
        &self,
        user_id: &str,
        sp_entity_id: &str,
        name_id_policy: Option<&NameIdPolicy>,
        default_format: Option<&str>,
    ) -> Result<NameId, IdentError> {
        let format = name_id_policy
            .and_then(|p| p.format.as_deref())
            .or(default_format)
            .ok_or(IdentError::NoFormat)?;
        let sp_name_qualifier = name_id_policy
            .and_then(|p| p.sp_name_qualifier.as_deref())
            .unwrap_or(sp_entity_id);

        if format == constants::NAMEID_PERSISTENT {
            // Only an explicit NameIDPolicy with AllowCreate=false forbids
            // creating a new identifier. A request with no NameIDPolicy at all
            // (name_id_policy is None) means the IdP's configured default
            // format applies, and the IdP is permitted to mint that default -
            // it must not be treated as AllowCreate=false, or a persistent
            // default would deny every first-time subject whose request omits
            // NameIDPolicy.
            let allow_create = name_id_policy.map(|p| p.allow_create).unwrap_or(true);
            let existing = self.match_local_id(
                user_id,
                Some(sp_name_qualifier),
                Some(self.name_qualifier.as_str()),
            )?;
            match existing {
                Some(nid) => return Ok(nid),
                None if !allow_create => return Err(IdentError::CreateNotAllowed),
                None => {}
            }
        }

        Ok(self.get_nameid(
            user_id,
            format,
            Some(sp_name_qualifier),
            Some(self.name_qualifier.as_str()),
        )?)
    }

    /// Forget a NameID (pysaml2 `remove_remote()`).
    pub fn remove_remote(&self, name_id: &NameId) -> Result<(), StoreError> {
        self.store.remove(&name_id.value)
    }

    /// Forget every NameID for a local user (pysaml2 `remove_local()`).
    pub fn remove_local(&self, user_id: &str) -> Result<(), StoreError> {
        self.store.remove_all(user_id)
    }

    /// Apply a ManageNameIDRequest to the database (pysaml2
    /// `handle_manage_name_id_request()`); returns the updated NameID.
    ///
    /// - `NewID`: record the SP-provided identifier (`SPProvidedID`).
    /// - `Terminate`: drop the SP-provided identifier and terminate the
    ///   association for federation purposes.
    pub fn handle_manage_name_id_request(
        &self,
        name_id: &NameId,
        operation: &NewIdOrTerminate,
    ) -> Result<NameId, IdentError> {
        let user_id = self
            .find_local_id(name_id)?
            .ok_or_else(|| IdentError::UnknownNameId(name_id.value.clone()))?;

        let mut updated = name_id.clone();
        match operation {
            NewIdOrTerminate::NewId(new_id) => {
                updated.sp_provided_id = Some(new_id.clone());
            }
            NewIdOrTerminate::NewEncryptedId(_) => {
                return Err(IdentError::Unsupported(
                    "NewEncryptedID requires decryption before calling \
                     handle_manage_name_id_request",
                ));
            }
            NewIdOrTerminate::Terminate => {
                updated.sp_provided_id = None;
                self.remove_remote(name_id)?;
                return Ok(updated);
            }
        }

        self.store.replace(&user_id, updated.clone())?;
        Ok(updated)
    }

    /// Resolve a NameIDMappingRequest against the database (pysaml2
    /// `handle_name_id_mapping_request()`).
    ///
    /// Returns an existing NameID matching the requested policy, or
    /// creates one when `AllowCreate` permits.
    pub fn handle_name_id_mapping_request(
        &self,
        name_id: &NameId,
        name_id_policy: &NameIdPolicy,
    ) -> Result<NameId, IdentError> {
        let user_id = self
            .find_local_id(name_id)?
            .ok_or_else(|| IdentError::UnknownNameId(name_id.value.clone()))?;

        let wanted_format = name_id_policy.format.as_deref();
        let wanted_spq = name_id_policy.sp_name_qualifier.as_deref();
        let filter = NameIdFilter {
            format: wanted_format.map(str::to_string),
            sp_name_qualifier: wanted_spq.map(str::to_string),
            ..Default::default()
        };
        // A transient identifier is one-time-use and must not be reused, even
        // when persist_transient keeps it in the store.
        if let Some(existing) = self
            .find_nameid(&user_id, &filter)?
            .into_iter()
            .find(|nid| nid.format.as_deref() != Some(constants::NAMEID_TRANSIENT))
        {
            return Ok(existing);
        }

        if !name_id_policy.allow_create {
            return Err(IdentError::CreateNotAllowed);
        }

        let format = wanted_format.unwrap_or(constants::NAMEID_PERSISTENT);
        Ok(self.get_nameid(
            &user_id,
            format,
            wanted_spq,
            Some(self.name_qualifier.as_str()),
        )?)
    }
}

/// Object-safe view of [`IdentDb::construct_nameid`], so a caller that only
/// needs NameID construction can hold `dyn NameIdConstructor` instead of a
/// concrete `IdentDb<S>` — freeing it from committing to one `IdentityStore`
/// implementation at the type level.
///
/// [`idp::orchestrator::ResponseEngine`](crate::idp::orchestrator::ResponseEngine)
/// uses this: without it, `ResponseEngine` would need to stay generic over
/// `S: IdentityStore`, which a ready-made framework integration (a fixed
/// function signature registered as a route handler) cannot parameterize
/// per-application — hardcoding the default `InMemoryIdentityStore` would
/// shut out a Redis/SQL-backed store, the documented multi-instance seam.
pub trait NameIdConstructor: Send + Sync {
    /// See [`IdentDb::construct_nameid`].
    fn construct_nameid(
        &self,
        user_id: &str,
        sp_entity_id: &str,
        name_id_policy: Option<&NameIdPolicy>,
        default_format: Option<&str>,
    ) -> Result<NameId, IdentError>;
}

impl<S: IdentityStore> NameIdConstructor for IdentDb<S> {
    fn construct_nameid(
        &self,
        user_id: &str,
        sp_entity_id: &str,
        name_id_policy: Option<&NameIdPolicy>,
        default_format: Option<&str>,
    ) -> Result<NameId, IdentError> {
        IdentDb::construct_nameid(self, user_id, sp_entity_id, name_id_policy, default_format)
    }
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// A reusable check that an [`IdentityStore`] backend honours the contract
/// [`IdentDb`] relies on.
///
/// The two uniqueness constraints (NameID value; persistent `(user,
/// sp_name_qualifier, name_qualifier)`) live in the backend, not in this
/// crate, so a backend that forgets one - say a missing unique index -
/// compiles fine and only misbehaves under concurrent load. Run [`run`]
/// against a real instance (e.g. in the integration suite of the crate that
/// implements the Mongo store) to catch that.
///
/// `new_store` must return a **fresh, empty** store each call. Panics with a
/// description of the first violated rule.
pub mod conformance {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    const IDP: &str = "https://idp.example.com";
    const SP_A: &str = "https://sp-a.example.com";
    const SP_B: &str = "https://sp-b.example.com";
    const THREADS: usize = 16;

    fn nid(value: &str, format: &str, sp: Option<&str>) -> NameId {
        NameId {
            value: value.to_string(),
            format: Some(format.to_string()),
            name_qualifier: Some(IDP.to_string()),
            sp_name_qualifier: sp.map(str::to_string),
            sp_provided_id: None,
        }
    }

    fn persistent(value: &str, sp: &str) -> NameId {
        nid(value, constants::NAMEID_PERSISTENT, Some(sp))
    }

    /// Run every check against stores produced by `new_store`.
    pub fn run<S, F>(new_store: F)
    where
        S: IdentityStore + 'static,
        F: Fn() -> S,
    {
        value_is_unique(&new_store());
        lookups_round_trip_and_isolate_users(&new_store());
        persistent_is_get_or_insert(&new_store());
        persistent_insert_reports_a_taken_value(&new_store());
        find_persistent_is_format_and_qualifier_exact(&new_store());
        find_filters_on_every_field(&new_store());
        replace_upserts_by_value(&new_store());
        removal_is_scoped(&new_store());
        concurrent_get_or_insert_converges_on_one_identifier(new_store());
        concurrent_insert_of_one_value_has_one_winner(new_store());
    }

    fn value_is_unique<S: IdentityStore>(s: &S) {
        let first = nid("v1", constants::NAMEID_EMAIL, Some(SP_A));
        s.insert("alice", first.clone()).unwrap();
        assert!(
            matches!(
                s.insert("bob", nid("v1", constants::NAMEID_EMAIL, Some(SP_B))),
                Err(InsertError::ValueTaken)
            ),
            "a value already in use must be rejected, for any user"
        );
        assert_eq!(s.user_for("v1").unwrap().as_deref(), Some("alice"));
        assert_eq!(
            s.for_user("alice").unwrap(),
            vec![first],
            "loser must not overwrite"
        );
        assert!(s.for_user("bob").unwrap().is_empty());
    }

    fn lookups_round_trip_and_isolate_users<S: IdentityStore>(s: &S) {
        s.insert("alice", nid("a1", constants::NAMEID_EMAIL, Some(SP_A)))
            .unwrap();
        s.insert("bob", nid("b1", constants::NAMEID_EMAIL, Some(SP_A)))
            .unwrap();
        assert_eq!(s.user_for("a1").unwrap().as_deref(), Some("alice"));
        assert_eq!(s.user_for("b1").unwrap().as_deref(), Some("bob"));
        assert_eq!(s.user_for("nobody").unwrap(), None);
        assert_eq!(s.for_user("alice").unwrap().len(), 1);
        assert_eq!(s.for_user("alice").unwrap()[0].value, "a1");
        assert!(s.for_user("carol").unwrap().is_empty());
    }

    fn persistent_is_get_or_insert<S: IdentityStore>(s: &S) {
        let first = s
            .get_or_insert_persistent("alice", persistent("p1", SP_A))
            .unwrap();
        assert_eq!(first.value, "p1");
        let again = s
            .get_or_insert_persistent("alice", persistent("p2", SP_A))
            .unwrap();
        assert_eq!(
            again.value, "p1",
            "a second candidate for the same (user, SP) must return the existing one"
        );
        assert!(
            s.user_for("p2").unwrap().is_none(),
            "the losing candidate must not be stored"
        );
        let other_sp = s
            .get_or_insert_persistent("alice", persistent("p3", SP_B))
            .unwrap();
        assert_eq!(
            other_sp.value, "p3",
            "a different SP gets its own identifier"
        );
        let other_user = s
            .get_or_insert_persistent("bob", persistent("p4", SP_A))
            .unwrap();
        assert_eq!(other_user.value, "p4", "a different user gets their own");
    }

    fn persistent_insert_reports_a_taken_value<S: IdentityStore>(s: &S) {
        s.insert("alice", nid("taken", constants::NAMEID_EMAIL, Some(SP_A)))
            .unwrap();
        assert!(
            matches!(
                s.get_or_insert_persistent("bob", persistent("taken", SP_A)),
                Err(InsertError::ValueTaken)
            ),
            "no existing persistent record, but the value is taken by another user"
        );
        assert_eq!(s.user_for("taken").unwrap().as_deref(), Some("alice"));
    }

    fn find_persistent_is_format_and_qualifier_exact<S: IdentityStore>(s: &S) {
        s.insert("alice", nid("e1", constants::NAMEID_EMAIL, Some(SP_A)))
            .unwrap();
        assert!(
            s.find_persistent("alice", Some(SP_A), Some(IDP))
                .unwrap()
                .is_none(),
            "a non-persistent record must never satisfy a persistent lookup"
        );
        s.get_or_insert_persistent("alice", persistent("p1", SP_A))
            .unwrap();
        assert_eq!(
            s.find_persistent("alice", Some(SP_A), Some(IDP))
                .unwrap()
                .map(|n| n.value),
            Some("p1".to_string())
        );
        assert!(s
            .find_persistent("alice", Some(SP_B), Some(IDP))
            .unwrap()
            .is_none());
        assert!(s
            .find_persistent("alice", None, Some(IDP))
            .unwrap()
            .is_none());
    }

    fn find_filters_on_every_field<S: IdentityStore>(s: &S) {
        let mut with_alias = nid("f1", constants::NAMEID_EMAIL, Some(SP_A));
        with_alias.sp_provided_id = Some("alias".to_string());
        s.insert("alice", with_alias).unwrap();
        s.insert("alice", nid("f2", constants::NAMEID_EMAIL, Some(SP_B)))
            .unwrap();
        s.get_or_insert_persistent("alice", persistent("f3", SP_A))
            .unwrap();
        s.insert("bob", nid("f4", constants::NAMEID_EMAIL, Some(SP_A)))
            .unwrap();

        let values = |filter: NameIdFilter| -> Vec<String> {
            let mut v: Vec<String> = s
                .find("alice", &filter)
                .unwrap()
                .into_iter()
                .map(|n| n.value)
                .collect();
            v.sort();
            v
        };
        assert_eq!(
            values(NameIdFilter::default()),
            ["f1", "f2", "f3"],
            "an empty filter matches every record of the user, and no one else's"
        );
        assert_eq!(
            values(NameIdFilter {
                format: Some(constants::NAMEID_EMAIL.to_string()),
                ..Default::default()
            }),
            ["f1", "f2"],
            "format filters"
        );
        assert_eq!(
            values(NameIdFilter {
                sp_name_qualifier: Some(SP_A.to_string()),
                ..Default::default()
            }),
            ["f1", "f3"],
            "sp_name_qualifier filters"
        );
        assert_eq!(
            values(NameIdFilter {
                name_qualifier: Some(IDP.to_string()),
                ..Default::default()
            }),
            ["f1", "f2", "f3"],
            "name_qualifier filters"
        );
        assert_eq!(
            values(NameIdFilter {
                sp_provided_id: Some("alias".to_string()),
                ..Default::default()
            }),
            ["f1"],
            "sp_provided_id filters, and a record without one does not match"
        );
        assert_eq!(
            values(NameIdFilter {
                format: Some(constants::NAMEID_EMAIL.to_string()),
                sp_name_qualifier: Some(SP_A.to_string()),
                ..Default::default()
            }),
            ["f1"],
            "fields combine with AND"
        );
        assert!(values(NameIdFilter {
            sp_name_qualifier: Some("https://nobody.example.com".to_string()),
            ..Default::default()
        })
        .is_empty());
    }

    fn replace_upserts_by_value<S: IdentityStore>(s: &S) {
        s.replace("alice", nid("r1", constants::NAMEID_EMAIL, Some(SP_A)))
            .unwrap();
        let mut updated = nid("r1", constants::NAMEID_EMAIL, Some(SP_A));
        updated.sp_provided_id = Some("alias".to_string());
        s.replace("alice", updated.clone()).unwrap();
        assert_eq!(
            s.for_user("alice").unwrap(),
            vec![updated],
            "replace must update in place, not add a second record for the value"
        );
        s.replace("bob", nid("r1", constants::NAMEID_EMAIL, Some(SP_A)))
            .unwrap();
        assert_eq!(
            s.user_for("r1").unwrap().as_deref(),
            Some("bob"),
            "replace reassigns"
        );
        assert!(s.for_user("alice").unwrap().is_empty());
    }

    fn removal_is_scoped<S: IdentityStore>(s: &S) {
        s.insert("alice", nid("x1", constants::NAMEID_EMAIL, Some(SP_A)))
            .unwrap();
        s.insert("alice", nid("x2", constants::NAMEID_EMAIL, Some(SP_B)))
            .unwrap();
        s.insert("bob", nid("x3", constants::NAMEID_EMAIL, Some(SP_A)))
            .unwrap();
        s.remove("x1").unwrap();
        assert_eq!(s.user_for("x1").unwrap(), None);
        assert_eq!(
            s.for_user("alice").unwrap().len(),
            1,
            "remove drops one record only"
        );
        s.remove("no-such-value").unwrap(); // absent value is not an error
        s.remove_all("alice").unwrap();
        assert!(s.for_user("alice").unwrap().is_empty());
        assert_eq!(
            s.user_for("x2").unwrap(),
            None,
            "remove_all clears the value lookup too"
        );
        assert_eq!(
            s.user_for("x3").unwrap().as_deref(),
            Some("bob"),
            "other users untouched"
        );
    }

    fn concurrent_get_or_insert_converges_on_one_identifier<S>(store: S)
    where
        S: IdentityStore + 'static,
    {
        let store = Arc::new(store);
        let handles: Vec<_> = (0..THREADS)
            .map(|i| {
                let store = Arc::clone(&store);
                thread::spawn(move || {
                    // Retry on ValueTaken exactly as IdentDb does.
                    loop {
                        let candidate = persistent(&format!("c{i}"), SP_A);
                        match store.get_or_insert_persistent("alice", candidate) {
                            Ok(winner) => return winner.value,
                            Err(InsertError::ValueTaken) => continue,
                            Err(e) => panic!("backend failure during conformance run: {e}"),
                        }
                    }
                })
            })
            .collect();
        let values: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(
            values.iter().all(|v| v == &values[0]),
            "concurrent first requests for one (user, SP) minted different \
             persistent identifiers - the backend is missing its uniqueness \
             constraint on (user, sp_name_qualifier, name_qualifier): {values:?}"
        );
        let stored = store
            .for_user("alice")
            .unwrap()
            .into_iter()
            .filter(|n| n.format.as_deref() == Some(constants::NAMEID_PERSISTENT))
            .count();
        assert_eq!(stored, 1, "exactly one persistent record must be stored");
    }

    fn concurrent_insert_of_one_value_has_one_winner<S>(store: S)
    where
        S: IdentityStore + 'static,
    {
        let store = Arc::new(store);
        let handles: Vec<_> = (0..THREADS)
            .map(|i| {
                let store = Arc::clone(&store);
                thread::spawn(move || {
                    store
                        .insert(
                            &format!("user{i}"),
                            nid("same", constants::NAMEID_EMAIL, Some(SP_A)),
                        )
                        .is_ok()
                })
            })
            .collect();
        let winners = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(
            winners, 1,
            "exactly one concurrent insert of a value may succeed - the \
             backend is missing its uniqueness constraint on the NameID value"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDP: &str = "https://idp.example.com";
    const SP: &str = "https://sp.example.com";

    fn db() -> IdentDb {
        IdentDb::in_memory(IDP)
    }

    #[test]
    fn in_memory_identity_store_passes_the_conformance_suite() {
        conformance::run(InMemoryIdentityStore::new);
    }

    /// Delegates to the in-memory store, except where a test overrides a
    /// method to model a backend that forgot a uniqueness constraint.
    #[derive(Default)]
    struct BrokenStore {
        inner: InMemoryIdentityStore,
        no_value_uniqueness: bool,
        check_then_insert: bool,
    }

    impl IdentityStore for BrokenStore {
        fn for_user(&self, user_id: &str) -> Result<Vec<NameId>, StoreError> {
            self.inner.for_user(user_id)
        }
        fn user_for(&self, value: &str) -> Result<Option<String>, StoreError> {
            self.inner.user_for(value)
        }
        fn get_or_insert_persistent(
            &self,
            user_id: &str,
            candidate: NameId,
        ) -> Result<NameId, InsertError> {
            if self.check_then_insert {
                // Look, release, then write: what a backend without a unique
                // index does. Widen the window so the race is certain.
                if let Some(existing) = self.inner.find_persistent(
                    user_id,
                    candidate.sp_name_qualifier.as_deref(),
                    candidate.name_qualifier.as_deref(),
                )? {
                    return Ok(existing);
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
                // Value uniqueness still holds; only the persistent
                // (user, SP) tuple has no constraint behind this check.
                self.inner.insert(user_id, candidate.clone())?;
                return Ok(candidate);
            }
            self.inner.get_or_insert_persistent(user_id, candidate)
        }
        fn insert(&self, user_id: &str, name_id: NameId) -> Result<(), InsertError> {
            if self.no_value_uniqueness {
                self.inner.replace(user_id, name_id)?;
                return Ok(());
            }
            self.inner.insert(user_id, name_id)
        }
        fn replace(&self, user_id: &str, name_id: NameId) -> Result<(), StoreError> {
            self.inner.replace(user_id, name_id)
        }
        fn remove(&self, value: &str) -> Result<(), StoreError> {
            self.inner.remove(value)
        }
        fn remove_all(&self, user_id: &str) -> Result<(), StoreError> {
            self.inner.remove_all(user_id)
        }
    }

    /// A backend that cannot answer: every operation fails. Models an outage.
    struct DownStore;

    fn down() -> StoreError {
        StoreError::new("backend unreachable")
    }

    impl IdentityStore for DownStore {
        fn for_user(&self, _: &str) -> Result<Vec<NameId>, StoreError> {
            Err(down())
        }
        fn user_for(&self, _: &str) -> Result<Option<String>, StoreError> {
            Err(down())
        }
        fn get_or_insert_persistent(&self, _: &str, _: NameId) -> Result<NameId, InsertError> {
            Err(down().into())
        }
        fn insert(&self, _: &str, _: NameId) -> Result<(), InsertError> {
            Err(down().into())
        }
        fn replace(&self, _: &str, _: NameId) -> Result<(), StoreError> {
            Err(down())
        }
        fn remove(&self, _: &str) -> Result<(), StoreError> {
            Err(down())
        }
        fn remove_all(&self, _: &str) -> Result<(), StoreError> {
            Err(down())
        }
    }

    #[test]
    fn an_outage_is_an_error_not_a_missing_record() {
        let db = IdentDb::new(DownStore, IDP);
        // The lookup that decides "does this user already have a persistent
        // identifier?" must fail, not answer "no" and let a second one be minted.
        assert!(db.persistent_nameid("alice", Some(SP)).is_err());
        assert!(db.match_local_id("alice", Some(SP), Some(IDP)).is_err());
        assert!(db
            .find_local_id(&NameId {
                value: "v".into(),
                format: None,
                name_qualifier: None,
                sp_name_qualifier: None,
                sp_provided_id: None
            })
            .is_err());
        assert!(db.name_ids_for("alice").is_err());
        assert!(db.remove_local("alice").is_err());
        assert!(matches!(
            db.construct_nameid("alice", SP, None, Some(constants::NAMEID_PERSISTENT)),
            Err(IdentError::Store(_))
        ));
    }

    #[test]
    fn issuing_a_transient_nameid_does_not_need_the_store() {
        // Transients are never stored, so an outage must not block them.
        let db = IdentDb::new(DownStore, IDP);
        let nid = db.transient_nameid("alice", Some(SP)).unwrap();
        assert_eq!(nid.format.as_deref(), Some(constants::NAMEID_TRANSIENT));
    }

    #[test]
    #[should_panic(expected = "a value already in use must be rejected")]
    fn conformance_catches_a_backend_without_value_uniqueness() {
        conformance::run(|| BrokenStore {
            no_value_uniqueness: true,
            ..Default::default()
        });
    }

    #[test]
    #[should_panic(expected = "minted different persistent identifiers")]
    fn conformance_catches_a_check_then_insert_backend() {
        conformance::run(|| BrokenStore {
            check_then_insert: true,
            ..Default::default()
        });
    }

    #[test]
    fn test_code_decode_roundtrip() {
        let nid = NameId {
            value: "abc %25,=%123".to_string(),
            format: Some(constants::NAMEID_PERSISTENT.to_string()),
            name_qualifier: Some(IDP.to_string()),
            sp_name_qualifier: Some(SP.to_string()),
            sp_provided_id: Some("sp alias %25".to_string()),
        };
        let coded = code_name_id(&nid);
        assert!(!coded.contains(' '));
        let back = decode_name_id(&coded);
        assert_eq!(back, nid);
    }

    #[test]
    fn test_store_roundtrip_with_space_in_name_id_fields() {
        let db = db();
        let nid = NameId {
            value: "Alice Smith %25".to_string(),
            format: Some(constants::NAMEID_PERSISTENT.to_string()),
            name_qualifier: Some(IDP.to_string()),
            sp_name_qualifier: Some(SP.to_string()),
            sp_provided_id: Some("sp alias".to_string()),
        };

        db.store("alice", &nid).unwrap();

        assert_eq!(db.name_ids_for("alice").unwrap(), vec![nid.clone()]);
        assert_eq!(db.find_local_id(&nid).unwrap().as_deref(), Some("alice"));
    }

    #[test]
    fn test_transient_unique_each_time() {
        let db = db();
        let a = db.transient_nameid("alice", Some(SP)).unwrap();
        let b = db.transient_nameid("alice", Some(SP)).unwrap();
        assert_ne!(a.value, b.value);
        assert_eq!(a.format.as_deref(), Some(constants::NAMEID_TRANSIENT));
        // Transient identifiers are one-time-use and not persisted, so they
        // must not be reverse-looked-up and must not accumulate in the store
        // (the default per-SP format is transient, so every response would
        // otherwise grow the identity store without bound).
        assert_eq!(db.find_local_id(&a).unwrap(), None);
        assert_eq!(db.find_local_id(&b).unwrap(), None);
        assert!(db.name_ids_for("alice").unwrap().is_empty());
    }

    #[test]
    fn find_nameid_filters_a_users_records() {
        let db = db();
        let persistent = db.persistent_nameid("alice", Some(SP)).unwrap();
        db.get_nameid("alice", constants::NAMEID_EMAIL, Some(SP), Some(IDP))
            .unwrap();
        db.persistent_nameid("bob", Some(SP)).unwrap();

        let all = db.find_nameid("alice", &NameIdFilter::default()).unwrap();
        assert_eq!(all.len(), 2, "only alice's records");

        let only_persistent = db
            .find_nameid(
                "alice",
                &NameIdFilter {
                    format: Some(constants::NAMEID_PERSISTENT.to_string()),
                    sp_name_qualifier: Some(SP.to_string()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(only_persistent, vec![persistent]);
    }

    #[test]
    fn persist_transient_makes_a_transient_nameid_resolvable() {
        let db = IdentDb::in_memory(IDP).with_persist_transient(true);
        let a = db.transient_nameid("alice", Some(SP)).unwrap();
        let b = db.transient_nameid("alice", Some(SP)).unwrap();
        assert_ne!(a.value, b.value, "each issuance is still a fresh value");
        assert_eq!(db.find_local_id(&a).unwrap().as_deref(), Some("alice"));
        assert_eq!(db.find_local_id(&b).unwrap().as_deref(), Some("alice"));
        assert_eq!(db.name_ids_for("alice").unwrap().len(), 2);
        // A stored transient is never mistaken for the persistent identifier.
        assert!(db
            .match_local_id("alice", Some(SP), Some(IDP))
            .unwrap()
            .is_none());
        db.remove_remote(&a).unwrap();
        assert_eq!(db.find_local_id(&a).unwrap(), None);
        db.remove_local("alice").unwrap();
        assert_eq!(db.find_local_id(&b).unwrap(), None);
    }

    #[test]
    fn a_stored_transient_is_never_reused_by_a_nameid_mapping_request() {
        let db = IdentDb::in_memory(IDP).with_persist_transient(true);
        let t = db.transient_nameid("alice", Some(SP)).unwrap();
        let policy = NameIdPolicy {
            format: Some(constants::NAMEID_TRANSIENT.to_string()),
            sp_name_qualifier: Some(SP.to_string()),
            allow_create: true,
        };
        let mapped = db.handle_name_id_mapping_request(&t, &policy).unwrap();
        assert_ne!(
            mapped.value, t.value,
            "a transient identifier is one-time-use and must not be handed out again"
        );
    }

    #[test]
    fn persist_transient_needs_the_store() {
        let db = IdentDb::new(DownStore, IDP).with_persist_transient(true);
        assert!(db.transient_nameid("alice", Some(SP)).is_err());
    }

    #[test]
    fn repeated_transient_issuance_does_not_grow_the_store() {
        // Regression for the review finding "transient identifiers accumulate
        // without cleanup": the default per-SP NameID format is transient, and
        // every successful response (including repeated reuse of one session)
        // mints a fresh transient. Because a transient is one-time-use and
        // never reverse-looked-up, none of them may be persisted - otherwise
        // the identity store grows without bound for the IdP's most common
        // configuration. Drive construct_nameid (the orchestrator's path) with
        // the transient default repeatedly and assert the store stays empty.
        let db = db();
        let policy = NameIdPolicy {
            format: Some(constants::NAMEID_TRANSIENT.to_string()),
            sp_name_qualifier: None,
            allow_create: true,
        };
        let mut values = Vec::new();
        for _ in 0..50 {
            let nid = db
                .construct_nameid("alice", SP, Some(&policy), None)
                .unwrap();
            values.push(nid.value.clone());
        }
        // Each issuance is still a fresh, unique value...
        let unique = values.iter().collect::<std::collections::HashSet<_>>();
        assert_eq!(values.len(), unique.len());
        // ...and none of them accumulated in either index.
        assert!(db.name_ids_for("alice").unwrap().is_empty());
    }

    #[test]
    fn test_persistent_is_stable() {
        let db = db();
        let a = db.persistent_nameid("alice", Some(SP)).unwrap();
        let b = db.persistent_nameid("alice", Some(SP)).unwrap();
        assert_eq!(a.value, b.value);
        // different SP gets a different persistent id
        let c = db
            .persistent_nameid("alice", Some("https://other.example.com"))
            .unwrap();
        assert_ne!(a.value, c.value);
    }

    #[test]
    fn test_construct_nameid_honors_policy_format() {
        let db = db();
        let policy = NameIdPolicy {
            format: Some(constants::NAMEID_TRANSIENT.to_string()),
            sp_name_qualifier: None,
            allow_create: true,
        };
        let nid = db
            .construct_nameid("alice", SP, Some(&policy), None)
            .unwrap();
        assert_eq!(nid.format.as_deref(), Some(constants::NAMEID_TRANSIENT));
        assert_eq!(nid.sp_name_qualifier.as_deref(), Some(SP));
        assert_eq!(nid.name_qualifier.as_deref(), Some(IDP));
    }

    #[test]
    fn test_construct_nameid_default_format() {
        // Regression for the review finding "Missing NameIDPolicy incorrectly
        // disables persistent NameID creation": a request with no NameIDPolicy
        // at all must not be treated as AllowCreate=false. When the IdP's
        // configured default format is persistent, a first-time subject whose
        // request omits NameIDPolicy must be minted the default, not denied.
        let db = db();
        let nid = db
            .construct_nameid("alice", SP, None, Some(constants::NAMEID_PERSISTENT))
            .expect("no NameIDPolicy + persistent default must mint the default");
        assert_eq!(
            nid.format.as_deref(),
            Some(constants::NAMEID_PERSISTENT),
            "the IdP's configured default format must be honored"
        );
        // And it is stable: a second request for the same (user, SP) reuses it.
        let again = db
            .construct_nameid("alice", SP, None, Some(constants::NAMEID_PERSISTENT))
            .unwrap();
        assert_eq!(nid.value, again.value);
    }

    #[test]
    fn test_persistent_lookup_is_format_aware() {
        // Regression: a persistent request must not reuse an earlier
        // non-transient NameID of a *different* format for the same (user,
        // SP) pair. Sequential format requests against one shared store -
        // the realistic production shape, unlike a fresh store per format.
        let db = db();
        let email = db
            .get_nameid("alice", constants::NAMEID_EMAIL, Some(SP), Some(IDP))
            .unwrap();
        assert_eq!(email.format.as_deref(), Some(constants::NAMEID_EMAIL));

        let create = NameIdPolicy {
            format: Some(constants::NAMEID_PERSISTENT.to_string()),
            sp_name_qualifier: None,
            allow_create: true,
        };
        let persistent = db
            .construct_nameid("alice", SP, Some(&create), None)
            .expect("allow_create=true mints a fresh persistent id");
        assert_eq!(
            persistent.format.as_deref(),
            Some(constants::NAMEID_PERSISTENT),
            "a persistent request must not come back labeled with an earlier, \
             unrelated format"
        );
        assert_ne!(
            persistent.value, email.value,
            "a persistent request must not reuse the email-format identifier's value"
        );

        // And it's genuinely stable: asking again returns the same persistent
        // identifier, not a fresh one each time.
        let again = db
            .construct_nameid("alice", SP, Some(&create), None)
            .unwrap();
        assert_eq!(persistent.value, again.value);
    }

    #[test]
    fn test_allow_create_false_does_not_block_non_persistent_formats() {
        // Decided behavior (not a bug): AllowCreate (E14) is only meaningful
        // for the persistent format, matching pysaml2's own
        // construct_nameid()/persistent_nameid() split - transient/email/
        // unspecified/custom formats have no "existing identifier to reuse"
        // concept in the same sense and are minted fresh regardless of
        // AllowCreate. See ProcessedAuthnRequest::has_name_id_policy's doc.
        let db = db();
        let policy = NameIdPolicy {
            format: Some(constants::NAMEID_EMAIL.to_string()),
            sp_name_qualifier: None,
            allow_create: false,
        };
        let nid = db
            .construct_nameid("alice", SP, Some(&policy), None)
            .expect("AllowCreate=false must not block a non-persistent format");
        assert_eq!(nid.format.as_deref(), Some(constants::NAMEID_EMAIL));
    }

    #[test]
    fn concurrent_persistent_requests_for_the_same_user_and_sp_mint_only_one_identifier() {
        // Regression: construct_nameid/get_nameid's persistent path used to
        // be a plain check-then-create (match_local_id, then create_id +
        // store), so two concurrent requests for the same (user, SP) could
        // both observe "no existing association" and each mint a different
        // persistent identifier - violating the "stable per (user, SP)"
        // invariant (E78) the very first time it mattered. The
        // atomic get_or_insert_persistent closes this.
        use std::sync::Arc;
        use std::thread;

        let db = Arc::new(db());
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let db = Arc::clone(&db);
                thread::spawn(move || db.persistent_nameid("alice", Some(SP)).unwrap())
            })
            .collect();

        let values: Vec<String> = threads
            .into_iter()
            .map(|t| t.join().unwrap().value)
            .collect();

        let first = &values[0];
        assert!(
            values.iter().all(|v| v == first),
            "concurrent persistent requests for the same (user, SP) must all \
             resolve to the same identifier, got: {values:?}"
        );

        // Exactly one persistent NameID was stored for (alice, SP), not one
        // per thread that lost the race.
        let persistent_entries: Vec<_> = db
            .name_ids_for("alice")
            .unwrap()
            .into_iter()
            .filter(|nid| nid.format.as_deref() == Some(constants::NAMEID_PERSISTENT))
            .collect();
        assert_eq!(persistent_entries.len(), 1);
    }

    #[test]
    fn concurrent_persistent_and_durable_issuance_do_not_clobber_each_other() {
        // Regression: get_or_create_persistent's CAS loop only coordinated
        // with other CAS writers on the forward key; store() (used for
        // durable non-persistent formats like email) still did a plain
        // get-then-set on that same key. A store() write could read the list
        // before the persistent CAS committed and then overwrite it with a
        // stale value, silently dropping the persistent entry even though its
        // own CAS "succeeded". Both paths now go through the same
        // atomic get_or_insert_persistent / insert.
        //
        // (Transient identifiers are not stored at all, so they no longer
        // exercise this path; email is a durable non-persistent format that
        // does.)
        use std::sync::Arc;
        use std::thread;

        let db = Arc::new(db());
        let mut threads = Vec::new();
        for _ in 0..8 {
            let db = Arc::clone(&db);
            threads.push(thread::spawn(move || {
                db.persistent_nameid("alice", Some(SP)).unwrap();
            }));
        }
        for i in 0..8 {
            let db = Arc::clone(&db);
            threads.push(thread::spawn(move || {
                db.get_nameid(
                    "alice",
                    constants::NAMEID_EMAIL,
                    Some(&format!("{SP}/{i}")),
                    Some(IDP),
                )
                .unwrap();
            }));
        }
        for t in threads {
            t.join().unwrap();
        }

        let entries = db.name_ids_for("alice").unwrap();
        let persistent: Vec<_> = entries
            .iter()
            .filter(|nid| nid.format.as_deref() == Some(constants::NAMEID_PERSISTENT))
            .collect();
        let email: Vec<_> = entries
            .iter()
            .filter(|nid| nid.format.as_deref() == Some(constants::NAMEID_EMAIL))
            .collect();
        assert_eq!(
            persistent.len(),
            1,
            "persistent entry must survive: {entries:?}"
        );
        assert_eq!(
            email.len(),
            8,
            "every durable non-persistent issuance must survive: {entries:?}"
        );
    }

    #[test]
    fn concurrent_remove_local_does_not_orphan_a_racing_writers_reverse_key() {
        // Regression: remove_local read name_ids_for(user) (forward key),
        // then unconditionally removed each entry's reverse key followed by
        // the forward key itself - all as plain, non-CAS operations, unlike
        // every other forward-key writer (store/get_or_create_persistent/
        // remove_remote). A concurrent store() for a *different* SP could
        // commit a brand-new forward-list entry (and its reverse key) in the
        // window between remove_local's read and its final forward-key
        // removal; remove_local's unconditional removal then wiped that
        // fresh entry out of the forward list while its reverse-key mapping
        // was never cleaned up (it didn't exist yet when remove_local read
        // the list) - a permanently orphaned reverse-key entry, and a
        // "stable" persistent identifier that silently stops being stable.
        use std::sync::Arc;
        use std::thread;

        for round in 0..20 {
            let db = Arc::new(db());
            db.persistent_nameid("alice", Some(SP)).unwrap();

            let remover = {
                let db = Arc::clone(&db);
                thread::spawn(move || db.remove_local("alice").unwrap())
            };
            let writers: Vec<_> = (0..4)
                .map(|i| {
                    let db = Arc::clone(&db);
                    thread::spawn(move || {
                        db.get_nameid(
                            "alice",
                            constants::NAMEID_EMAIL,
                            Some(&format!("{SP}/{round}/{i}")),
                            Some(IDP),
                        )
                        .unwrap()
                    })
                })
                .collect();

            remover.join().unwrap();
            let written: Vec<_> = writers.into_iter().map(|t| t.join().unwrap()).collect();

            let present: Vec<String> = db
                .name_ids_for("alice")
                .unwrap()
                .into_iter()
                .map(|nid| nid.value)
                .collect();
            for nid in &written {
                let in_forward_list = present.contains(&nid.value);
                let reverse_points_here =
                    db.find_local_id(nid).unwrap().as_deref() == Some("alice");
                assert_eq!(
                    in_forward_list, reverse_points_here,
                    "round {round}: NameID {:?} must be either fully present (forward + \
                     reverse) or fully absent, never a dangling reverse-key entry",
                    nid.value
                );
            }
        }
    }

    #[test]
    fn test_construct_persistent_allow_create_e14() {
        let db = db();
        let no_create = NameIdPolicy {
            format: Some(constants::NAMEID_PERSISTENT.to_string()),
            sp_name_qualifier: None,
            allow_create: false,
        };
        assert!(matches!(
            db.construct_nameid("alice", SP, Some(&no_create), None),
            Err(IdentError::CreateNotAllowed)
        ));

        let create = NameIdPolicy {
            allow_create: true,
            ..no_create.clone()
        };
        let nid = db
            .construct_nameid("alice", SP, Some(&create), None)
            .unwrap();

        // E14: with AllowCreate=false an *existing* identifier may be used
        let again = db
            .construct_nameid("alice", SP, Some(&no_create), None)
            .unwrap();
        assert_eq!(nid.value, again.value);
    }

    #[test]
    fn test_no_format_error() {
        let db = db();
        assert!(matches!(
            db.construct_nameid("alice", SP, None, None),
            Err(IdentError::NoFormat)
        ));
    }

    #[test]
    fn test_remove_remote_and_local() {
        let db = db();
        let nid = db.persistent_nameid("alice", Some(SP)).unwrap();
        db.remove_remote(&nid).unwrap();
        assert!(db.find_local_id(&nid).unwrap().is_none());
        assert!(db.name_ids_for("alice").unwrap().is_empty());

        let n1 = db.persistent_nameid("alice", Some(SP)).unwrap();
        let n2 = db
            .get_nameid("alice", constants::NAMEID_EMAIL, Some(SP), Some(IDP))
            .unwrap();
        db.remove_local("alice").unwrap();
        assert!(db.find_local_id(&n1).unwrap().is_none());
        assert!(db.find_local_id(&n2).unwrap().is_none());
    }

    #[test]
    fn test_manage_name_id_new_id_and_terminate() {
        let db = db();
        let nid = db.persistent_nameid("alice", Some(SP)).unwrap();

        let updated = db
            .handle_manage_name_id_request(&nid, &NewIdOrTerminate::NewId("sp-alias".to_string()))
            .unwrap();
        assert_eq!(updated.sp_provided_id.as_deref(), Some("sp-alias"));
        assert_eq!(
            db.find_local_id(&updated).unwrap().as_deref(),
            Some("alice")
        );
        let stored = db
            .match_local_id("alice", Some(SP), Some(IDP))
            .unwrap()
            .unwrap();
        assert_eq!(stored.sp_provided_id.as_deref(), Some("sp-alias"));

        db.handle_manage_name_id_request(&updated, &NewIdOrTerminate::Terminate)
            .unwrap();
        assert!(db.find_local_id(&updated).unwrap().is_none());
    }

    #[test]
    fn test_manage_name_id_unknown() {
        let db = db();
        let stranger = NameId {
            value: "nobody".to_string(),
            format: None,
            name_qualifier: None,
            sp_name_qualifier: None,
            sp_provided_id: None,
        };
        assert!(matches!(
            db.handle_manage_name_id_request(&stranger, &NewIdOrTerminate::Terminate),
            Err(IdentError::UnknownNameId(_))
        ));
    }

    #[test]
    fn test_name_id_mapping() {
        let db = db();
        let nid = db.persistent_nameid("alice", Some(SP)).unwrap();

        // Map to another SP, creation allowed
        let policy = NameIdPolicy {
            format: Some(constants::NAMEID_PERSISTENT.to_string()),
            sp_name_qualifier: Some("https://other.example.com".to_string()),
            allow_create: true,
        };
        let mapped = db.handle_name_id_mapping_request(&nid, &policy).unwrap();
        assert_eq!(
            mapped.sp_name_qualifier.as_deref(),
            Some("https://other.example.com")
        );
        assert_ne!(mapped.value, nid.value);

        // Second request returns the same mapping
        let mapped2 = db.handle_name_id_mapping_request(&nid, &policy).unwrap();
        assert_eq!(mapped.value, mapped2.value);

        // Creation forbidden for a third SP
        let strict = NameIdPolicy {
            sp_name_qualifier: Some("https://third.example.com".to_string()),
            allow_create: false,
            format: Some(constants::NAMEID_PERSISTENT.to_string()),
        };
        assert!(matches!(
            db.handle_name_id_mapping_request(&nid, &strict),
            Err(IdentError::CreateNotAllowed)
        ));
    }

    #[test]
    fn test_email_format_uses_domain() {
        let db = IdentDb::in_memory(IDP).with_domain("example.org");
        let nid = db
            .get_nameid("alice", constants::NAMEID_EMAIL, Some(SP), Some(IDP))
            .unwrap();
        assert!(nid.value.ends_with("@example.org"));
    }

    #[test]
    fn test_email_format_reverse_mapping_uses_full_value() {
        // The collision check and the reverse index must both key on the
        // final `local-part@domain` value, so the issued email NameID resolves
        // back to its local principal.
        let db = IdentDb::in_memory(IDP).with_domain("example.org");
        let nid = db
            .get_nameid("alice", constants::NAMEID_EMAIL, Some(SP), Some(IDP))
            .unwrap();
        assert!(nid.value.contains('@'));
        assert_eq!(db.find_local_id(&nid).unwrap().as_deref(), Some("alice"));
    }
}
