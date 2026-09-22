// IdP identity database: NameID generation and management
// (pysaml2 `IdentDB` equivalent).
//
// Maintains the bidirectional mapping between local user ids and the
// NameIDs issued to relying parties, generates transient/persistent
// NameIDs honoring an incoming `NameIDPolicy`, and implements the server
// side of the ManageNameID and NameIDMapping profiles on top of it.
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
}

/// Pluggable key/value backend for the identity database.
///
/// Implement this over Redis/SQL/etc. for multi-instance deployments.
pub trait IdentityStore: Send + Sync {
    /// Fetch a value.
    fn get(&self, key: &str) -> Option<String>;
    /// Store a value.
    fn set(&self, key: &str, value: String);
    /// Remove a value.
    fn remove(&self, key: &str);

    /// Atomically replace `key`'s value with `new`, but only if its current
    /// value equals `expected` (`None` means "key must be absent"). Returns
    /// whether the swap happened.
    ///
    /// `IdentDb` uses this to close a check-then-create race on persistent
    /// NameID minting: two concurrent requests for the same (user, SP) that
    /// both observe no existing association must not both succeed at
    /// storing a *different* persistent identifier for it. This must be a
    /// real atomic operation at the storage layer for a multi-instance
    /// backend (Redis `WATCH`/`MULTI`, a SQL `UPDATE ... WHERE current =
    /// expected`, etc.) - a single process serializing its own calls (e.g.
    /// behind a mutex) is not enough once more than one process shares the
    /// same backing store. There is deliberately no default implementation:
    /// a plausible-looking but non-atomic default (a plain `get`+`set`, or
    /// even a process-local mutex) would silently leave the exact race this
    /// method exists to close in place for any multi-instance deployment
    /// that didn't happen to notice it needed to do something extra.
    /// Implementing `IdentityStore` for a new backend is already the moment
    /// to decide this deliberately, not a moment to inherit a default that
    /// looks safe and isn't.
    fn compare_and_swap(&self, key: &str, expected: Option<&str>, new: &str) -> bool;
}

/// In-memory identity store.
#[derive(Debug, Default)]
pub struct InMemoryIdentityStore {
    map: Mutex<HashMap<String, String>>,
}

impl InMemoryIdentityStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl IdentityStore for InMemoryIdentityStore {
    fn get(&self, key: &str) -> Option<String> {
        self.map.lock().unwrap().get(key).cloned()
    }

    fn set(&self, key: &str, value: String) {
        self.map.lock().unwrap().insert(key.to_string(), value);
    }

    fn remove(&self, key: &str) {
        self.map.lock().unwrap().remove(key);
    }

    fn compare_and_swap(&self, key: &str, expected: Option<&str>, new: &str) -> bool {
        let mut map = self.map.lock().unwrap();
        if map.get(key).map(String::as_str) != expected {
            return false;
        }
        map.insert(key.to_string(), new.to_string());
        true
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

const FORWARD_PREFIX: &str = "user:";
const REVERSE_PREFIX: &str = "nameid:";

/// The identity database (pysaml2 `IdentDB`).
pub struct IdentDb<S: IdentityStore = InMemoryIdentityStore> {
    store: S,
    /// The IdP entity ID, used as the default NameQualifier.
    name_qualifier: String,
    /// Domain appended to generated email-format NameIDs.
    domain: Option<String>,
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
        }
    }

    /// Set the domain used for email-format NameIDs.
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    fn forward_key(user_id: &str) -> String {
        format!("{FORWARD_PREFIX}{user_id}")
    }

    fn reverse_key(value: &str) -> String {
        format!("{REVERSE_PREFIX}{value}")
    }

    /// Split a forward entry's stored value into its coded NameID entries,
    /// filtering out empty segments so the empty-string sentinel a CAS-based
    /// removal can leave behind (see [`Self::remove_forward_entry`]) reads
    /// back as "no entries", not a phantom entry.
    fn forward_entries(joined: &str) -> Vec<&str> {
        joined.split(' ').filter(|s| !s.is_empty()).collect()
    }

    /// All NameIDs stored for a local user.
    pub fn name_ids_for(&self, user_id: &str) -> Vec<NameId> {
        self.store
            .get(&Self::forward_key(user_id))
            .map(|joined| {
                Self::forward_entries(&joined)
                    .into_iter()
                    .map(decode_name_id)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Associate a NameID with a local user (pysaml2 `store()`).
    ///
    /// Maintains both directions: user -> issued NameIDs (forward) and
    /// NameID value -> user (reverse, used by `find_local_id`).
    ///
    /// Writes the reverse key *before* appending to the forward list, not
    /// after: `remove_local`'s cleanup derives which reverse keys to remove
    /// from what it reads in the forward list, so a concurrent `store()`
    /// that becomes forward-list-visible before its reverse key exists lets
    /// `remove_local` observe the new forward entry, find nothing to clean
    /// up for it (a `remove` on an as-yet-absent key is a silent no-op), and
    /// finish - after which this call's now-late reverse-key write creates
    /// a mapping nothing will ever revisit. Writing reverse-then-forward
    /// means any forward-visible entry already has its reverse key, which
    /// is the invariant `remove_local`'s snapshot-based cleanup needs.
    pub fn store(&self, user_id: &str, name_id: &NameId) {
        let coded = code_name_id(name_id);
        self.store
            .set(&Self::reverse_key(&name_id.value), user_id.to_string());
        self.append_forward_entry(user_id, &coded);
    }

    /// Atomically append `coded` to a user's forward entry, retrying on CAS
    /// conflict.
    ///
    /// Every writer of the forward key (this, and the persistent-NameID
    /// get-or-create loop) must go through `compare_and_swap` against the
    /// *same* key, or two writers can still race: one reads the old list,
    /// the other's plain `get`+`set` (or CAS) commits first, and the first
    /// then overwrites that committed entry with its own stale-based
    /// value - silently dropping whichever entry lost the race, independent
    /// of whether either individual writer was itself "atomic".
    fn append_forward_entry(&self, user_id: &str, coded: &str) {
        let key = Self::forward_key(user_id);
        loop {
            let current = self.store.get(&key);
            let mut entries: Vec<String> = current
                .as_deref()
                .map(|joined| {
                    Self::forward_entries(joined)
                        .into_iter()
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            if entries.iter().any(|e| e == coded) {
                return;
            }
            entries.push(coded.to_string());
            let new_value = entries.join(" ");
            if self
                .store
                .compare_and_swap(&key, current.as_deref(), &new_value)
            {
                return;
            }
        }
    }

    /// The local user a NameID was issued to (pysaml2 `find_local_id()`).
    pub fn find_local_id(&self, name_id: &NameId) -> Option<String> {
        self.store.get(&Self::reverse_key(&name_id.value))
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
    ) -> Option<NameId> {
        self.name_ids_for(user_id).into_iter().find(|nid| {
            if nid.format.as_deref() != Some(constants::NAMEID_PERSISTENT) {
                return false;
            }
            let sp_match = match sp_name_qualifier {
                Some(spq) => nid.sp_name_qualifier.as_deref() == Some(spq),
                None => nid.sp_name_qualifier.is_none(),
            };
            let nq_match = match name_qualifier {
                Some(nq) => nid.name_qualifier.as_deref() == Some(nq),
                None => nid.name_qualifier.is_none(),
            };
            sp_match && nq_match
        })
    }

    /// Generate a fresh opaque identifier value (pysaml2 `create_id()`).
    fn create_id(
        &self,
        format: &str,
        name_qualifier: Option<&str>,
        sp_name_qualifier: Option<&str>,
    ) -> String {
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
            // *before* the collision check, otherwise the check tests a key
            // that is never stored and a rare collision would silently
            // overwrite the reverse mapping.
            let value = if format == constants::NAMEID_EMAIL {
                let domain = self.domain.as_deref().unwrap_or("idp.example.org");
                format!("{id}@{domain}")
            } else {
                id
            };
            if self.store.get(&Self::reverse_key(&value)).is_none() {
                return value;
            }
        }
    }

    /// Create and store a new NameID of the given format
    /// (pysaml2 `get_nameid()`); persistent format reuses an existing
    /// association when one exists.
    pub fn get_nameid(
        &self,
        user_id: &str,
        format: &str,
        sp_name_qualifier: Option<&str>,
        name_qualifier: Option<&str>,
    ) -> NameId {
        // Persistent identifiers must stay stable per (user, SP): reuse an
        // existing association instead of minting a new value (E78), via an
        // atomic get-or-create so two concurrent requests for the same
        // (user, SP) can't both observe "none exists" and mint two
        // different persistent identifiers.
        if format == constants::NAMEID_PERSISTENT {
            return self.get_or_create_persistent(user_id, sp_name_qualifier, name_qualifier);
        }

        // `create_id` already applies the email-format `@domain` suffix and
        // guarantees the value is free in the reverse index.
        let value = self.create_id(format, name_qualifier, sp_name_qualifier);

        let name_id = NameId {
            value,
            format: Some(format.to_string()),
            name_qualifier: name_qualifier.map(str::to_string),
            sp_name_qualifier: sp_name_qualifier.map(str::to_string),
            sp_provided_id: None,
        };
        self.store(user_id, &name_id);
        name_id
    }

    /// Atomic get-or-create for a persistent NameID (see [`IdentityStore::compare_and_swap`]).
    ///
    /// Loops: read the user's current forward entry, return an existing
    /// persistent match if one is already there (possibly written by a
    /// concurrent caller since the last read), otherwise mint a candidate
    /// and try to CAS it in; on CAS failure someone else just wrote to this
    /// key, so retry from the read.
    ///
    /// The candidate's reverse key is written *before* the forward CAS is
    /// attempted, and reused (not regenerated) across retries, for the same
    /// reason [`Self::store`] writes reverse-before-forward: once an entry
    /// is visible in the forward list, its reverse key must already exist,
    /// or a concurrent `remove_local` can observe the forward entry, find
    /// nothing yet to clean up in the reverse index, and finish before this
    /// call's reverse-key write lands - permanently orphaning it. If a
    /// retry instead finds an existing match (someone else's write already
    /// satisfies this request), the unused candidate's speculative reverse
    /// key is rolled back rather than left dangling.
    fn get_or_create_persistent(
        &self,
        user_id: &str,
        sp_name_qualifier: Option<&str>,
        name_qualifier: Option<&str>,
    ) -> NameId {
        let key = Self::forward_key(user_id);
        let mut candidate: Option<NameId> = None;
        loop {
            let current = self.store.get(&key);
            let entries: Vec<String> = current
                .as_deref()
                .map(|joined| {
                    Self::forward_entries(joined)
                        .into_iter()
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();

            if let Some(existing) = entries.iter().map(|e| decode_name_id(e)).find(|nid| {
                nid.format.as_deref() == Some(constants::NAMEID_PERSISTENT)
                    && nid.sp_name_qualifier.as_deref() == sp_name_qualifier
                    && nid.name_qualifier.as_deref() == name_qualifier
            }) {
                if let Some(abandoned) = &candidate {
                    self.store.remove(&Self::reverse_key(&abandoned.value));
                }
                return existing;
            }

            let name_id = candidate.get_or_insert_with(|| {
                let value = self.create_id(
                    constants::NAMEID_PERSISTENT,
                    name_qualifier,
                    sp_name_qualifier,
                );
                let name_id = NameId {
                    value,
                    format: Some(constants::NAMEID_PERSISTENT.to_string()),
                    name_qualifier: name_qualifier.map(str::to_string),
                    sp_name_qualifier: sp_name_qualifier.map(str::to_string),
                    sp_provided_id: None,
                };
                self.store
                    .set(&Self::reverse_key(&name_id.value), user_id.to_string());
                name_id
            });

            let mut new_entries = entries.clone();
            new_entries.push(code_name_id(name_id));
            let new_value = new_entries.join(" ");

            if self
                .store
                .compare_and_swap(&key, current.as_deref(), &new_value)
            {
                return candidate.expect("just inserted above");
            }
            // Someone else wrote to `key` concurrently; loop and re-check
            // whether *their* write already satisfies this request - reusing
            // the same candidate (and its already-written reverse key) if we
            // end up needing to append it after all.
        }
    }

    /// Generate a transient NameID (pysaml2 `transient_nameid()`).
    pub fn transient_nameid(&self, user_id: &str, sp_name_qualifier: Option<&str>) -> NameId {
        self.get_nameid(
            user_id,
            constants::NAMEID_TRANSIENT,
            sp_name_qualifier,
            Some(self.name_qualifier.as_str()),
        )
    }

    /// Get-or-create a persistent NameID (pysaml2 `persistent_nameid()`).
    pub fn persistent_nameid(&self, user_id: &str, sp_name_qualifier: Option<&str>) -> NameId {
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
    /// - AllowCreate (E14): when false, only an existing identifier may be
    ///   returned for the persistent format.
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
            let allow_create = name_id_policy.map(|p| p.allow_create).unwrap_or(false);
            let existing = self.match_local_id(
                user_id,
                Some(sp_name_qualifier),
                Some(self.name_qualifier.as_str()),
            );
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
        ))
    }

    /// Forget a NameID (pysaml2 `remove_remote()`).
    pub fn remove_remote(&self, name_id: &NameId) {
        let coded = code_name_id(name_id);
        if let Some(user_id) = self.find_local_id(name_id) {
            self.remove_forward_entry(&user_id, &coded);
        }
        self.store.remove(&Self::reverse_key(&name_id.value));
    }

    /// Atomically remove `coded` from a user's forward entry, retrying on
    /// CAS conflict. See [`Self::append_forward_entry`] for why this must
    /// go through `compare_and_swap` rather than a plain `get`+`set`.
    ///
    /// When removal empties the entry, this CASes to `""` rather than
    /// removing the key outright - a separate, non-atomic `remove` call
    /// would let a concurrent reader observe a half-updated state, and
    /// [`Self::forward_entries`] treats `""` identically to an absent key.
    fn remove_forward_entry(&self, user_id: &str, coded: &str) {
        let key = Self::forward_key(user_id);
        loop {
            let Some(current) = self.store.get(&key) else {
                return;
            };
            let remaining = Self::forward_entries(&current);
            if !remaining.contains(&coded) {
                return;
            }
            let new_value = remaining
                .into_iter()
                .filter(|c| *c != coded)
                .collect::<Vec<_>>()
                .join(" ");
            if self
                .store
                .compare_and_swap(&key, Some(&current), &new_value)
            {
                return;
            }
        }
    }

    /// Forget every NameID for a local user (pysaml2 `remove_local()`).
    pub fn remove_local(&self, user_id: &str) {
        let key = Self::forward_key(user_id);
        loop {
            let Some(current) = self.store.get(&key) else {
                return;
            };
            // CAS the forward key to the empty sentinel (see
            // Self::remove_forward_entry) rather than reading-then-removing:
            // a plain remove here could discard an entry a concurrent
            // store()/get_or_create_persistent() call just added for a
            // *different* SP, in the window between our read and the
            // removal, while leaving that entry's reverse-key mapping
            // dangling forever (it was never cleaned up because it didn't
            // exist yet when we read the forward list).
            if self.store.compare_and_swap(&key, Some(&current), "") {
                for coded in Self::forward_entries(&current) {
                    let nid = decode_name_id(coded);
                    self.store.remove(&Self::reverse_key(&nid.value));
                }
                return;
            }
            // Someone else wrote to `key` concurrently; retry against the
            // now-current value instead of clobbering their write.
        }
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
            .find_local_id(name_id)
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
                self.remove_remote(name_id);
                return Ok(updated);
            }
        }

        self.remove_remote(name_id);
        self.store(&user_id, &updated);
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
            .find_local_id(name_id)
            .ok_or_else(|| IdentError::UnknownNameId(name_id.value.clone()))?;

        let wanted_format = name_id_policy.format.as_deref();
        let wanted_spq = name_id_policy.sp_name_qualifier.as_deref();
        if let Some(existing) = self.name_ids_for(&user_id).into_iter().find(|nid| {
            (wanted_format.is_none() || nid.format.as_deref() == wanted_format)
                && (wanted_spq.is_none() || nid.sp_name_qualifier.as_deref() == wanted_spq)
        }) {
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
        ))
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

#[cfg(test)]
mod tests {
    use super::*;

    const IDP: &str = "https://idp.example.com";
    const SP: &str = "https://sp.example.com";

    fn db() -> IdentDb {
        IdentDb::in_memory(IDP)
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

        db.store("alice", &nid);

        assert_eq!(db.name_ids_for("alice"), vec![nid.clone()]);
        assert_eq!(db.find_local_id(&nid).as_deref(), Some("alice"));
    }

    #[test]
    fn test_transient_unique_each_time() {
        let db = db();
        let a = db.transient_nameid("alice", Some(SP));
        let b = db.transient_nameid("alice", Some(SP));
        assert_ne!(a.value, b.value);
        assert_eq!(a.format.as_deref(), Some(constants::NAMEID_TRANSIENT));
        assert_eq!(db.find_local_id(&a).as_deref(), Some("alice"));
        assert_eq!(db.find_local_id(&b).as_deref(), Some("alice"));
    }

    #[test]
    fn test_persistent_is_stable() {
        let db = db();
        let a = db.persistent_nameid("alice", Some(SP));
        let b = db.persistent_nameid("alice", Some(SP));
        assert_eq!(a.value, b.value);
        // different SP gets a different persistent id
        let c = db.persistent_nameid("alice", Some("https://other.example.com"));
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
        let db = db();
        let nid = db
            .construct_nameid("alice", SP, None, Some(constants::NAMEID_PERSISTENT))
            .unwrap_err();
        // persistent + no policy => allow_create false => no new id
        assert!(matches!(nid, IdentError::CreateNotAllowed));
    }

    #[test]
    fn test_persistent_lookup_is_format_aware() {
        // Regression: a persistent request must not reuse an earlier
        // non-transient NameID of a *different* format for the same (user,
        // SP) pair. Sequential format requests against one shared store -
        // the realistic production shape, unlike a fresh store per format.
        let db = db();
        let email = db.get_nameid("alice", constants::NAMEID_EMAIL, Some(SP), Some(IDP));
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
        // IdentityStore::compare_and_swap-backed retry loop closes this.
        use std::sync::Arc;
        use std::thread;

        let db = Arc::new(db());
        let threads: Vec<_> = (0..16)
            .map(|_| {
                let db = Arc::clone(&db);
                thread::spawn(move || db.persistent_nameid("alice", Some(SP)))
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
            .into_iter()
            .filter(|nid| nid.format.as_deref() == Some(constants::NAMEID_PERSISTENT))
            .collect();
        assert_eq!(persistent_entries.len(), 1);
    }

    #[test]
    fn concurrent_persistent_and_transient_issuance_do_not_clobber_each_other() {
        // Regression: get_or_create_persistent's CAS loop only coordinated
        // with other CAS writers on the forward key; store() (used for
        // transient/email/etc.) still did a plain get-then-set on that same
        // key. A store() write could read the list before the persistent
        // CAS committed and then overwrite it with a stale value, silently
        // dropping the persistent entry even though its own CAS "succeeded".
        // Both paths now go through the same compare_and_swap-based retry.
        use std::sync::Arc;
        use std::thread;

        let db = Arc::new(db());
        let mut threads = Vec::new();
        for _ in 0..8 {
            let db = Arc::clone(&db);
            threads.push(thread::spawn(move || {
                db.persistent_nameid("alice", Some(SP));
            }));
        }
        for i in 0..8 {
            let db = Arc::clone(&db);
            threads.push(thread::spawn(move || {
                db.transient_nameid("alice", Some(&format!("{SP}/{i}")));
            }));
        }
        for t in threads {
            t.join().unwrap();
        }

        let entries = db.name_ids_for("alice");
        let persistent: Vec<_> = entries
            .iter()
            .filter(|nid| nid.format.as_deref() == Some(constants::NAMEID_PERSISTENT))
            .collect();
        let transient: Vec<_> = entries
            .iter()
            .filter(|nid| nid.format.as_deref() == Some(constants::NAMEID_TRANSIENT))
            .collect();
        assert_eq!(
            persistent.len(),
            1,
            "persistent entry must survive: {entries:?}"
        );
        assert_eq!(
            transient.len(),
            8,
            "every transient issuance must survive: {entries:?}"
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
            db.persistent_nameid("alice", Some(SP));

            let remover = {
                let db = Arc::clone(&db);
                thread::spawn(move || db.remove_local("alice"))
            };
            let writers: Vec<_> = (0..4)
                .map(|i| {
                    let db = Arc::clone(&db);
                    thread::spawn(move || {
                        db.transient_nameid("alice", Some(&format!("{SP}/{round}/{i}")))
                    })
                })
                .collect();

            remover.join().unwrap();
            let written: Vec<_> = writers.into_iter().map(|t| t.join().unwrap()).collect();

            let present: Vec<String> = db
                .name_ids_for("alice")
                .into_iter()
                .map(|nid| nid.value)
                .collect();
            for nid in &written {
                let in_forward_list = present.contains(&nid.value);
                let reverse_points_here = db.find_local_id(nid).as_deref() == Some("alice");
                assert_eq!(
                    in_forward_list, reverse_points_here,
                    "round {round}: NameID {:?} must be either fully present (forward + \
                     reverse) or fully absent, never a dangling reverse-key entry",
                    nid.value
                );
            }
        }
    }

    /// An `IdentityStore` that pauses the *first* `set()` call on a
    /// reverse-index key (`nameid:...`) after it has landed, releasing only
    /// when told to - used to deterministically force a `remove_local` to
    /// interleave in the exact window a scheduling-dependent test can only
    /// hit by luck.
    struct SteppedStore {
        inner: InMemoryIdentityStore,
        reverse_written_tx: Mutex<Option<std::sync::mpsc::Sender<()>>>,
        proceed_rx: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    impl IdentityStore for SteppedStore {
        fn get(&self, key: &str) -> Option<String> {
            self.inner.get(key)
        }
        fn set(&self, key: &str, value: String) {
            self.inner.set(key, value);
            if key.starts_with(REVERSE_PREFIX) {
                if let Some(tx) = self.reverse_written_tx.lock().unwrap().take() {
                    let _ = tx.send(());
                    if let Some(rx) = self.proceed_rx.lock().unwrap().take() {
                        let _ = rx.recv();
                    }
                }
            }
        }
        fn remove(&self, key: &str) {
            self.inner.remove(key);
        }
        fn compare_and_swap(&self, key: &str, expected: Option<&str>, new: &str) -> bool {
            self.inner.compare_and_swap(key, expected, new)
        }
    }

    #[test]
    fn get_or_create_persistent_reverse_key_survives_a_racing_remove_local() {
        // Regression: get_or_create_persistent used to CAS the candidate
        // into the forward list, THEN write its reverse key as a separate,
        // later operation. A remove_local landing in that exact gap would
        // see the new forward entry (post-CAS) with no reverse key yet,
        // clean up based on that snapshot (a `remove` on the not-yet-present
        // reverse key is a silent no-op), and finish - after which the
        // writer's now-late reverse-key write created a mapping nothing
        // would ever revisit. Writing the reverse key *before* the forward
        // CAS (and reusing it across retries) closes this. Force the exact
        // interleaving deterministically instead of relying on scheduling
        // luck (see the sibling test above, which never caught this in
        // practice despite exercising the same two operations concurrently).
        use std::sync::{mpsc, Arc};
        use std::thread;

        let (reverse_written_tx, reverse_written_rx) = mpsc::channel();
        let (proceed_tx, proceed_rx) = mpsc::channel();
        let store = SteppedStore {
            inner: InMemoryIdentityStore::new(),
            reverse_written_tx: Mutex::new(Some(reverse_written_tx)),
            proceed_rx: Mutex::new(Some(proceed_rx)),
        };
        let db = Arc::new(IdentDb::new(store, IDP));

        let writer = {
            let db = Arc::clone(&db);
            thread::spawn(move || db.persistent_nameid("alice", Some(SP)))
        };

        // Wait until the writer has written its candidate's reverse key and
        // is paused before attempting its forward CAS.
        reverse_written_rx.recv().unwrap();

        // The candidate isn't in the forward list yet (the writer's CAS
        // hasn't run), so this must be a no-op with respect to it.
        db.remove_local("alice");

        // Let the writer proceed to its forward CAS.
        proceed_tx.send(()).unwrap();
        let minted = writer.join().unwrap();

        let listed = db.name_ids_for("alice");
        assert!(
            listed.iter().any(|n| n.value == minted.value),
            "the minted persistent NameID must end up in the forward list: {listed:?}"
        );
        assert_eq!(
            db.find_local_id(&minted).as_deref(),
            Some("alice"),
            "and its reverse mapping must still resolve, not be orphaned"
        );
    }

    #[test]
    fn store_reverse_key_survives_a_racing_remove_local() {
        // Same fix, same deterministic technique, for store() (the path
        // transient/email/etc. NameIDs go through) rather than
        // get_or_create_persistent. The scheduling-based sibling test above
        // races transient_nameid (-> store()) against remove_local across
        // 20 rounds and 4 threads without ever reproducing this - the
        // window is only a few CPU instructions wide, so a real regression
        // here would ship silently without a deterministic reproduction.
        use std::sync::{mpsc, Arc};
        use std::thread;

        let (reverse_written_tx, reverse_written_rx) = mpsc::channel();
        let (proceed_tx, proceed_rx) = mpsc::channel();
        let store = SteppedStore {
            inner: InMemoryIdentityStore::new(),
            reverse_written_tx: Mutex::new(Some(reverse_written_tx)),
            proceed_rx: Mutex::new(Some(proceed_rx)),
        };
        let db = Arc::new(IdentDb::new(store, IDP));

        let writer = {
            let db = Arc::clone(&db);
            thread::spawn(move || db.transient_nameid("alice", Some(SP)))
        };

        reverse_written_rx.recv().unwrap();
        db.remove_local("alice");
        proceed_tx.send(()).unwrap();
        let minted = writer.join().unwrap();

        let listed = db.name_ids_for("alice");
        assert!(
            listed.iter().any(|n| n.value == minted.value),
            "the minted transient NameID must end up in the forward list: {listed:?}"
        );
        assert_eq!(
            db.find_local_id(&minted).as_deref(),
            Some("alice"),
            "and its reverse mapping must still resolve, not be orphaned"
        );
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
        let nid = db.persistent_nameid("alice", Some(SP));
        db.remove_remote(&nid);
        assert!(db.find_local_id(&nid).is_none());
        assert!(db.name_ids_for("alice").is_empty());

        let n1 = db.persistent_nameid("alice", Some(SP));
        let n2 = db.transient_nameid("alice", Some(SP));
        db.remove_local("alice");
        assert!(db.find_local_id(&n1).is_none());
        assert!(db.find_local_id(&n2).is_none());
    }

    #[test]
    fn test_manage_name_id_new_id_and_terminate() {
        let db = db();
        let nid = db.persistent_nameid("alice", Some(SP));

        let updated = db
            .handle_manage_name_id_request(&nid, &NewIdOrTerminate::NewId("sp-alias".to_string()))
            .unwrap();
        assert_eq!(updated.sp_provided_id.as_deref(), Some("sp-alias"));
        assert_eq!(db.find_local_id(&updated).as_deref(), Some("alice"));
        let stored = db.match_local_id("alice", Some(SP), Some(IDP)).unwrap();
        assert_eq!(stored.sp_provided_id.as_deref(), Some("sp-alias"));

        db.handle_manage_name_id_request(&updated, &NewIdOrTerminate::Terminate)
            .unwrap();
        assert!(db.find_local_id(&updated).is_none());
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
        let nid = db.persistent_nameid("alice", Some(SP));

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
        let nid = db.get_nameid("alice", constants::NAMEID_EMAIL, Some(SP), Some(IDP));
        assert!(nid.value.ends_with("@example.org"));
    }

    #[test]
    fn test_email_format_reverse_mapping_uses_full_value() {
        // The collision check and the reverse index must both key on the
        // final `local-part@domain` value, so the issued email NameID resolves
        // back to its local principal.
        let db = IdentDb::in_memory(IDP).with_domain("example.org");
        let nid = db.get_nameid("alice", constants::NAMEID_EMAIL, Some(SP), Some(IDP));
        assert!(nid.value.contains('@'));
        assert_eq!(db.find_local_id(&nid).as_deref(), Some("alice"));
    }
}
