//! A reusable check that an [`IdentityStore`] backend honours the contract
//! [`IdentDb`] relies on.
//!
//! The two uniqueness constraints (NameID value; persistent `(user,
//! sp_name_qualifier, name_qualifier)`) live in the backend, not in this
//! crate, so a backend that forgets one - say a missing unique index -
//! compiles fine and only misbehaves under concurrent load. Run the suite
//! against a real instance (e.g. in the integration suite of the crate that
//! implements the Mongo store) to catch that.
//!
//! Three entry points, from most to least convenient for a Rust test:
//!
//! - [`run`] panics with a description of the first violated rule.
//! - [`check`] / [`check_with`] return the first violation as a
//!   [`ConformanceError`], for a caller that is not a Rust test (a binding to
//!   another language, a CLI) and must not panic.
//! - [`check_one`] runs a single check by name; [`CHECKS`] lists the names, so
//!   a test runner can report which constraint a backend is missing.
//!
//! `new_store` must return a **fresh, empty** store on every call: a new
//! collection or table, or one that has been cleared. Each check gets its own.
//!
//! # What this does and does not prove
//!
//! The two concurrent checks race threads against one store instance. They
//! catch a backend that has no unique constraint when its calls genuinely
//! overlap, which a network backend does. A backend that serialises every call
//! (an in-memory store behind one lock, or a binding that holds a global lock
//! across the call) can pass them without having the constraint. They cannot
//! detect a race between separate processes or instances.

use super::*;
use std::fmt;
use std::sync::Arc;
use std::thread;

const IDP: &str = "https://idp.example.com";
const SP_A: &str = "https://sp-a.example.com";
const SP_B: &str = "https://sp-b.example.com";

/// A check that failed, and what it found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceError {
    /// The name of the failing check (one of [`CHECKS`]).
    pub check: &'static str,
    /// What was violated, or which backend operation failed.
    pub message: String,
}

impl fmt::Display for ConformanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.check, self.message)
    }
}

impl std::error::Error for ConformanceError {}

/// Tuning for a run.
#[derive(Debug, Clone)]
pub struct Options {
    /// Threads used by the concurrent checks (at least 2 are always used).
    pub threads: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options { threads: 16 }
    }
}

/// The names of every check, in the order [`check`] runs them.
pub const CHECKS: &[&str] = &[
    "value_is_unique",
    "lookups_round_trip_and_isolate_users",
    "persistent_is_get_or_insert",
    "persistent_insert_reports_a_taken_value",
    "persistent_is_unique_on_every_write_path",
    "find_persistent_is_format_and_qualifier_exact",
    "find_filters_on_every_field",
    "replace_upserts_by_value",
    "removal_is_scoped",
    "concurrent_get_or_insert_converges_on_one_identifier",
    "concurrent_insert_of_one_value_has_one_winner",
];

type Outcome = Result<(), String>;

/// Fail the check with a message unless `cond` holds.
macro_rules! ensure {
    ($cond:expr, $($msg:tt)+) => {
        if !$cond {
            return Err(format!($($msg)+));
        }
    };
}

/// Fail the check, showing both values, unless `left == right`.
macro_rules! ensure_eq {
    ($left:expr, $right:expr, $($msg:tt)+) => {{
        let (left, right) = (&$left, &$right);
        if left != right {
            return Err(format!(
                "{} (got {left:?}, expected {right:?})",
                format!($($msg)+)
            ));
        }
    }};
}

/// A backend call that failed is a failed check, naming the operation.
fn step<T, E: fmt::Display>(what: &str, result: Result<T, E>) -> Result<T, String> {
    result.map_err(|e| format!("backend call `{what}` failed: {e}"))
}

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

type CheckFn<S> = fn(S, &Options) -> Outcome;

fn table<S: IdentityStore + 'static>() -> Vec<(&'static str, CheckFn<S>)> {
    let table: Vec<(&'static str, CheckFn<S>)> = vec![
        ("value_is_unique", |s, _| value_is_unique(&s)),
        ("lookups_round_trip_and_isolate_users", |s, _| {
            lookups_round_trip_and_isolate_users(&s)
        }),
        ("persistent_is_get_or_insert", |s, _| {
            persistent_is_get_or_insert(&s)
        }),
        ("persistent_insert_reports_a_taken_value", |s, _| {
            persistent_insert_reports_a_taken_value(&s)
        }),
        ("persistent_is_unique_on_every_write_path", |s, _| {
            persistent_is_unique_on_every_write_path(&s)
        }),
        ("find_persistent_is_format_and_qualifier_exact", |s, _| {
            find_persistent_is_format_and_qualifier_exact(&s)
        }),
        ("find_filters_on_every_field", |s, _| {
            find_filters_on_every_field(&s)
        }),
        ("replace_upserts_by_value", |s, _| {
            replace_upserts_by_value(&s)
        }),
        ("removal_is_scoped", |s, _| removal_is_scoped(&s)),
        (
            "concurrent_get_or_insert_converges_on_one_identifier",
            concurrent_get_or_insert_converges_on_one_identifier,
        ),
        (
            "concurrent_insert_of_one_value_has_one_winner",
            concurrent_insert_of_one_value_has_one_winner,
        ),
    ];
    debug_assert_eq!(
        table.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        CHECKS
    );
    table
}

/// Run every check against stores produced by `new_store`, panicking with a
/// description of the first violated rule.
pub fn run<S, F>(new_store: F)
where
    S: IdentityStore + 'static,
    F: Fn() -> S,
{
    if let Err(e) = check(new_store) {
        panic!("{e}");
    }
}

/// Run every check with default [`Options`], returning the first violation.
pub fn check<S, F>(new_store: F) -> Result<(), ConformanceError>
where
    S: IdentityStore + 'static,
    F: Fn() -> S,
{
    check_with(new_store, &Options::default())
}

/// Run every check, returning the first violation.
pub fn check_with<S, F>(new_store: F, options: &Options) -> Result<(), ConformanceError>
where
    S: IdentityStore + 'static,
    F: Fn() -> S,
{
    for (check, run) in table::<S>() {
        run(new_store(), options).map_err(|message| ConformanceError { check, message })?;
    }
    Ok(())
}

/// Run the single check called `name` (one of [`CHECKS`]) against a store from
/// `new_store`. An unknown name is an error that lists the known ones.
pub fn check_one<S, F>(name: &str, new_store: F, options: &Options) -> Result<(), ConformanceError>
where
    S: IdentityStore + 'static,
    F: Fn() -> S,
{
    match table::<S>().into_iter().find(|(n, _)| *n == name) {
        Some((check, run)) => {
            run(new_store(), options).map_err(|message| ConformanceError { check, message })
        }
        None => Err(ConformanceError {
            check: "check_one",
            message: format!("no check named {name:?}; known checks: {CHECKS:?}"),
        }),
    }
}

fn value_is_unique<S: IdentityStore>(s: &S) -> Outcome {
    let first = nid("v1", constants::NAMEID_EMAIL, Some(SP_A));
    step("insert", s.insert("alice", first.clone()))?;
    match s.insert("bob", nid("v1", constants::NAMEID_EMAIL, Some(SP_B))) {
        Err(InsertError::ValueTaken) => {}
        Ok(()) => {
            return Err("a value already in use must be rejected, for any user".to_string());
        }
        Err(e) => return Err(format!("backend call `insert` failed: {e}")),
    }
    let owner = step("user_for", s.user_for("v1"))?;
    ensure_eq!(
        owner.as_deref(),
        Some("alice"),
        "the first owner keeps the value"
    );
    let alice = step("for_user", s.for_user("alice"))?;
    ensure_eq!(alice, vec![first], "loser must not overwrite");
    ensure!(
        step("for_user", s.for_user("bob"))?.is_empty(),
        "the rejected insert must not leave a record for the loser"
    );
    Ok(())
}

fn lookups_round_trip_and_isolate_users<S: IdentityStore>(s: &S) -> Outcome {
    step(
        "insert",
        s.insert("alice", nid("a1", constants::NAMEID_EMAIL, Some(SP_A))),
    )?;
    step(
        "insert",
        s.insert("bob", nid("b1", constants::NAMEID_EMAIL, Some(SP_A))),
    )?;
    let a1 = step("user_for", s.user_for("a1"))?;
    ensure_eq!(a1.as_deref(), Some("alice"), "user_for a1");
    let b1 = step("user_for", s.user_for("b1"))?;
    ensure_eq!(b1.as_deref(), Some("bob"), "user_for b1");
    ensure_eq!(
        step("user_for", s.user_for("nobody"))?,
        None,
        "an unknown value has no user"
    );
    let alice = step("for_user", s.for_user("alice"))?;
    ensure_eq!(alice.len(), 1, "for_user returns only that user's records");
    ensure_eq!(alice[0].value.as_str(), "a1", "for_user alice");
    ensure!(
        step("for_user", s.for_user("carol"))?.is_empty(),
        "a user with no records has none"
    );
    Ok(())
}

fn persistent_is_get_or_insert<S: IdentityStore>(s: &S) -> Outcome {
    let first = step(
        "get_or_insert_persistent",
        s.get_or_insert_persistent("alice", persistent("p1", SP_A)),
    )?;
    ensure_eq!(
        first.value.as_str(),
        "p1",
        "the first candidate is inserted"
    );
    let again = step(
        "get_or_insert_persistent",
        s.get_or_insert_persistent("alice", persistent("p2", SP_A)),
    )?;
    ensure_eq!(
        again.value.as_str(),
        "p1",
        "a second candidate for the same (user, SP) must return the existing one"
    );
    ensure!(
        step("user_for", s.user_for("p2"))?.is_none(),
        "the losing candidate must not be stored"
    );
    let other_sp = step(
        "get_or_insert_persistent",
        s.get_or_insert_persistent("alice", persistent("p3", SP_B)),
    )?;
    ensure_eq!(
        other_sp.value.as_str(),
        "p3",
        "a different SP gets its own identifier"
    );
    let other_user = step(
        "get_or_insert_persistent",
        s.get_or_insert_persistent("bob", persistent("p4", SP_A)),
    )?;
    ensure_eq!(
        other_user.value.as_str(),
        "p4",
        "a different user gets their own"
    );
    Ok(())
}

fn persistent_insert_reports_a_taken_value<S: IdentityStore>(s: &S) -> Outcome {
    step(
        "insert",
        s.insert("alice", nid("taken", constants::NAMEID_EMAIL, Some(SP_A))),
    )?;
    match s.get_or_insert_persistent("bob", persistent("taken", SP_A)) {
        Err(InsertError::ValueTaken) => {}
        Ok(_) => {
            return Err(
                "no existing persistent record, but the value is taken by another user".to_string(),
            );
        }
        Err(e) => {
            return Err(format!(
                "backend call `get_or_insert_persistent` failed: {e}"
            ))
        }
    }
    let owner = step("user_for", s.user_for("taken"))?;
    ensure_eq!(
        owner.as_deref(),
        Some("alice"),
        "the original owner keeps the value"
    );
    Ok(())
}

fn persistent_is_unique_on_every_write_path<S: IdentityStore>(s: &S) -> Outcome {
    step(
        "get_or_insert_persistent",
        s.get_or_insert_persistent("alice", persistent("p1", SP_A)),
    )?;

    // A second persistent record for the same (user, SP, NameQualifier), written
    // with a different value, must be refused on `insert` and on `replace`, not
    // only through `get_or_insert_persistent`. A backend whose partial unique
    // index is missing, or whose other write paths bypass it, would otherwise
    // hold two "stable" identifiers for one (user, SP).
    match s.insert("alice", persistent("p2", SP_A)) {
        Err(InsertError::PersistentExists) => {}
        Ok(()) => {
            return Err(
                "insert accepted a second persistent record for the same (user, \
                        SPNameQualifier, NameQualifier): the persistent uniqueness \
                        constraint is missing or does not cover insert"
                    .to_string(),
            );
        }
        Err(InsertError::ValueTaken) => {
            return Err("insert reported ValueTaken for a fresh value; expected \
                        PersistentExists"
                .to_string());
        }
        Err(e) => return Err(format!("backend call `insert` failed: {e}")),
    }
    match s.replace("alice", persistent("p3", SP_A)) {
        Err(InsertError::PersistentExists) => {}
        Ok(()) => {
            return Err(
                "replace accepted a second persistent record for the same (user, \
                        SPNameQualifier, NameQualifier): the persistent uniqueness \
                        constraint is missing or does not cover replace"
                    .to_string(),
            );
        }
        Err(InsertError::ValueTaken) => {
            return Err("replace reported ValueTaken; it upserts by value".to_string());
        }
        Err(e) => return Err(format!("backend call `replace` failed: {e}")),
    }

    // Nothing was written by the refused attempts.
    let alice = step("for_user", s.for_user("alice"))?;
    ensure_eq!(
        alice.len(),
        1,
        "a refused write must not leave a record behind"
    );
    ensure_eq!(alice[0].value.as_str(), "p1", "the original record is kept");
    ensure!(
        step("user_for", s.user_for("p2"))?.is_none()
            && step("user_for", s.user_for("p3"))?.is_none(),
        "a refused write must not be findable by its value"
    );

    // The constraint is exactly (user, SPNameQualifier, NameQualifier, persistent):
    // other users, other SPs and other formats are unaffected...
    step("insert", s.insert("alice", persistent("p4", SP_B)))?;
    step("insert", s.insert("bob", persistent("p5", SP_A)))?;
    step(
        "insert",
        s.insert("alice", nid("e1", constants::NAMEID_EMAIL, Some(SP_A))),
    )?;
    // ...and the existing persistent record can still be updated in place.
    let mut updated = persistent("p1", SP_A);
    updated.sp_provided_id = Some("alias".to_string());
    step("replace", s.replace("alice", updated))?;
    Ok(())
}

fn find_persistent_is_format_and_qualifier_exact<S: IdentityStore>(s: &S) -> Outcome {
    step(
        "insert",
        s.insert("alice", nid("e1", constants::NAMEID_EMAIL, Some(SP_A))),
    )?;
    ensure!(
        step(
            "find_persistent",
            s.find_persistent("alice", Some(SP_A), Some(IDP))
        )?
        .is_none(),
        "a non-persistent record must never satisfy a persistent lookup"
    );
    step(
        "get_or_insert_persistent",
        s.get_or_insert_persistent("alice", persistent("p1", SP_A)),
    )?;
    let found = step(
        "find_persistent",
        s.find_persistent("alice", Some(SP_A), Some(IDP)),
    )?
    .map(|n| n.value);
    ensure_eq!(
        found,
        Some("p1".to_string()),
        "the persistent record is found by its qualifiers"
    );
    ensure!(
        step(
            "find_persistent",
            s.find_persistent("alice", Some(SP_B), Some(IDP))
        )?
        .is_none(),
        "a different SPNameQualifier must not match"
    );
    ensure!(
        step(
            "find_persistent",
            s.find_persistent("alice", None, Some(IDP))
        )?
        .is_none(),
        "a None qualifier means the record has no such qualifier"
    );
    Ok(())
}

fn find_values<S: IdentityStore>(s: &S, filter: NameIdFilter) -> Result<Vec<String>, String> {
    let mut values: Vec<String> = step("find", s.find("alice", &filter))?
        .into_iter()
        .map(|n| n.value)
        .collect();
    values.sort();
    Ok(values)
}

fn find_filters_on_every_field<S: IdentityStore>(s: &S) -> Outcome {
    let mut with_alias = nid("f1", constants::NAMEID_EMAIL, Some(SP_A));
    with_alias.sp_provided_id = Some("alias".to_string());
    step("insert", s.insert("alice", with_alias))?;
    step(
        "insert",
        s.insert("alice", nid("f2", constants::NAMEID_EMAIL, Some(SP_B))),
    )?;
    step(
        "get_or_insert_persistent",
        s.get_or_insert_persistent("alice", persistent("f3", SP_A)),
    )?;
    step(
        "insert",
        s.insert("bob", nid("f4", constants::NAMEID_EMAIL, Some(SP_A))),
    )?;

    ensure_eq!(
        find_values(s, NameIdFilter::default())?,
        ["f1", "f2", "f3"],
        "an empty filter matches every record of the user, and no one else's"
    );
    ensure_eq!(
        find_values(
            s,
            NameIdFilter {
                format: Some(constants::NAMEID_EMAIL.to_string()),
                ..Default::default()
            }
        )?,
        ["f1", "f2"],
        "format filters"
    );
    ensure_eq!(
        find_values(
            s,
            NameIdFilter {
                sp_name_qualifier: Some(SP_A.to_string()),
                ..Default::default()
            }
        )?,
        ["f1", "f3"],
        "sp_name_qualifier filters"
    );
    ensure_eq!(
        find_values(
            s,
            NameIdFilter {
                name_qualifier: Some(IDP.to_string()),
                ..Default::default()
            }
        )?,
        ["f1", "f2", "f3"],
        "name_qualifier filters"
    );
    ensure_eq!(
        find_values(
            s,
            NameIdFilter {
                sp_provided_id: Some("alias".to_string()),
                ..Default::default()
            }
        )?,
        ["f1"],
        "sp_provided_id filters, and a record without one does not match"
    );
    ensure_eq!(
        find_values(
            s,
            NameIdFilter {
                format: Some(constants::NAMEID_EMAIL.to_string()),
                sp_name_qualifier: Some(SP_A.to_string()),
                ..Default::default()
            }
        )?,
        ["f1"],
        "fields combine with AND"
    );
    ensure!(
        find_values(
            s,
            NameIdFilter {
                sp_name_qualifier: Some("https://nobody.example.com".to_string()),
                ..Default::default()
            }
        )?
        .is_empty(),
        "a filter that nothing satisfies matches nothing"
    );
    Ok(())
}

fn replace_upserts_by_value<S: IdentityStore>(s: &S) -> Outcome {
    step(
        "replace",
        s.replace("alice", nid("r1", constants::NAMEID_EMAIL, Some(SP_A))),
    )?;
    let mut updated = nid("r1", constants::NAMEID_EMAIL, Some(SP_A));
    updated.sp_provided_id = Some("alias".to_string());
    step("replace", s.replace("alice", updated.clone()))?;
    let alice = step("for_user", s.for_user("alice"))?;
    ensure_eq!(
        alice,
        vec![updated],
        "replace must update in place, not add a second record for the value"
    );
    step(
        "replace",
        s.replace("bob", nid("r1", constants::NAMEID_EMAIL, Some(SP_A))),
    )?;
    let owner = step("user_for", s.user_for("r1"))?;
    ensure_eq!(owner.as_deref(), Some("bob"), "replace reassigns");
    ensure!(
        step("for_user", s.for_user("alice"))?.is_empty(),
        "the previous owner no longer has the record"
    );
    Ok(())
}

fn removal_is_scoped<S: IdentityStore>(s: &S) -> Outcome {
    step(
        "insert",
        s.insert("alice", nid("x1", constants::NAMEID_EMAIL, Some(SP_A))),
    )?;
    step(
        "insert",
        s.insert("alice", nid("x2", constants::NAMEID_EMAIL, Some(SP_B))),
    )?;
    step(
        "insert",
        s.insert("bob", nid("x3", constants::NAMEID_EMAIL, Some(SP_A))),
    )?;
    step("remove", s.remove("x1"))?;
    ensure_eq!(
        step("user_for", s.user_for("x1"))?,
        None,
        "a removed value is gone"
    );
    let alice = step("for_user", s.for_user("alice"))?;
    ensure_eq!(alice.len(), 1, "remove drops one record only");
    // Removing an absent value is not an error.
    step("remove", s.remove("no-such-value"))?;
    step("remove_all", s.remove_all("alice"))?;
    ensure!(
        step("for_user", s.for_user("alice"))?.is_empty(),
        "remove_all clears the user's records"
    );
    ensure_eq!(
        step("user_for", s.user_for("x2"))?,
        None,
        "remove_all clears the value lookup too"
    );
    let bob = step("user_for", s.user_for("x3"))?;
    ensure_eq!(bob.as_deref(), Some("bob"), "other users untouched");
    Ok(())
}

/// Join every worker, turning a panicked thread into a failed check.
fn join_all<T>(handles: Vec<thread::JoinHandle<Result<T, String>>>) -> Result<Vec<T>, String> {
    handles
        .into_iter()
        .map(|h| {
            h.join()
                .map_err(|_| "a worker thread panicked".to_string())?
        })
        .collect()
}

fn concurrent_get_or_insert_converges_on_one_identifier<S>(store: S, options: &Options) -> Outcome
where
    S: IdentityStore + 'static,
{
    let store = Arc::new(store);
    let handles: Vec<_> = (0..options.threads.max(2))
        .map(|i| {
            let store = Arc::clone(&store);
            thread::spawn(move || -> Result<String, String> {
                // Retry on ValueTaken exactly as IdentDb does.
                loop {
                    let candidate = persistent(&format!("c{i}"), SP_A);
                    match store.get_or_insert_persistent("alice", candidate) {
                        Ok(winner) => return Ok(winner.value),
                        Err(InsertError::ValueTaken) => continue,
                        Err(e) => {
                            return Err(format!(
                                "backend call `get_or_insert_persistent` failed: {e}"
                            ))
                        }
                    }
                }
            })
        })
        .collect();
    let values = join_all(handles)?;
    ensure!(
        values.iter().all(|v| v == &values[0]),
        "concurrent first requests for one (user, SP) minted different \
         persistent identifiers - the backend is missing its uniqueness \
         constraint on (user, sp_name_qualifier, name_qualifier): {values:?}"
    );
    let stored = step("for_user", store.for_user("alice"))?
        .into_iter()
        .filter(|n| n.format.as_deref() == Some(constants::NAMEID_PERSISTENT))
        .count();
    ensure_eq!(stored, 1, "exactly one persistent record must be stored");
    Ok(())
}

fn concurrent_insert_of_one_value_has_one_winner<S>(store: S, options: &Options) -> Outcome
where
    S: IdentityStore + 'static,
{
    let store = Arc::new(store);
    let handles: Vec<_> = (0..options.threads.max(2))
        .map(|i| {
            let store = Arc::clone(&store);
            thread::spawn(move || -> Result<bool, String> {
                match store.insert(
                    &format!("user{i}"),
                    nid("same", constants::NAMEID_EMAIL, Some(SP_A)),
                ) {
                    Ok(()) => Ok(true),
                    Err(InsertError::ValueTaken) => Ok(false),
                    // A backend failure is not a lost race: do not count it as one.
                    Err(e) => Err(format!("backend call `insert` failed: {e}")),
                }
            })
        })
        .collect();
    let winners = join_all(handles)?.into_iter().filter(|won| *won).count();
    ensure_eq!(
        winners,
        1,
        "exactly one concurrent insert of a value may succeed - the \
         backend is missing its uniqueness constraint on the NameID value"
    );
    Ok(())
}
