//! Denial reasons for the response orchestrator.
//!
//! A [`Denial`] is a *protocol* refusal — the SP asked for something the IdP
//! cannot or will not provide — as opposed to a programming or configuration
//! fault (which is a `ProfileError`). Every denial is rendered as a **signed**
//! SAML protocol error response, matching what `example-idp` does today: an
//! unsigned denial is trivially forgeable, so the Response envelope is always
//! signed, unconditionally (not gated on `SignTargets`).
//!
//! The enum is closed and its [`Denial::status`] mapping is fixed and total.
//! The `StatusMessage` is always a fixed, IdP-controlled string — never an
//! echo of SP-supplied input — so a hostile `NameIDPolicy`, attribute name, or
//! other request field cannot inject markup into the signed error.

use crate::core::constants;
use crate::core::protocol::status::Status;

/// A protocol-level refusal to satisfy an AuthnRequest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    /// `IsPassive` was set but no reusable session exists (or `ForceAuthn`
    /// defeated reuse). The IdP cannot authenticate without user interaction.
    NoPassive,
    /// The requested `RequestedAuthnContext` cannot be satisfied by any
    /// registered authentication method.
    NoAuthnContext,
    /// The requested `NameIDPolicy/@Format` is not one this IdP can issue.
    InvalidNameIdPolicy,
    /// The `NameIDPolicy` forbids creating a new identifier (`AllowCreate=false`)
    /// and no existing identifier is available.
    NameIdCreationNotAllowed,
    /// A required attribute (per the SP's `AttributeConsumingService` and
    /// `fail_on_missing_requested`) could not be released.
    MissingRequiredAttributes,
}

impl Denial {
    /// The SAML `Status` this denial maps to.
    ///
    /// The mapping is fixed:
    /// - `NoPassive` → `Responder/NoPassive`
    /// - `NoAuthnContext` → `Responder/NoAuthnContext`
    /// - `InvalidNameIdPolicy` / `NameIdCreationNotAllowed` →
    ///   `Requester/InvalidNameIDPolicy`
    /// - `MissingRequiredAttributes` → `Requester/InvalidAttrNameOrValue`
    pub fn status(&self) -> Status {
        match self {
            Denial::NoPassive => Status::with_sub_status(
                constants::STATUS_RESPONDER,
                constants::STATUS_NO_PASSIVE,
                Some(
                    "Passive authentication is not possible without a reusable session"
                        .to_string(),
                ),
            ),
            Denial::NoAuthnContext => Status::with_sub_status(
                constants::STATUS_RESPONDER,
                constants::STATUS_NO_AUTHN_CONTEXT,
                Some("The requested authentication context is unavailable".to_string()),
            ),
            Denial::InvalidNameIdPolicy => Status::with_sub_status(
                constants::STATUS_REQUESTER,
                constants::STATUS_INVALID_NAMEID_POLICY,
                Some("The requested NameID format is not supported".to_string()),
            ),
            Denial::NameIdCreationNotAllowed => Status::with_sub_status(
                constants::STATUS_REQUESTER,
                constants::STATUS_INVALID_NAMEID_POLICY,
                Some("The NameIDPolicy does not allow creating a new identifier".to_string()),
            ),
            Denial::MissingRequiredAttributes => Status::with_sub_status(
                constants::STATUS_REQUESTER,
                constants::STATUS_INVALID_ATTR_NAME_OR_VALUE,
                Some("A required attribute is missing".to_string()),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exhaustive mapping: every denial variant produces exactly the expected
    /// (top-level, sub-status) pair and a non-empty, fixed message.
    #[test]
    fn status_mapping_is_fixed_and_total() {
        let cases: &[(Denial, &str, &str)] = &[
            (
                Denial::NoPassive,
                constants::STATUS_RESPONDER,
                constants::STATUS_NO_PASSIVE,
            ),
            (
                Denial::NoAuthnContext,
                constants::STATUS_RESPONDER,
                constants::STATUS_NO_AUTHN_CONTEXT,
            ),
            (
                Denial::InvalidNameIdPolicy,
                constants::STATUS_REQUESTER,
                constants::STATUS_INVALID_NAMEID_POLICY,
            ),
            (
                Denial::NameIdCreationNotAllowed,
                constants::STATUS_REQUESTER,
                constants::STATUS_INVALID_NAMEID_POLICY,
            ),
            (
                Denial::MissingRequiredAttributes,
                constants::STATUS_REQUESTER,
                constants::STATUS_INVALID_ATTR_NAME_OR_VALUE,
            ),
        ];

        for (denial, expected_top, expected_sub) in cases {
            let status = denial.status();
            assert!(
                !status.is_success(),
                "{denial:?} must not be a success status"
            );
            assert_eq!(
                status.status_code.value.as_str(),
                *expected_top,
                "{denial:?} top-level status"
            );
            let sub = status
                .status_code
                .sub_status
                .as_ref()
                .expect("{denial:?} must carry a sub-status");
            assert_eq!(
                sub.value.as_str(),
                *expected_sub,
                "{denial:?} sub-status"
            );
            // The message is always present and is a fixed IdP string.
            assert!(
                status.status_message.as_ref().is_some_and(|m| !m.is_empty()),
                "{denial:?} must carry a status message"
            );
        }
    }

    /// The two NameID denials share a wire status but are distinct variants, so
    /// an integrator can still tell them apart for logging.
    #[test]
    fn nameid_denials_share_status_but_are_distinct() {
        assert_ne!(
            Denial::InvalidNameIdPolicy,
            Denial::NameIdCreationNotAllowed
        );
        assert_eq!(
            Denial::InvalidNameIdPolicy.status().status_code.value,
            Denial::NameIdCreationNotAllowed.status().status_code.value
        );
        assert_eq!(
            Denial::InvalidNameIdPolicy
                .status()
                .status_code
                .sub_status
                .unwrap()
                .value,
            Denial::NameIdCreationNotAllowed
                .status()
                .status_code
                .sub_status
                .unwrap()
                .value
        );
    }

    /// No denial message interpolates SP-supplied input: the message is one of a
    /// fixed set, so a hostile request field cannot inject markup.
    #[test]
    fn messages_are_a_fixed_set() {
        let messages: Vec<String> = [
            Denial::NoPassive,
            Denial::NoAuthnContext,
            Denial::InvalidNameIdPolicy,
            Denial::NameIdCreationNotAllowed,
            Denial::MissingRequiredAttributes,
        ]
        .iter()
        .map(|d| d.status().status_message.clone().unwrap())
        .collect();

        // Every message is non-empty and contains no markup-significant
        // characters that a hostile input could have introduced.
        for m in &messages {
            assert!(!m.is_empty());
            assert!(!m.contains('<'), "message must not contain '<': {m}");
            assert!(!m.contains('>'), "message must not contain '>': {m}");
        }
    }
}
