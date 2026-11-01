// SPDX-License-Identifier: MIT OR Apache-2.0

//! The host's ISSUANCE POLICY: one async call per token issuance, after every check this crate
//! makes and before anything is written, that may refuse the issuance or add claims to an RFC 9068
//! access token.
//!
//! The same seam as OpenID Connect providers' "extra token claims" hooks and Spring Authorization
//! Server's `OAuth2TokenCustomizer`. It exists for rules only the host can decide at issuance
//! time: "this account changed since the user approved", "this resource needs that scope", or a
//! claim a resource server expects (RFC 9068 section 2.2.3 allows claims beyond the required set).
//!
//! WHAT IT CANNOT DO is restate a claim this crate sets. [`ExtraClaims::insert`] refuses every
//! claim name the crate owns, under every feature, so a policy cannot widen `aud`, move `exp` or
//! replace `sub`: the signed token and the stored record would then disagree about what was
//! issued.
//!
//! A refusal is the policy's own [`ErrorResponse`], returned to the client as is. What the grant
//! already consumed stays consumed: an authorization code or a rotated refresh token taken for
//! this request is not put back, exactly as when storing the new token fails.

use std::future::Future;
use std::pin::Pin;
use std::time::SystemTime;

use crate::client::Client;
use crate::error::ErrorResponse;
use crate::grant::GrantType;
use crate::scope::ScopeSet;

/// What is about to be issued, as this crate resolved it.
#[derive(Debug)]
#[non_exhaustive]
pub struct IssuanceContext<'a> {
    /// The client the token is for.
    pub client: &'a Client,
    /// The grant being served.
    pub grant_type: GrantType,
    /// The resource owner, or `None` for a client-only grant.
    pub subject: Option<&'a str>,
    /// The scope as granted (after any narrowing).
    pub scope: &'a ScopeSet,
    /// The RFC 8707 resources the token is for; empty means the configured default audience.
    pub resource: &'a [String],
    /// The instant the grant behind this issuance was authorized; see
    /// [`crate::token::IssuedToken::grant_established_at`].
    pub grant_established_at: SystemTime,
}

/// The claim names this crate sets itself, under any feature. [`ExtraClaims::insert`] refuses them.
pub const RESERVED_CLAIMS: &[&str] = &[
    "iss",
    "sub",
    "aud",
    "exp",
    "nbf",
    "iat",
    "jti",
    "scope",
    "client_id",
    "cnf",
    "act",
    "auth_time",
    "acr",
    "authorization_details",
];

/// Claims a policy adds to an RFC 9068 access token. Empty by default. An opaque access token
/// carries no claims, so with [`crate::jwt::AccessTokenFormat::Opaque`] they are dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtraClaims {
    #[cfg(feature = "jwt")]
    pub(crate) claims: serde_json::Map<String, serde_json::Value>,
}

/// The refusal for a claim name this crate sets itself (see [`RESERVED_CLAIMS`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedClaim(pub String);

impl ExtraClaims {
    /// Add a claim. Refused, and nothing added, when the name is in [`RESERVED_CLAIMS`].
    #[cfg(feature = "jwt")]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
    pub fn insert(
        &mut self,
        name: impl Into<String>,
        value: serde_json::Value,
    ) -> Result<(), ReservedClaim> {
        let name = name.into();
        if RESERVED_CLAIMS.contains(&name.as_str()) {
            return Err(ReservedClaim(name));
        }
        self.claims.insert(name, value);
        Ok(())
    }

    /// True when no claim was added.
    pub fn is_empty(&self) -> bool {
        #[cfg(feature = "jwt")]
        return self.claims.is_empty();
        #[cfg(not(feature = "jwt"))]
        true
    }
}

/// The boxed future an [`IssuancePolicy`] returns. Boxed because the policy is held as a trait
/// object, like every other host seam, and is typically I/O (the host's own store).
pub type IssuanceFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ExtraClaims, ErrorResponse>> + Send + 'a>>;

/// The host's issuance policy. Installed with
/// [`crate::server::AuthorizationServer::with_issuance_policy`]; with none installed every
/// issuance proceeds with no extra claims, as before the seam existed.
///
/// Called exactly once per issued access token, on every grant, after this crate's own checks.
pub trait IssuancePolicy: Send + Sync {
    /// Allow the issuance (with any extra claims) or refuse it with the error the client gets.
    fn check<'a>(&'a self, issuance: &'a IssuanceContext<'a>) -> IssuanceFuture<'a>;
}
