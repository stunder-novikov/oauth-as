// SPDX-License-Identifier: MIT OR Apache-2.0

//! `AuthorizationServer::with_issuance_policy`: called once per issued token on every grant, with
//! what is about to be issued; its refusal is the client's answer; its claims reach the JWT; the
//! claims this crate owns cannot be restated.

#![cfg(feature = "jwt-p256")]

mod support;

use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{json, Value};

use oauth_as::issuance::{
    ExtraClaims, IssuanceContext, IssuanceFuture, IssuancePolicy, ReservedClaim, RESERVED_CLAIMS,
};
use oauth_as::jwt::{AccessTokenFormat, EcdsaP256Key, JwtConfig};
use oauth_as::{
    AuthorizationServer, ClientId, ErrorCode, ErrorResponse, GrantType, MemoryStorage, ScopeSet,
    ServerConfig, TokenRequest,
};
use support::{
    client_credentials_client, mint_code_token_keeping_code, public_client, ManualClock, CC_SECRET,
    PUBLIC_REDIRECT, RFC7636_VERIFIER,
};

/// What the policy saw, one entry per call.
type Seen = Arc<Mutex<Vec<(GrantType, Option<String>, String)>>>;

struct Recording {
    seen: Seen,
    refuse: bool,
}

impl IssuancePolicy for Recording {
    fn check<'a>(&'a self, issuance: &'a IssuanceContext<'a>) -> IssuanceFuture<'a> {
        Box::pin(async move {
            self.seen.lock().unwrap().push((
                issuance.grant_type,
                issuance.subject.map(str::to_string),
                issuance.scope.to_string(),
            ));
            if self.refuse {
                return Err(ErrorResponse::new(ErrorCode::InvalidGrant)
                    .with_description("the host says no"));
            }
            let mut extra = ExtraClaims::default();
            extra.insert("lvl", json!(3)).unwrap();
            Ok(extra)
        })
    }
}

async fn server(policy: Option<Recording>) -> AuthorizationServer<MemoryStorage, ManualClock> {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.access_token_format = AccessTokenFormat::Jwt(Box::new(JwtConfig::new(
        EcdsaP256Key::generate("kid-1"),
        "https://rs.example",
    )));
    let mut srv =
        AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    if let Some(p) = policy {
        srv = srv.with_issuance_policy(Box::new(p));
    }
    srv.register_client(public_client()).await.unwrap();
    srv.register_client(client_credentials_client())
        .await
        .unwrap();
    srv
}

fn payload(token: &str) -> Value {
    let p = token.split('.').nth(1).expect("a JWS");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).unwrap()).unwrap()
}

fn cc() -> TokenRequest {
    TokenRequest::ClientCredentials {
        client_id: ClientId::new("cc-app"),
        client_secret: Some(CC_SECRET.to_string()),
        scope: Some(ScopeSet::parse("api:read").unwrap()),
    }
}

fn redeem(code: String) -> TokenRequest {
    TokenRequest::AuthorizationCode {
        client_id: ClientId::new("public-app"),
        client_secret: None,
        code,
        redirect_uri: Some(PUBLIC_REDIRECT.to_string()),
        code_verifier: Some(RFC7636_VERIFIER.to_string()),
    }
}

#[tokio::test]
async fn called_on_every_grant_and_its_claims_reach_the_token() {
    let seen = Seen::default();
    let srv = server(Some(Recording {
        seen: seen.clone(),
        refuse: false,
    }))
    .await;
    let (code_token, _) =
        mint_code_token_keeping_code(&srv, "public-app", None, PUBLIC_REDIRECT, "read", "user-1")
            .await;
    let refreshed = srv
        .token(TokenRequest::RefreshToken {
            client_id: ClientId::new("public-app"),
            client_secret: None,
            refresh_token: code_token.refresh_token.clone().unwrap(),
            scope: None,
        })
        .await
        .unwrap();
    let cc_token = srv.token(cc()).await.unwrap();

    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            (
                GrantType::AuthorizationCode,
                Some("user-1".into()),
                "read".into()
            ),
            (
                GrantType::RefreshToken,
                Some("user-1".into()),
                "read".into()
            ),
            (GrantType::ClientCredentials, None, "api:read".into()),
        ]
    );
    for t in [&code_token, &refreshed, &cc_token] {
        let claims = payload(&t.access_token);
        assert_eq!(claims["lvl"], 3);
        assert_eq!(
            claims["iss"], "https://as.example",
            "the crate's own claims are intact"
        );
    }
}

#[tokio::test]
async fn a_refusal_is_the_answer_and_the_code_stays_spent() {
    let seen = Seen::default();
    let srv = server(Some(Recording {
        seen: seen.clone(),
        refuse: true,
    }))
    .await;
    let challenge = oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER);
    let req = oauth_as::AuthorizationRequest::from_pairs([
        ("response_type", "code"),
        ("client_id", "public-app"),
        ("redirect_uri", PUBLIC_REDIRECT),
        ("scope", "read"),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]);
    let validated = srv.validate_authorization_request(&req).await.unwrap();
    let code = srv
        .issue_authorization_code(oauth_as::UserApproval::granted(&validated, "user-1"))
        .await
        .unwrap()
        .code;

    let e = srv.token(redeem(code.clone())).await.unwrap_err();
    assert_eq!(e.error, ErrorCode::InvalidGrant);
    assert_eq!(e.error_description.as_deref(), Some("the host says no"));
    // Spent: a second try never reaches the policy.
    let again = srv.token(redeem(code)).await.unwrap_err();
    assert_eq!(again.error, ErrorCode::InvalidGrant);
    assert_eq!(seen.lock().unwrap().len(), 1);

    let e = srv.token(cc()).await.unwrap_err();
    assert_eq!(e.error_description.as_deref(), Some("the host says no"));
}

#[tokio::test]
async fn without_a_policy_nothing_is_added() {
    let srv = server(None).await;
    let t = srv.token(cc()).await.unwrap();
    assert!(payload(&t.access_token).get("lvl").is_none());
}

#[test]
fn every_reserved_name_is_refused() {
    let mut extra = ExtraClaims::default();
    for name in RESERVED_CLAIMS {
        assert_eq!(
            extra.insert(*name, json!("x")),
            Err(ReservedClaim(name.to_string()))
        );
    }
    assert!(extra.is_empty());
    extra.insert("acc", json!("a")).unwrap();
    assert!(!extra.is_empty());
}
