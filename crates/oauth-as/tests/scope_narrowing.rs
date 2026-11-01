// SPDX-License-Identifier: MIT OR Apache-2.0

//! `ServerConfig::narrow_requested_scope` (RFC 6749 section 3.3): off, a scope wider than the
//! registration is refused; on, it is narrowed to the allowed part. An empty intersection is still
//! refused at authorize, and returned as an empty scope at the token endpoint.

mod support;

use oauth_as::{
    AuthorizationRequest, AuthorizationServer, ClientId, ErrorCode, MemoryStorage, ScopeSet,
    ServerConfig, TokenRequest,
};
use support::{
    client_credentials_client, public_client, ManualClock, CC_SECRET, PUBLIC_REDIRECT,
    RFC7636_VERIFIER,
};

async fn server(narrow: bool) -> AuthorizationServer<MemoryStorage, ManualClock> {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.narrow_requested_scope = narrow;
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    srv.register_client(public_client()).await.unwrap();
    srv.register_client(client_credentials_client())
        .await
        .unwrap();
    srv
}

fn authorize(scope: &str) -> AuthorizationRequest<'static> {
    AuthorizationRequest::from_pairs([
        ("response_type", "code".to_string()),
        ("client_id", "public-app".to_string()),
        ("redirect_uri", PUBLIC_REDIRECT.to_string()),
        ("scope", scope.to_string()),
        (
            "code_challenge",
            oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER),
        ),
        ("code_challenge_method", "S256".to_string()),
    ])
}

fn cc(scope: &str) -> TokenRequest {
    TokenRequest::ClientCredentials {
        client_id: ClientId::new("cc-app"),
        client_secret: Some(CC_SECRET.to_string()),
        scope: Some(ScopeSet::parse(scope).unwrap()),
    }
}

#[tokio::test]
async fn off_a_wider_scope_is_refused_on_both_endpoints() {
    let srv = server(false).await;
    assert!(srv
        .validate_authorization_request(&authorize("read other"))
        .await
        .is_err());
    let e = srv.token(cc("api:read other")).await.unwrap_err();
    assert_eq!(e.error, ErrorCode::InvalidScope);
}

#[tokio::test]
async fn on_authorize_narrows_to_the_allowed_part() {
    let srv = server(true).await;
    let v = srv
        .validate_authorization_request(&authorize("read other write"))
        .await
        .expect("narrowed, not refused");
    assert_eq!(v.scope, ScopeSet::parse("read write").unwrap());
}

#[tokio::test]
async fn on_authorize_still_refuses_when_nothing_is_allowed() {
    let srv = server(true).await;
    assert!(srv
        .validate_authorization_request(&authorize("other"))
        .await
        .is_err());
}

#[tokio::test]
async fn on_client_credentials_narrows_and_reports_the_granted_scope() {
    let srv = server(true).await;
    let t = srv
        .token(cc("api:read other"))
        .await
        .expect("narrowed, not refused");
    assert_eq!(t.scope.as_deref(), Some("api:read"));
}

#[tokio::test]
async fn on_client_credentials_returns_an_empty_intersection_for_the_host_to_judge() {
    let srv = server(true).await;
    let t = srv
        .token(cc("other"))
        .await
        .expect("empty is the host's call");
    assert_eq!(t.scope, None);
}
