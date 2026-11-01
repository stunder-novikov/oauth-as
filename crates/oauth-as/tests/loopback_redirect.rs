// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 8252 section 7.3: a native (public) client's loopback IP redirect matches with any port,
//! because the app binds an ephemeral one. Everything else about the URI stays exact, the code is
//! pinned to the port it was issued for, and `localhost` relaxes only when the host opts in.

mod support;

use oauth_as::server::UserApproval;
use oauth_as::{
    AuthorizationError, AuthorizationRequest, AuthorizationServer, Client, ClientAuth, ClientId,
    ErrorCode, GrantType, MemoryStorage, ScopeSet, ServerConfig, TokenRequest,
};
use support::{ManualClock, RFC7636_VERIFIER};

fn native(id: &str, auth: ClientAuth) -> Client {
    Client {
        client_id: ClientId::new(id),
        auth,
        grant_types: vec![GrantType::AuthorizationCode],
        redirect_uris: vec![
            "http://127.0.0.1/cb".into(),
            "http://[::1]:8000/cb".into(),
            "http://localhost/cb".into(),
            "http://app.example/cb".into(),
        ],
        allowed_scopes: ScopeSet::parse("read").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
        registration: None,
    }
}

async fn server(localhost: bool) -> AuthorizationServer<MemoryStorage, ManualClock> {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.loopback_redirect_localhost = localhost;
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    srv.register_client(native("native", ClientAuth::Public))
        .await
        .unwrap();
    srv.register_client(native(
        "confidential",
        ClientAuth::ConfidentialSecret {
            secret: "loopback-secret".into(),
        },
    ))
    .await
    .unwrap();
    srv
}

fn request(client: &str, redirect: &str) -> AuthorizationRequest<'static> {
    AuthorizationRequest::from_pairs([
        ("response_type", "code".to_string()),
        ("client_id", client.to_string()),
        ("redirect_uri", redirect.to_string()),
        ("scope", "read".to_string()),
        (
            "code_challenge",
            oauth_as::pkce::code_challenge_s256(RFC7636_VERIFIER),
        ),
        ("code_challenge_method", "S256".to_string()),
    ])
}

async fn accepted(
    srv: &AuthorizationServer<MemoryStorage, ManualClock>,
    client: &str,
    uri: &str,
) -> Option<String> {
    srv.validate_authorization_request(&request(client, uri))
        .await
        .ok()
        .map(|v| v.redirect_uri)
}

#[tokio::test]
async fn a_public_clients_loopback_ip_redirect_takes_any_port_and_keeps_the_presented_one() {
    let srv = server(false).await;
    for uri in [
        "http://127.0.0.1:49152/cb",
        "http://127.0.0.1/cb",
        "http://[::1]:61000/cb",
        "http://[::1]/cb",
    ] {
        assert_eq!(
            accepted(&srv, "native", uri).await.as_deref(),
            Some(uri),
            "{uri}"
        );
    }
}

#[tokio::test]
async fn every_part_but_the_port_stays_exact() {
    let srv = server(true).await;
    for uri in [
        "http://127.0.0.1:49152/cb/other",
        "http://127.0.0.1:49152/cb?x=1",
        "http://127.0.0.1:49152/CB",
        "http://127.0.0.2:49152/cb",
        "https://127.0.0.1:49152/cb",
        "http://user@127.0.0.1:49152/cb",
        "http://127.0.0.1:99999/cb",
        "http://127.0.0.1:/cb",
        "http://127.0.0.1:4a/cb",
        "http://[::1]x:80/cb",
        "http://app.example:8080/cb",
    ] {
        assert_eq!(accepted(&srv, "native", uri).await, None, "{uri}");
    }
}

#[tokio::test]
async fn localhost_relaxes_only_with_the_opt_in() {
    let uri = "http://localhost:50000/cb";
    assert_eq!(accepted(&server(false).await, "native", uri).await, None);
    assert_eq!(
        accepted(&server(true).await, "native", uri)
            .await
            .as_deref(),
        Some(uri)
    );
}

#[tokio::test]
async fn a_confidential_clients_loopback_redirect_stays_exact() {
    let srv = server(true).await;
    assert_eq!(
        accepted(&srv, "confidential", "http://127.0.0.1:49152/cb").await,
        None
    );
    let refused = srv
        .validate_authorization_request(&request("confidential", "http://127.0.0.1:49152/cb"))
        .await
        .unwrap_err();
    match refused {
        AuthorizationError::Direct(e) => assert_eq!(e.error, ErrorCode::InvalidRequest),
        other => panic!("a mismatched redirect is never redirected to: {other:?}"),
    }
}

#[tokio::test]
async fn the_code_is_pinned_to_the_port_it_was_issued_for() {
    let srv = server(false).await;
    let v = srv
        .validate_authorization_request(&request("native", "http://127.0.0.1:49152/cb"))
        .await
        .unwrap();
    let code = srv
        .issue_authorization_code(UserApproval::granted(&v, "user-1"))
        .await
        .unwrap()
        .code;
    let redeem = |uri: &str| TokenRequest::AuthorizationCode {
        client_id: ClientId::new("native"),
        client_secret: None,
        code: code.clone(),
        redirect_uri: Some(uri.to_string()),
        code_verifier: Some(RFC7636_VERIFIER.to_string()),
    };
    let other_port = srv
        .token(redeem("http://127.0.0.1:49153/cb"))
        .await
        .unwrap_err();
    assert_eq!(other_port.error, ErrorCode::InvalidGrant);
    srv.token(redeem("http://127.0.0.1:49152/cb"))
        .await
        .expect("the issuing port redeems");
}
