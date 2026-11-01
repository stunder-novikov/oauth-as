// SPDX-License-Identifier: MIT OR Apache-2.0

//! `ErrorResponse::client_auth_failure`: the refusal the event sink is told about comes back with
//! the error, for the host, and never reaches the wire.

mod support;

use oauth_as::events::ClientAuthFailure;
use oauth_as::server::ClientCredential;
use oauth_as::{ClientId, ErrorCode, ScopeSet, TokenRequest};
use support::{client_credentials_client, public_client, server_with, ManualClock, CC_SECRET};

fn cc(client: &str, secret: Option<&str>) -> TokenRequest {
    TokenRequest::ClientCredentials {
        client_id: ClientId::new(client),
        client_secret: secret.map(str::to_string),
        scope: Some(ScopeSet::parse("api:read").unwrap()),
    }
}

#[tokio::test]
async fn each_token_refusal_carries_its_verdict() {
    let srv = server_with(
        ManualClock::at_epoch(),
        vec![client_credentials_client(), public_client()],
    )
    .await;
    for (request, want) in [
        (
            cc("cc-app", Some("wrong")),
            ClientAuthFailure::SecretMismatch,
        ),
        (
            cc("nobody", Some(CC_SECRET)),
            ClientAuthFailure::UnknownClient,
        ),
        (cc("public-app", None), ClientAuthFailure::NotConfidential),
    ] {
        let e = srv.token(request).await.unwrap_err();
        assert_eq!(e.error, ErrorCode::InvalidClient);
        assert_eq!(e.client_auth_failure(), Some(want));
    }
    srv.token(cc("cc-app", Some(CC_SECRET)))
        .await
        .expect("the right secret is not refused");
}

#[tokio::test]
async fn a_refusal_that_is_not_client_authentication_carries_none() {
    let srv = server_with(ManualClock::at_epoch(), vec![client_credentials_client()]).await;
    let wider = TokenRequest::ClientCredentials {
        client_id: ClientId::new("cc-app"),
        client_secret: Some(CC_SECRET.to_string()),
        scope: Some(ScopeSet::parse("other").unwrap()),
    };
    let e = srv.token(wider).await.unwrap_err();
    assert_eq!(e.error, ErrorCode::InvalidScope);
    assert_eq!(e.client_auth_failure(), None);
}

#[tokio::test]
async fn revocation_refusals_carry_the_verdict_too() {
    let srv = server_with(ManualClock::at_epoch(), vec![client_credentials_client()]).await;
    let e = srv
        .revoke_with_credential(
            &ClientId::new("cc-app"),
            &ClientCredential::secret(Some("wrong")),
            "some-token",
            None,
        )
        .await
        .unwrap_err();
    assert_eq!(
        e.client_auth_failure(),
        Some(ClientAuthFailure::SecretMismatch)
    );
}

#[tokio::test]
async fn the_verdict_never_reaches_the_wire() {
    let srv = server_with(ManualClock::at_epoch(), vec![client_credentials_client()]).await;
    let e = srv.token(cc("cc-app", Some("wrong"))).await.unwrap_err();
    assert!(e.client_auth_failure().is_some());
    assert_eq!(
        serde_json::to_string(&e).unwrap(),
        r#"{"error":"invalid_client"}"#
    );
}
