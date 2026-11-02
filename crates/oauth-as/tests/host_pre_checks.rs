// SPDX-License-Identifier: MIT OR Apache-2.0

//! The two checks a host can run on its own, ahead of the token endpoint: client authentication
//! alone (`authenticate_client_credential`) and the RFC 8707 resource checks
//! (`check_resource_indicators`). Each answers what the token endpoint itself would.

mod support;

use oauth_as::events::ClientAuthFailure;
use oauth_as::server::ClientCredential;
use oauth_as::{AuthorizationServer, ClientId, ErrorCode, MemoryStorage, ServerConfig};
use support::{client_credentials_client, public_client, server_with, ManualClock, CC_SECRET};

#[tokio::test]
async fn client_authentication_alone_carries_the_verdict() {
    let srv = server_with(
        ManualClock::at_epoch(),
        vec![client_credentials_client(), public_client()],
    )
    .await;
    srv.authenticate_client_credential(&ClientId::new("cc-app"), &ClientCredential::secret(Some(CC_SECRET)))
        .await
        .expect("the right secret is not refused");
    srv.authenticate_client_credential(&ClientId::new("public-app"), &ClientCredential::secret(None))
        .await
        .expect("a public client presenting no secret is not refused");
    for (client, secret, want) in [
        ("cc-app", Some("wrong"), ClientAuthFailure::SecretMismatch),
        ("nobody", Some(CC_SECRET), ClientAuthFailure::UnknownClient),
        ("public-app", Some(CC_SECRET), ClientAuthFailure::SecretMismatch),
    ] {
        let e = srv
            .authenticate_client_credential(&ClientId::new(client), &ClientCredential::secret(secret))
            .await
            .unwrap_err();
        assert_eq!(e.error, ErrorCode::InvalidClient, "{client}");
        assert_eq!(e.client_auth_failure(), Some(want), "{client}");
    }
}

#[tokio::test]
async fn the_resource_checks_alone() {
    let mut cfg = ServerConfig::new("https://as.example", "https://as.example/device");
    cfg.allowed_resources = Some(Box::new(["https://a.example/api".into()]));
    let srv = AuthorizationServer::with_clock(cfg, MemoryStorage::new(), ManualClock::at_epoch());
    srv.check_resource_indicators(["https://a.example/api"])
        .expect("an allowed resource passes");
    srv.check_resource_indicators([]).expect("no resource passes");
    for bad in ["not-a-uri", "https://a.example/api#frag", "https://b.example/api"] {
        let e = srv.check_resource_indicators([bad]).unwrap_err();
        assert_eq!(e.error, ErrorCode::InvalidTarget, "{bad}");
        assert_eq!(e.client_auth_failure(), None, "{bad}");
    }
}
