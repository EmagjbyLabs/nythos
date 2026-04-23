use std::time::{Duration, SystemTime};

use nythos_core::{
    SessionId, TenantId, UserId,
    session::{RefreshToken, Session},
};

#[test]
fn refresh_token_is_distinct_from_structured_claims() {
    let token = RefreshToken::new("opaque-refresh-token").unwrap();

    assert_eq!(token.as_str(), "opaque-refresh-token");
}

#[test]
fn session_carries_typed_ids_and_lifecycle_timestamps() {
    let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let session_id = SessionId::generate();
    let user_id = UserId::generate();
    let tenant_id = TenantId::generate();

    let session = Session::with_ttl(
        session_id,
        user_id,
        tenant_id,
        issued_at,
        Duration::from_secs(900),
    )
    .unwrap();

    assert_eq!(session.id(), session_id);
    assert_eq!(session.user_id(), user_id);
    assert_eq!(session.tenant_id(), tenant_id);
    assert_eq!(session.issued_at(), issued_at);
    assert_eq!(session.expires_at(), issued_at + Duration::from_secs(900));
}
