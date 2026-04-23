use std::time::{Duration, SystemTime};

use nythos_core::{AccessToken, Claims, PasswordHash, TenantId, TokenPurpose, UserId};

#[test]
fn claims_distinguish_structured_data_from_raw_token_strings() {
    let issued_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let claims = Claims::access(
        UserId::generate(),
        TenantId::generate(),
        issued_at,
        Duration::from_secs(300),
    )
    .unwrap();
    let token = AccessToken::new("header.payload.signature".to_owned()).unwrap();

    assert_eq!(claims.purpose(), &TokenPurpose::Access);
    assert_eq!(token.as_str(), "header.payload.signature");
}

#[test]
fn password_hash_is_a_first_class_domain_type() {
    let hash = PasswordHash::new("hashed_password".to_owned()).unwrap();

    assert_eq!(hash.as_str(), "hashed_password");
}
