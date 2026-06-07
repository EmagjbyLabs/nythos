use nythos_core::{
    Email, Password, Permission, RefreshToken, Role, RoleId, Session, SessionId, TenantId, UserId,
};
use std::time::{Duration, SystemTime};

pub fn canonical_issued_at() -> SystemTime {
    SystemTime::UNIX_EPOCH
}

pub fn canonical_access_token_ttl() -> Duration {
    Duration::from_secs(300)
}

pub fn canonical_session_ttl() -> Duration {
    Duration::from_secs(600)
}

pub fn canonical_email() -> Email {
    Email::parse(canonical_email_string()).unwrap()
}

pub fn canonical_email_string() -> String {
    "person@example.com".to_owned()
}

pub fn canonical_password() -> Password {
    Password::new(canonical_password_string()).unwrap()
}

pub fn canonical_password_string() -> String {
    "super-secret-password".to_owned()
}

pub fn alternate_email() -> Email {
    Email::parse(alternate_email_string()).unwrap()
}

pub fn alternate_email_string() -> String {
    "other@example.com".to_owned()
}

pub fn operator_role(tenant_id: TenantId) -> Role {
    Role::new(
        RoleId::generate(),
        tenant_id,
        "operator",
        [Permission::new("shipments.read").unwrap()],
    )
    .unwrap()
}

pub fn refresh_token(value: &str) -> RefreshToken {
    RefreshToken::new(value.to_owned()).unwrap()
}

pub fn session(
    session_id: SessionId,
    user_id: UserId,
    tenant_id: TenantId,
    issued_at: SystemTime,
    ttl: Duration,
) -> Session {
    Session::with_ttl(session_id, user_id, tenant_id, issued_at, ttl).unwrap()
}
