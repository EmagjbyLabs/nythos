use nythos_core::{
    AuthError, auth::AuthMarker, domain::DomainMarker, ports::PortsMarker, rbac::RbacMarker,
    session::SessionMarker,
};

#[test]
fn public_modules_and_core_errors_are_reachable() {
    let _ = AuthMarker;
    let _ = DomainMarker;
    let _ = SessionMarker;
    let _ = RbacMarker;
    let _ = PortsMarker;

    let err = AuthError::InvalidCredentials;
    assert!(matches!(err, AuthError::InvalidCredentials))
}
