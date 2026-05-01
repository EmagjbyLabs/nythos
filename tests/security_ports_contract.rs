mod support;

use futures::executor::block_on;
use nythos_core::{
    Claims, PasswordHasher, RevocationChecker, SessionId, TenantId, TokenSigner, UserId,
};
use support::{FakePasswordHasher, FakeRevocationChecker, FakeTokenSigner, fixtures};

#[test]
fn password_hasher_supports_deterministic_test_hash_and_verify_flow() {
    block_on(async {
        let hasher = FakePasswordHasher;
        let password = fixtures::canonical_password();

        let hash = hasher.hash(&password).await.unwrap();

        assert!(hasher.verify(&password, &hash).await.unwrap());
    });
}

#[test]
fn token_signer_signs_and_verifies_core_claims() {
    block_on(async {
        let signer = FakeTokenSigner;
        let user_id = UserId::generate();
        let tenant_id = TenantId::generate();
        let claims = Claims::access(
            user_id,
            tenant_id,
            fixtures::canonical_issued_at(),
            fixtures::canonical_access_token_ttl(),
        )
        .unwrap();

        let token = signer.sign(&claims).await.unwrap();
        let verified = signer.verify(&token).await.unwrap();

        assert_eq!(verified.subject(), user_id);
        assert_eq!(verified.tenant_id(), tenant_id);
    });
}

#[test]
fn revocation_checker_reports_revoked_session_ids() {
    block_on(async {
        let checker = FakeRevocationChecker::default();
        let revoked_session_id = SessionId::generate();
        let active_session_id = SessionId::generate();

        checker.mark_revoked(revoked_session_id);

        assert!(checker.is_revoked(revoked_session_id).await.unwrap());
        assert!(!checker.is_revoked(active_session_id).await.unwrap());
    });
}

#[test]
fn security_port_exports_remain_usable() {
    fn assert_password_hasher<T: PasswordHasher>() {}
    fn assert_token_signer<T: TokenSigner>() {}
    fn assert_revocation_checker<T: RevocationChecker>() {}

    assert_password_hasher::<FakePasswordHasher>();
    assert_token_signer::<FakeTokenSigner>();
    assert_revocation_checker::<FakeRevocationChecker>();
}
