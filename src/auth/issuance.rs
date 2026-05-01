use std::time::{Duration, SystemTime};

use uuid::Uuid;

use crate::{
    AccessToken, Claims, NythosResult, RefreshToken, Session, SessionId, SessionRecord,
    SessionStore, TenantId, TokenSigner, UserId,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::auth) struct IssuedAuthMaterial {
    pub(in crate::auth) session: Session,
    pub(in crate::auth) refresh_token: RefreshToken,
    pub(in crate::auth) access_token: AccessToken,
    pub(in crate::auth) claims: Claims,
}

pub(in crate::auth) async fn issue_session_auth<S, T>(
    session_store: &S,
    token_signer: &T,
    user_id: UserId,
    tenant_id: TenantId,
    issued_at: SystemTime,
    access_token_ttl: Duration,
    session_ttl: Duration,
) -> NythosResult<IssuedAuthMaterial>
where
    S: SessionStore,
    T: TokenSigner,
{
    let session = Session::with_ttl(
        SessionId::generate(),
        user_id,
        tenant_id,
        issued_at,
        session_ttl,
    )?;

    let claims = Claims::access(user_id, tenant_id, issued_at, access_token_ttl)?;
    let access_token = token_signer.sign(&claims).await?;
    let refresh_token = RefreshToken::new(Uuid::new_v4().to_string())?;

    session_store
        .create_session(SessionRecord::new(session.clone(), refresh_token.clone()))
        .await?;

    Ok(IssuedAuthMaterial {
        session,
        refresh_token,
        access_token,
        claims,
    })
}
