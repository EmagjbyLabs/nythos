use nythos_core::domain::{RoleId, SessionId, TenantId, UserId};
use serde_json::{from_str, to_string};
use std::str::FromStr;
use uuid::Uuid;

#[test]
fn each_typed_id_can_be_constructed_from_uuid() {
    let user_raw = Uuid::new_v4();
    let tenant_raw = Uuid::new_v4();
    let session_raw = Uuid::new_v4();
    let role_raw = Uuid::new_v4();

    let user_id = UserId::from(user_raw);
    let tenant_id = TenantId::from(tenant_raw);
    let session_id = SessionId::from(session_raw);
    let role_id = RoleId::from(role_raw);

    assert_eq!(user_id.into_uuid(), user_raw);
    assert_eq!(tenant_id.into_uuid(), tenant_raw);
    assert_eq!(session_id.into_uuid(), session_raw);
    assert_eq!(role_id.into_uuid(), role_raw);
}

#[test]
fn typed_ids_round_trip_through_strings() {
    let raw = Uuid::new_v4();
    let raw_str = raw.to_string();

    let parsed = UserId::from_str(&raw_str).unwrap();

    assert_eq!(parsed.to_string(), raw_str);
    assert_eq!(Uuid::from(parsed), raw);
}

#[test]
fn invalid_uuid_string_fails_to_parse() {
    let parsed = SessionId::from_str("not-a-uuid");

    assert!(parsed.is_err());
}

#[test]
fn typed_ids_are_lightweight_copyable_domain_types() {
    let role_id = RoleId::generate();
    let copied = role_id;

    assert_eq!(role_id, copied);
}

#[test]
fn typed_ids_do_not_leak_raw_uuid_as_primary_api_surface() {
    let tenant_id = TenantId::generate();

    let borrowed: &Uuid = tenant_id.as_uuid();
    let owned: Uuid = tenant_id.into_uuid();

    assert_eq!(borrowed, &owned);
}

#[test]
fn user_id_serializes_as_uuid_string() {
    let raw = Uuid::new_v4();
    let user_id = UserId::from(raw);

    let json = to_string(&user_id).unwrap();

    assert_eq!(json, format!("\"{raw}\""));
}

#[test]
fn tenant_id_deserializes_from_uuid_string() {
    let raw = Uuid::new_v4();
    let json = format!("\"{raw}\"");

    let tenant_id: TenantId = from_str(&json).unwrap();

    assert_eq!(tenant_id.into_uuid(), raw);
}

#[test]
fn all_typed_ids_round_trip_through_serde_json() {
    let user_id = UserId::generate();
    let tenant_id = TenantId::generate();
    let session_id = SessionId::generate();
    let role_id = RoleId::generate();

    let user_json = to_string(&user_id).unwrap();
    let tenant_json = to_string(&tenant_id).unwrap();
    let session_json = to_string(&session_id).unwrap();
    let role_json = to_string(&role_id).unwrap();

    let deserialized_user_id: UserId = from_str(&user_json).unwrap();
    let deserialized_tenant_id: TenantId = from_str(&tenant_json).unwrap();
    let deserialized_session_id: SessionId = from_str(&session_json).unwrap();
    let deserialized_role_id: RoleId = from_str(&role_json).unwrap();

    assert_eq!(deserialized_user_id, user_id);
    assert_eq!(deserialized_tenant_id, tenant_id);
    assert_eq!(deserialized_session_id, session_id);
    assert_eq!(deserialized_role_id, role_id);
}

#[test]
fn invalid_uuid_string_fails_deserialization() {
    let json = "\"not-a-uuid\"";

    let result: Result<SessionId, _> = from_str(json);

    assert!(result.is_err());
}

#[test]
fn typed_ids_serialize_to_same_shape_but_deserialize_to_distinct_types() {
    let raw = Uuid::new_v4();

    let user_json = to_string(&UserId::from(raw)).unwrap();
    let tenant_json = to_string(&TenantId::from(raw)).unwrap();

    assert_eq!(user_json, tenant_json);

    let user_id: UserId = from_str(&user_json).unwrap();
    let tenant_id: TenantId = from_str(&tenant_json).unwrap();

    assert_eq!(user_id.into_uuid(), raw);
    assert_eq!(tenant_id.into_uuid(), raw);
}
