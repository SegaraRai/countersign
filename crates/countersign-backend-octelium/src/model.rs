//! The subset of Octelium's JSON resource format (`octeliumctl -o json`) that
//! this backend reads. Unknown fields are ignored.

use jiff::Timestamp;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct List<T> {
    #[serde(default = "Vec::new")]
    pub items: Vec<T>,
    #[serde(default)]
    pub list_response_meta: Option<ListMeta>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ListMeta {
    #[serde(default)]
    pub total_count: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Metadata {
    pub name: String,
    #[serde(default)]
    pub created_at: Option<Timestamp>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Ref {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Session {
    pub metadata: Metadata,
    pub spec: SessionSpec,
    pub status: SessionStatus,
}

/// Session states as serialized by protojson.
pub(crate) const PENDING: &str = "PENDING";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SessionSpec {
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub expires_at: Option<Timestamp>,
}

impl SessionSpec {
    pub fn is_pending(&self) -> bool {
        self.state.as_deref() == Some(PENDING)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SessionStatus {
    pub user_ref: Ref,
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    #[serde(default)]
    pub authentication: Option<Authentication>,
    #[serde(default)]
    pub device_ref: Option<Ref>,
    #[serde(default)]
    pub is_browser: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Authentication {
    #[serde(default)]
    pub info: Option<AuthenticationInfo>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthenticationInfo {
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    #[serde(default)]
    pub credential: Option<CredentialInfo>,
    #[serde(default)]
    pub downstream: Option<Downstream>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialInfo {
    #[serde(default)]
    pub credential_ref: Option<Ref>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Downstream {
    #[serde(default)]
    pub user_agent: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct User {
    pub spec: UserSpec,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UserSpec {
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub authentication: Option<UserAuthentication>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct UserAuthentication {
    #[serde(default)]
    pub identities: Vec<Identity>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Identity {
    pub identity_provider: String,
    pub identifier: String,
}
