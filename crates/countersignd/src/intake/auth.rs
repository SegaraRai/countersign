//! Client authentication (static `cshk_` host keys and CI OIDC JWTs) and
//! proxy-aware client IP extraction for the intake API.

use std::net::{IpAddr, SocketAddr};

use axum::http::{HeaderMap, StatusCode, header};
use jiff::Timestamp;
use subtle::ConstantTimeEq as _;

use countersign_core::host_key;

use super::{ApiError, IntakeState, error, oidc};
use crate::config::{ClientConfig, Scope};

impl IntakeState {
    /// The client's address: the peer's, or behind a proxy the last entry of
    /// the header it sets (earlier entries come from the client and are not
    /// trusted).
    pub(super) fn client_ip(&self, headers: &HeaderMap, peer: Option<SocketAddr>) -> Option<IpAddr> {
        match &self.client_ip_header {
            None => peer.map(|p| p.ip()),
            Some(name) => {
                let last = headers.get_all(name).iter().next_back()?.to_str().ok()?.rsplit(',').next()?.trim();
                last.parse::<IpAddr>().ok().or_else(|| last.parse::<SocketAddr>().ok().map(|a| a.ip()))
            }
        }
    }

    pub(super) async fn authenticate(
        &self,
        headers: &HeaderMap,
        peer: Option<SocketAddr>,
        scope: Scope,
    ) -> Result<(ClientConfig, Option<oidc::VerifiedOidc>), ApiError> {
        let token = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "unauthorized", "missing client key"))?;
        let rules = self.engine.rules();
        let ip = self.client_ip(headers, peer);

        let (client, verified_oidc) = if host_key::is_well_formed(token) {
            let digest = host_key::digest(token);
            let found = rules.clients.values().fold(None, |found, c| {
                let matches = c
                    .auth
                    .host_key()
                    .and_then(|hk| host_key::parse_reference(hk).ok())
                    .is_some_and(|d| bool::from(d.ct_eq(&digest)));
                if matches { Some(c.clone()) } else { found }
            });
            let Some(client) = found else {
                tracing::warn!(address = ?ip, "intake request with an unknown client key");
                return Err(error(StatusCode::UNAUTHORIZED, "unauthorized", "unknown client key"));
            };
            (client, None)
        } else if let Some(issuer) = oidc::OidcVerifier::peek_issuer(token) {
            let candidates: Vec<ClientConfig> =
                rules.clients.values().filter(|c| c.auth.oidc().is_some_and(|o| o.issuer == issuer)).cloned().collect();
            let now = Timestamp::now();
            let mut matched = None;
            for c in candidates {
                if let Some(oidc_cfg) = c.auth.oidc()
                    && let Ok(v) = self.oidc.verify(token, oidc_cfg, now).await
                {
                    matched = Some((c, v));
                    break;
                }
            }
            let Some((client, verified)) = matched else {
                tracing::warn!(address = ?ip, %issuer, "intake request with an invalid OIDC token");
                return Err(error(StatusCode::UNAUTHORIZED, "unauthorized", "invalid client token"));
            };
            (client, Some(verified))
        } else {
            tracing::warn!(address = ?ip, "intake request with an unknown client key");
            return Err(error(StatusCode::UNAUTHORIZED, "unauthorized", "unknown client key"));
        };

        if !client.allowed_ips.is_empty() && !ip.is_some_and(|a| client.allowed_ips.contains(&a)) {
            tracing::warn!(client = %client.id, address = ?ip, "client key used from an address that is not allowed");
            return Err(error(StatusCode::UNAUTHORIZED, "unauthorized", "address not allowed for this client"));
        }
        if !client.has_scope(scope) {
            tracing::warn!(client = %client.id, ?scope, "client key used outside its scopes");
            return Err(error(StatusCode::FORBIDDEN, "scope", "this key may not be used for this"));
        }
        Ok((client, verified_oidc))
    }
}
