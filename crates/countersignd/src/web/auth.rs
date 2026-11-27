//! Signing in through the identity provider, and out.

use std::collections::BTreeSet;

use axum::Form;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::PrivateCookieJar;
use jiff::Timestamp;
use serde::Deserialize;
use tracing::{info, warn};

use countersign_core::{IdpSnapshot, Purpose};

use super::session::{
    LOGIN_COOKIE, LOGIN_TTL, LoginData, SESSION_COOKIE, SessionData, cookie, current_session, random_token, removal,
    safe_next, same,
};
use super::{AppState, notice};

#[derive(Debug, Deserialize)]
pub(super) struct LoginQuery {
    next: Option<String>,
    fresh: Option<String>,
}

async fn no_idp(state: &AppState) -> Response {
    notice(state, StatusCode::SERVICE_UNAVAILABLE, "Sign-in unavailable", "No identity provider is configured.", None)
        .await
}

pub(super) async fn login(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Query(q): Query<LoginQuery>,
) -> Response {
    let Some(auth) = &state.auth else {
        return no_idp(&state).await;
    };
    let fresh = q.fresh.as_deref().is_some_and(|f| f == "1" || f == "true");
    match auth.begin(fresh).await {
        Ok(start) => {
            let data = LoginData {
                state: start.state,
                next: safe_next(q.next.as_deref()),
                issued: Timestamp::now().as_second(),
            };
            let Ok(value) = serde_json::to_string(&data) else {
                return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
            };
            let jar = jar.add(cookie(LOGIN_COOKIE, value, state.settings.secure_cookies));
            (jar, Redirect::to(&start.redirect_url)).into_response()
        }
        Err(e) => {
            warn!(error = %e, "starting login failed");
            notice(
                &state,
                StatusCode::BAD_GATEWAY,
                "Sign-in unavailable",
                "The identity provider could not be reached.",
                None,
            )
            .await
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

pub(super) async fn callback(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let Some(auth) = &state.auth else {
        return no_idp(&state).await;
    };
    let now = Timestamp::now();
    let saved: Option<LoginData> = jar.get(LOGIN_COOKIE).and_then(|c| serde_json::from_str(c.value()).ok());
    let jar = jar.remove(removal(LOGIN_COOKIE));
    let max_age = i64::try_from(LOGIN_TTL.as_secs()).unwrap_or(600);
    let Some(saved) = saved.filter(|s| now.as_second() < s.issued.saturating_add(max_age)) else {
        let page = notice(&state, StatusCode::BAD_REQUEST, "Sign-in expired", "Start the sign-in again.", None).await;
        return (jar, page).into_response();
    };
    if let Some(err) = q.error {
        let page = notice(
            &state,
            StatusCode::UNAUTHORIZED,
            "Sign-in failed",
            "The identity provider refused the sign-in.",
            Some(err),
        )
        .await;
        return (jar, page).into_response();
    }
    let (Some(code), Some(returned)) = (q.code, q.state) else {
        let page =
            notice(&state, StatusCode::BAD_REQUEST, "Sign-in failed", "The callback was incomplete.", None).await;
        return (jar, page).into_response();
    };
    let login = match auth.complete(&saved.state, &returned, &code).await {
        Ok(l) => l,
        Err(e) => {
            warn!(error = %e, "completing login failed");
            let page =
                notice(&state, StatusCode::UNAUTHORIZED, "Sign-in failed", "The sign-in could not be verified.", None)
                    .await;
            return (jar, page).into_response();
        }
    };
    let rules = state.engine.rules();
    let Some(person) = rules.directory.by_identity(&login.identity, Purpose::SignIn).map(|a| a.id.clone()) else {
        info!(identity = %login.identity, "sign-in by an identity that is not a person");
        let page = notice(
            &state,
            StatusCode::FORBIDDEN,
            "No access",
            "You signed in, but this identity is not a person in countersign's configuration. An administrator can add it:",
            Some(login.identity),
        )
        .await;
        return (jar, page).into_response();
    };

    // Remember the groups the provider reported now (none if it sent no
    // groups claim), replacing the previous sign-in's.
    let (provider, groups) = login.groups.clone().unwrap_or_else(|| {
        let provider = login.identity.rsplit_once('#').map_or(login.identity.as_str(), |(p, _)| p).to_owned();
        (provider, BTreeSet::new())
    });
    let snapshot = IdpSnapshot { provider, groups, at: now };
    if let Err(e) = state.engine.store().save_idp_snapshot(&person, &snapshot).await {
        warn!(error = %e, "saving sign-in groups failed");
    }

    let data = SessionData {
        person: person.to_string(),
        identity: login.identity,
        auth_time: login.auth_time.map(Timestamp::as_second),
        issued: now.as_second(),
        csrf: random_token(),
    };
    let Ok(value) = serde_json::to_string(&data) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
    };
    let jar = jar.add(cookie(SESSION_COOKIE, value, state.settings.secure_cookies));
    if current_session(&state, &jar, now).await.is_none() {
        info!(%person, "sign-in by a person who is suspended or holds no role");
        let page = notice(
            &state,
            StatusCode::FORBIDDEN,
            "No access",
            "You signed in, but you are suspended or hold no role in countersign.",
            None,
        )
        .await;
        return (jar.remove(removal(SESSION_COOKIE)), page).into_response();
    }
    info!(%person, "signed in");
    (jar, Redirect::to(&safe_next(Some(&saved.next)))).into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct CsrfForm {
    csrf: String,
}

pub(super) async fn logout(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    Form(form): Form<CsrfForm>,
) -> Response {
    match current_session(&state, &jar, Timestamp::now()).await {
        Some(s) if !same(&form.csrf, &s.data.csrf) => {
            notice(&state, StatusCode::FORBIDDEN, "Forbidden", "The form was not valid. Reload the page.", None).await
        }
        _ => {
            let page = notice(&state, StatusCode::OK, "Signed out", "You have signed out of countersign.", None).await;
            (jar.remove(removal(SESSION_COOKIE)), page).into_response()
        }
    }
}
