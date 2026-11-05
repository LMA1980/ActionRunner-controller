// SPDX-License-Identifier: AGPL-3.0-only
//! Asynchronous Live E2E Integration Test for MuConsole Ingress OAuth2 contracts.
//! Run with: `cargo test --test live_oauth2_ingress_test -- --ignored --nocapture`

use reqwest::redirect::Policy;
use reqwest::Client;
use std::collections::HashMap;

const CONSOLE_BASE: &str = "https://console.lma1980.duckdns.org";

fn make_no_redirect_client() -> Client {
    Client::builder()
        .redirect(Policy::none())
        .build()
        .expect("Failed to build reqwest client")
}

#[tokio::test]
#[ignore = "Hits live public endpoint console.lma1980.duckdns.org"]
async fn test_live_oauth2_start_redirect() {
    let client = make_no_redirect_client();
    let url = format!("{CONSOLE_BASE}/oauth2/start?rd=/");
    let resp = client.get(&url).send().await.expect("Failed to connect");

    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.text().await.unwrap_or_default();

    assert!(
        status.is_redirection(),
        "GET /oauth2/start must return HTTP 302/303 redirect, got status {status}. Body: {body}"
    );

    let location = headers
        .get("location")
        .expect("Missing Location header")
        .to_str()
        .expect("Invalid Location header string");

    assert!(
        location.starts_with("https://github.com/login/oauth/authorize"),
        "Location must point to GitHub authorize, got: {location}"
    );

    let parsed_url = reqwest::Url::parse(location).expect("Failed to parse Location URL");
    let params: HashMap<_, _> = parsed_url.query_pairs().into_owned().collect();

    assert!(
        params.contains_key("client_id") && !params["client_id"].is_empty(),
        "Missing client_id in Location query"
    );
    assert_eq!(
        params.get("redirect_uri").map(String::as_str),
        Some("https://console.lma1980.duckdns.org/oauth2/callback"),
        "redirect_uri mismatch"
    );
    assert!(
        params
            .get("scope")
            .map(|s| s.contains("read:user"))
            .unwrap_or(false),
        "scope must include read:user"
    );
    assert!(
        params.contains_key("state") && !params["state"].is_empty(),
        "Missing state parameter"
    );

    // CSRF cookie check
    let has_csrf_cookie = headers.get_all("set-cookie").iter().any(|val| {
        let s = val.to_str().unwrap_or("").to_lowercase();
        s.contains("_muconsole_oauth2") || s.contains("_oauth2_proxy")
    });
    assert!(
        has_csrf_cookie,
        "Set-Cookie must issue an OAuth2 CSRF cookie"
    );
}

#[tokio::test]
#[ignore = "Hits live public endpoint console.lma1980.duckdns.org"]
async fn test_live_oauth2_callback_rejection() {
    let client = make_no_redirect_client();
    let url = format!("{CONSOLE_BASE}/oauth2/callback");
    let resp = client.get(&url).send().await.expect("Failed to connect");

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();

    assert!(
        status == reqwest::StatusCode::BAD_REQUEST || status == reqwest::StatusCode::FORBIDDEN,
        "GET /oauth2/callback without code/state must return 400 or 403, got status {status}. Body: {body}"
    );
    assert!(
        !body.contains("<title>MuConsole"),
        "Must NOT return SPA HTML index.html fallback"
    );
}

#[tokio::test]
#[ignore = "Hits live public endpoint console.lma1980.duckdns.org"]
async fn test_live_oauth2_sign_out_contract() {
    let client = make_no_redirect_client();
    let url = format!("{CONSOLE_BASE}/oauth2/sign_out?rd=/");
    let resp = client.get(&url).send().await.expect("Failed to connect");

    let status = resp.status();
    let headers = resp.headers().clone();

    assert!(
        status.is_redirection(),
        "GET /oauth2/sign_out must return HTTP 302/303 redirect, got status {status}"
    );

    let has_expired_cookie = headers.get_all("set-cookie").iter().any(|val| {
        let s = val.to_str().unwrap_or("").to_lowercase();
        (s.contains("_muconsole_oauth2") || s.contains("_oauth2_proxy"))
            && (s.contains("max-age=0") || s.contains("1970") || s.contains("expires="))
    });
    assert!(has_expired_cookie, "Set-Cookie must clear session cookie");
}
