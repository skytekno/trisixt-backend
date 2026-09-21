use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{
    Algorithm, EncodingKey, Header, encode,
    jwk::{Jwk, JwkSet},
};
use oauth2::{AccessToken, basic::BasicTokenType};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trisixt::oidc::{IdTokenFields, OidcTokenResponse, ProviderProfile, verify_identity};

// Generated test-only RSA key. Never used outside deterministic signature tests.
const TEST_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDGDA8Uc9CfTMLc
L/YIBtFn/aYNf9kzezvSwUuQzbpcTLXj0CNjd6AIxGNhkVOk9eaGC+u5FTzPATOk
x0Tn3YNBUMb+jB5jdBMuiKD4/YNfIjwoBjOxhkHaIC9vCO0fFgxpS1LbS9iNBhEc
gh5KsXPHQc4YowgGl5bbdBoVb2JdK2Ol/aqdt7N7PvaCgArCL2L9TeOFkBGLuYZm
2BoYcKhLXVqaaV5Qi+RVLe5Y5o5CTX0+Vp35AIMjqpQWSpZ0MgQdk9WEwByl1VAZ
dBuSaUWjsN5bQ3XoYgc5YyF1Hk9RxWn9BLyI3vUN3LxYIO3QcRdNoSPLYvLrLChw
BpQnbEsXAgMBAAECggEABOkdopswjBKiLkV+KzrIDHUMnf8SiqU+mX4zenavbUR1
qh1qEzhPHoiIEk5BLbDvM1muUZuGM3fLKQXL3pfufjsbhApDYqHpK9k1bJcUn9JA
fZmRxJAYp+juZClrf77TNfUpK8jYqL6CxBsx1xZJUaJ/ErtQIqG1muFpGCj33ml+
wvPKeE4f0baRueK7Uo2fxTVIBrtN6unyy8bn1B+sk+L5xfUEBnDb76XpHKHvZTHw
9AM/lO8NAib3kQLxgB3s//ax4RX+T/cReRy6LuxAdDtPaaaM7H08Ygfa1cwgEy9r
X7/jLFvzXuc5gT2iO5sZ6ZR3yrGMKpaBNRkYWX31IQKBgQD90GnM6ZdL/swHPhGo
TJX5vg6MIYaw1CxwR/FuA4/Gw+5ly3wTVIutryr+e+hI/IR6AmN3O8OKJ9tTTGQP
MMQ+BNO3j6zEutj2KoHF5Xrq7V82waPi1EI2y6X8djDfPWIgUVKrJQH5v5LE6P+L
npMd4ucw0EY2GDzZUehsatKhRwKBgQDHwLIMAToQPEUFkOw5nK1eFpgn+DptcXe0
9nXv0YfC4NP99MT3QnBSS5vJfu91JM6AzLIm3ji6aKwqlEHR7Vh829THgNUNkPio
rJdjb7zT8M2JM4tRsaM4rVjQS39WqsJaV9gL/rQ4xNJUn6FjQoN3Ls1Ej3XE1kuA
VQ0SD7tvsQKBgD16N8Y8ZjswEjdG33wGYOVHFbr3e+pk2gawRlhBYJfiaWIasYj1
F4gQP7e4R4E2ONhcr773qNtT4BoDDNFpHH9xJ970XAKix16I2ToX5Xf12vQmXw3Y
H9mp5iCKeDf6ZEQzrnRp2Fqn/mLXlN46oKPCjAEU0YzUvhhdcJCiJzaNAoGAbCf0
/7UGWFYZ1Tqz/TnNUT2Qo0uvbyTZ+RzdnL1p8eXEQyRuJadOo/CWaJKXW2lTer/a
0lrOgng8iE2AGgeWOvzYiDFEqrTNPp881TViG6utzlUfYVt6kiyiAx5t02JgG4Sm
0U/XC0nezL0mKFWSU0z/DdlTngGeHd1vV1E3XvECgYEApfJdSyzw+NIkFivdAjQG
ZKRdokr+hfn8jRaV0ii6IHmX6AOoiguQ1CVUp5LmUejGYs6GHj/ssPauqnBMlBFz
+2IZjsCqac9pY9E/ZAWRUpjGzEpWOyVtiU353zuinizLO1swvWHw0NMacER73rBV
dTGT+hKSvtlgaUHhYXQ49oQ=
-----END PRIVATE KEY-----
"#;

fn profile() -> ProviderProfile {
    ProviderProfile {
        issuer: "https://login.example.test".into(),
        client_id: "trisixt-client".into(),
        client_secret_env: None,
        allowed_origins: Vec::new(),
    }
}
fn claims() -> Value {
    let now = Utc::now().timestamp();
    json!({"iss":"https://login.example.test","sub":"subject-123","aud":"trisixt-client","exp":now+300,"iat":now,"nonce":"test-nonce","email":"verified@example.test","email_verified":true})
}
fn signed(value: &Value) -> (OidcTokenResponse, JwkSet) {
    let key = EncodingKey::from_rsa_pem(TEST_KEY.as_bytes()).unwrap();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".into());
    let mut jwk = Jwk::from_encoding_key(&key, Algorithm::RS256).unwrap();
    jwk.common.key_id = Some("test-key".into());
    let jwt = encode(&header, value, &key).unwrap();
    (
        OidcTokenResponse::new(
            AccessToken::new("provider-access-token".into()),
            BasicTokenType::Bearer,
            IdTokenFields { id_token: jwt },
        ),
        JwkSet { keys: vec![jwk] },
    )
}

#[test]
fn verifies_real_rsa_signature_identity_and_access_token_binding() {
    let mut value = claims();
    let hash = Sha256::digest(b"provider-access-token");
    value["at_hash"] = json!(URL_SAFE_NO_PAD.encode(&hash[..16]));
    let (response, jwks) = signed(&value);
    let identity = verify_identity(&response, &jwks, &profile(), "test-nonce").unwrap();
    assert_eq!(identity.subject, "subject-123");
    assert_eq!(identity.issuer, profile().issuer);
}

#[test]
fn rejects_oidc_token_substitution_and_invalid_claims() {
    let cases = [
        ("iss", json!("https://evil.example.test")),
        ("aud", json!("other-client")),
        ("exp", json!(Utc::now().timestamp() - 120)),
        ("iat", json!(Utc::now().timestamp() + 120)),
        ("iat", json!(Utc::now().timestamp() - 900)),
        ("nonce", json!("another-flow")),
        ("email_verified", json!(false)),
        ("email", json!("")),
        ("sub", json!("")),
        ("azp", json!("other-client")),
        ("at_hash", json!("wrong")),
        ("nbf", json!(Utc::now().timestamp() + 120)),
        ("aud", json!(["trisixt-client", "another-client"])),
    ];
    for (field, invalid) in cases {
        let mut value = claims();
        value[field] = invalid;
        let (response, jwks) = signed(&value);
        assert!(
            verify_identity(&response, &jwks, &profile(), "test-nonce").is_err(),
            "accepted invalid {field}"
        );
    }
    let mut value = claims();
    value["aud"] = json!(["trisixt-client", "another-client"]);
    value["azp"] = json!("trisixt-client");
    let (response, jwks) = signed(&value);
    assert!(verify_identity(&response, &jwks, &profile(), "test-nonce").is_ok());
}

#[test]
fn rejects_forged_signature_unknown_key_and_symmetric_algorithm() {
    let (response, mut jwks) = signed(&claims());
    jwks.keys[0].common.key_id = Some("different-key".into());
    assert!(verify_identity(&response, &jwks, &profile(), "test-nonce").is_err());
    let (response, jwks) = signed(&claims());
    let parts: Vec<_> = response.extra_fields().id_token.split('.').collect();
    let forged = format!(
        "{}.{}.{}",
        parts[0],
        parts[1],
        URL_SAFE_NO_PAD.encode(vec![0; 256])
    );
    let response = OidcTokenResponse::new(
        AccessToken::new("provider-access-token".into()),
        BasicTokenType::Bearer,
        IdTokenFields { id_token: forged },
    );
    assert!(verify_identity(&response, &jwks, &profile(), "test-nonce").is_err());
    let jwt = encode(
        &Header::new(Algorithm::HS256),
        &claims(),
        &EncodingKey::from_secret(b"attacker secret"),
    )
    .unwrap();
    let response = OidcTokenResponse::new(
        AccessToken::new("provider-access-token".into()),
        BasicTokenType::Bearer,
        IdTokenFields { id_token: jwt },
    );
    assert!(verify_identity(&response, &jwks, &profile(), "test-nonce").is_err());
}

#[test]
fn operator_profiles_reject_insecure_urls_secret_probing_and_path_origins() {
    for issuer in [
        "http://login.example.test",
        "https://user:secret@login.example.test",
        "https://login.example.test?redirect=evil",
        "https://login.example.test#fragment",
    ] {
        let mut p = profile();
        p.issuer = issuer.into();
        assert!(p.validate().is_err());
    }
    let mut p = profile();
    p.client_secret_env = Some("AWS_SECRET_ACCESS_KEY".into());
    assert!(p.validate().is_err());
    let mut p = profile();
    p.allowed_origins = vec!["https://cdn.example.test/path".into()];
    assert!(p.validate().is_err());
    let mut p = profile();
    p.allowed_origins = vec!["https://cdn.example.test".into()];
    assert_eq!(p.validate().unwrap().len(), 2);
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; run scripts/integration.sh"]
async fn oidc_state_requires_bound_browser_and_is_consumed_once() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use sqlx::{PgPool, postgres::PgPoolOptions};
    use std::sync::Arc;
    use tower::ServiceExt;
    use trisixt::{
        auth::token_hash,
        config::{AnalyticsBackend, Config, StorageBackend},
        state::AppState,
    };
    use uuid::Uuid;
    let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL required");
    let admin = PgPool::connect(&url).await.unwrap();
    let schema = format!("test_oidc_{}", Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await
        .unwrap();
    let search_path = format!("SET search_path TO {schema},public");
    let pg = PgPoolOptions::new()
        .max_connections(3)
        .after_connect(move |conn, _| {
            let s = search_path.clone();
            Box::pin(async move {
                sqlx::query(sqlx::AssertSqlSafe(s)).execute(conn).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pg).await.unwrap();
    let config = Config {
        env: "test".into(),
        host: "127.0.0.1".into(),
        port: 0,
        server_host: "example.test".into(),
        database_url: url,
        redis_url: "redis://127.0.0.1:56389".into(),
        ee_enabled: true,
        analytics_backend: AnalyticsBackend::ClickHouse,
        storage_backend: StorageBackend::S3,
        storage_region: None,
        storage_bucket: None,
        clickhouse_url: None,
        pubsub_topic: None,
        bigquery_dataset: None,
        gcs_credentials: None,
    };
    let app = trisixt::routes::router(AppState {
        config: Arc::new(config),
        pg: pg.clone(),
    });
    let instance = Uuid::new_v4();
    let version = Uuid::new_v4();
    let state = "test-oidc-state";
    let browser = "a".repeat(64);
    sqlx::query("INSERT INTO instances(id,name) VALUES($1,'OIDC test')")
        .bind(instance)
        .execute(&pg)
        .await
        .unwrap();
    sqlx::query("INSERT INTO instance_sso(instance_id,provider_key,version) VALUES($1,'unused-test-provider',$2)").bind(instance).bind(version).execute(&pg).await.unwrap();
    sqlx::query("INSERT INTO oidc_transactions(state_hash,browser_hash,instance_id,config_version,nonce,pkce_verifier) VALUES($1,$2,$3,$4,'nonce','verifier')").bind(token_hash(state)).bind(token_hash(&browser)).bind(instance).bind(version).execute(&pg).await.unwrap();
    let request = |cookie: String| {
        Request::builder()
            .uri(format!(
                "/auth/oidc/callback?state={state}&error=access_denied"
            ))
            .header("cookie", format!("__Host-trisixt_oidc={cookie}"))
            .body(Body::empty())
            .unwrap()
    };
    let wrong = app
        .clone()
        .oneshot(request("b".repeat(64)))
        .await
        .unwrap()
        .status();
    let after_wrong: i64 = sqlx::query_scalar("SELECT count(*) FROM oidc_transactions")
        .fetch_one(&pg)
        .await
        .unwrap();
    let denied = app
        .clone()
        .oneshot(request(browser.clone()))
        .await
        .unwrap()
        .status();
    let after_denied: i64 = sqlx::query_scalar("SELECT count(*) FROM oidc_transactions")
        .fetch_one(&pg)
        .await
        .unwrap();
    let replay = app.oneshot(request(browser)).await.unwrap().status();
    let tokens: i64 = sqlx::query_scalar("SELECT count(*) FROM access_tokens")
        .fetch_one(&pg)
        .await
        .unwrap();
    pg.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE")))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
    assert_eq!(wrong, StatusCode::UNAUTHORIZED);
    assert_eq!(after_wrong, 1);
    assert_eq!(denied, StatusCode::UNAUTHORIZED);
    assert_eq!(after_denied, 0);
    assert_eq!(replay, StatusCode::UNAUTHORIZED);
    assert_eq!(tokens, 0);
}

#[test]
fn verifies_es256_identity_with_matching_public_key() {
    const TEST_EC_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgIVUEhli8GNKKmKAf
HNsHYEwWiIM7U9DgrBSoU0SwoaChRANCAARdB5B+znDt2XJq7D1JY/M5OLClvG6a
p03aME7VqA9q3LEmKgBVLTIEHB60DgnqEBq9Pm6jtBceTiRprFbJfXnu
-----END PRIVATE KEY-----
"#;
    let key = EncodingKey::from_ec_pem(TEST_EC_KEY.as_bytes()).unwrap();
    let jwk = Jwk::from_encoding_key(&key, Algorithm::ES256).unwrap();
    let jwt = encode(&Header::new(Algorithm::ES256), &claims(), &key).unwrap();
    let response = OidcTokenResponse::new(
        AccessToken::new("provider-access-token".into()),
        BasicTokenType::Bearer,
        IdTokenFields { id_token: jwt },
    );
    assert!(
        verify_identity(
            &response,
            &JwkSet { keys: vec![jwk] },
            &profile(),
            "test-nonce"
        )
        .is_ok()
    );
}

mod support;
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn unlink_removes_bound_identity_and_revokes_sessions() {
    let f = support::Fixture::new().await;
    // This test binary has no other profile-dependent environment mutation.
    unsafe {
        std::env::set_var(
            "OIDC_PROVIDERS_JSON",
            r#"{"unlink-fixture":{"issuer":"https://id.example.test","client_id":"fixture"}}"#,
        );
    }
    sqlx::query("INSERT INTO instance_sso(instance_id,provider_key) VALUES($1,'unlink-fixture')")
        .bind(f.instance)
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO oidc_identities(issuer,subject,user_id) VALUES('https://id.example.test','subject',$1)").bind(f.user).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO refresh_sessions(user_id,family_id,token_hash,auth_method) VALUES($1,gen_random_uuid(),'unlink-refresh','oidc')").bind(f.user).execute(&f.pool).await.unwrap();
    let (s, b) = f
        .call(
            "DELETE",
            &format!("/api/v1/instances/{}/sso/link", f.instance),
            serde_json::Value::Null,
        )
        .await;
    assert_eq!(s, axum::http::StatusCode::NO_CONTENT, "{b}");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM oidc_identities WHERE user_id=$1")
            .bind(f.user)
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM refresh_sessions WHERE user_id=$1 AND revoked_at IS NULL"
        )
        .bind(f.user)
        .fetch_one(&f.pool)
        .await
        .unwrap(),
        0
    );
    let (s, _) = f.call("GET", "/auth/me", serde_json::Value::Null).await;
    assert_eq!(s, axum::http::StatusCode::UNAUTHORIZED);
    f.close().await;
}
