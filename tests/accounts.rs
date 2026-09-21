//! Account security and SMTP integration; run with --include-ignored and TEST_DATABASE_URL.
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use std::sync::Arc;
use tower::ServiceExt;
use trisixt::{
    accounts,
    config::{AnalyticsBackend, Config, StorageBackend},
    state::AppState,
};
use uuid::Uuid;
struct Fixture {
    app: Router,
    st: AppState,
    admin: PgPool,
    schema: String,
}
impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL required");
        let admin = PgPool::connect(&url).await.unwrap();
        let schema = format!("test_accounts_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        let path = format!("SET search_path TO {schema},public");
        let pg = PgPoolOptions::new()
            .max_connections(5)
            .after_connect(move |c, _| {
                let q = path.clone();
                Box::pin(async move {
                    sqlx::query(sqlx::AssertSqlSafe(q)).execute(c).await?;
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
            redis_url: "redis://127.0.0.1:56386".into(),
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
        let st = AppState {
            pg,
            config: Arc::new(config),
        };
        let app = trisixt::routes::router(st.clone());
        Self {
            app,
            st,
            admin,
            schema,
        }
    }
    async fn req(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Value,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(t) = token {
            builder = builder.header("authorization", format!("Bearer {t}"));
        }
        let response = self
            .app
            .clone()
            .oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&body)
                .unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&body)})),
        )
    }
    async fn user(&self, email: &str) -> (Uuid, String, Value) {
        let creds = json!({"email":email,"password":"correct horse battery staple","name":"Name"});
        let (status, body) = self
            .req("POST", "/auth/register", None, creds.clone())
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();
        let (status, session) = self.req("POST", "/auth/login", None, creds).await;
        assert_eq!(status, StatusCode::OK, "{session}");
        (id, session["token"].as_str().unwrap().into(), session)
    }
    async fn mail_token(&self, address: &str) -> String {
        let rows =
            sqlx::query("SELECT payload_encrypted FROM mail_outbox ORDER BY created_at DESC")
                .fetch_all(&self.st.pg)
                .await
                .unwrap();
        for row in rows {
            let mail: accounts::Mail = serde_json::from_slice(
                &accounts::decrypt_secret("mail-outbox", row.get("payload_encrypted")).unwrap(),
            )
            .unwrap();
            if mail.to == address
                && let Some(url) = mail
                    .text
                    .split_whitespace()
                    .find(|s| s.starts_with("http") && s.contains("token="))
            {
                return url::Url::parse(url)
                    .unwrap()
                    .query_pairs()
                    .find(|(k, _)| k == "token")
                    .unwrap()
                    .1
                    .to_string();
            }
        }
        panic!("no mail token")
    }
    async fn finish(self) {
        self.st.pg.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin)
        .await
        .unwrap();
        self.admin.close().await;
    }
}
#[tokio::test]
#[ignore = "requires PostgreSQL and TRISIXT_ENCRYPTION_KEY"]
async fn reset_invite_refresh_and_account_deletion_are_single_use_and_scoped() {
    let f = Fixture::new().await;
    let (id, token, session) = f.user("owner@example.test").await;
    // Refresh rotation invalidates the old access token; reuse revokes the entire family.
    let next = accounts::rotate_refresh(&f.st, session["refresh_token"].as_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        f.req("GET", "/auth/me", Some(&token), json!({})).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert!(
        accounts::rotate_refresh(&f.st, session["refresh_token"].as_str().unwrap())
            .await
            .is_err()
    );
    assert_eq!(
        f.req("GET", "/auth/me", next["token"].as_str(), json!({}))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let token = accounts::issue_session(&f.st, id).await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    let unknown = f
        .req(
            "POST",
            "/api/v1/users/reset_password",
            None,
            json!({"email":"missing@example.test"}),
        )
        .await;
    let known = f
        .req(
            "POST",
            "/api/v1/users/reset_password",
            None,
            json!({"email":"owner@example.test"}),
        )
        .await;
    assert_eq!(known, unknown, "reset must not disclose existence");
    assert_eq!(known.0, StatusCode::OK);
    let reset = f.mail_token("owner@example.test").await;
    let encrypted: String = sqlx::query_scalar(
        "SELECT payload_encrypted FROM mail_outbox ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_one(&f.st.pg)
    .await
    .unwrap();
    assert!(!encrypted.contains(&reset));
    let request = json!({"reset_token":reset,"new_password":"new secure password 123"});
    assert_eq!(
        f.req(
            "POST",
            "/api/v1/users/change_password",
            None,
            request.clone()
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        f.req("POST", "/api/v1/users/change_password", None, request)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        f.req("GET", "/auth/me", Some(&token), json!({})).await.0,
        StatusCode::UNAUTHORIZED
    );
    // Expired reset tokens cannot change a password.
    f.req(
        "POST",
        "/api/v1/users/reset_password",
        None,
        json!({"email":"owner@example.test"}),
    )
    .await;
    let expired = f.mail_token("owner@example.test").await;
    sqlx::query(
        "UPDATE account_tokens SET expires_at=now()-interval '1 second' WHERE token_hash=$1",
    )
    .bind(trisixt::auth::token_hash(&expired))
    .execute(&f.st.pg)
    .await
    .unwrap();
    assert_eq!(
        f.req(
            "POST",
            "/api/v1/users/change_password",
            None,
            json!({"reset_token":expired,"new_password":"another secure password"})
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let owner = accounts::issue_session(&f.st, id).await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, instance) = f
        .req(
            "POST",
            "/api/v1/instances",
            Some(&owner),
            json!({"name":"Invites"}),
        )
        .await;
    let tenant = instance["id"].as_str().unwrap();
    let (_, other, _) = f.user("other@example.test").await;
    assert_eq!(
        f.req(
            "POST",
            &format!("/api/v1/instances/{tenant}/invitations"),
            Some(&other),
            json!({"email":"invite@example.test","role":"member"})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (status, body) = f
        .req(
            "POST",
            &format!("/api/v1/instances/{tenant}/invitations"),
            Some(&owner),
            json!({"email":"invite@example.test","role":"member"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        f.req(
            "POST",
            "/auth/register",
            None,
            json!({"email":"invite@example.test","password":"attacker preclaim password"})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let invite = f.mail_token("invite@example.test").await;
    let accept =
        json!({"invitation_token":invite,"password":"invited secure password","name":"Invited"});
    let (status, invited) = f
        .req("POST", "/api/v1/users/accept_invite", None, accept.clone())
        .await;
    assert_eq!(status, StatusCode::OK, "{invited}");
    assert_eq!(
        f.req("POST", "/api/v1/users/accept_invite", None, accept)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        f.req(
            "GET",
            &format!("/api/v1/instances/{tenant}"),
            invited["token"].as_str(),
            json!({})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        f.req(
            "PATCH",
            "/api/v1/users/me",
            Some(&owner),
            json!({"name":"Updated"})
        )
        .await
        .1["name"],
        "Updated"
    );
    assert_eq!(
        f.req("DELETE", "/api/v1/users/me", Some(&owner), json!({}))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.req("GET", "/auth/me", Some(&owner), json!({})).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM instances WHERE id=$1)")
            .bind(Uuid::parse_str(tenant).unwrap())
            .fetch_one(&f.st.pg)
            .await
            .unwrap()
    );
    f.finish().await;
}

fn otp(secret: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    let counter = chrono::Utc::now().timestamp() as u64 / 30;
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).unwrap();
    mac.update(&counter.to_be_bytes());
    let bytes = mac.finalize().into_bytes();
    let offset = (bytes[19] & 15) as usize;
    format!(
        "{:06}",
        (u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) & 0x7fffffff)
            % 1_000_000
    )
}
#[tokio::test]
#[ignore = "requires PostgreSQL and TRISIXT_ENCRYPTION_KEY"]
async fn totp_enrollment_replay_recovery_and_revocation() {
    let f = Fixture::new().await;
    let (id, token, _) = f.user("mfa@example.test").await;
    let (status, qr) = f
        .req("GET", "/api/v1/users/me/otp_qr", Some(&token), json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{qr}");
    assert!(qr["raw"].as_str().unwrap().contains("<svg"));
    let cipher: String = sqlx::query_scalar("SELECT otp_secret_encrypted FROM users WHERE id=$1")
        .bind(id)
        .fetch_one(&f.st.pg)
        .await
        .unwrap();
    let secret = accounts::decrypt_secret(&format!("totp:{id}"), &cipher).unwrap();
    let code = otp(&secret);
    assert_eq!(
        f.req(
            "PUT",
            "/api/v1/users/me/two_factor",
            Some(&token),
            json!({"enable_2fa":true,"otp_code":"garbage"})
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, enabled) = f
        .req(
            "PUT",
            "/api/v1/users/me/two_factor",
            Some(&token),
            json!({"enable_2fa":true,"otp_code":code}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{enabled}");
    assert_eq!(enabled["recovery_codes"].as_array().unwrap().len(), 10);
    assert_eq!(
        f.req("GET", "/auth/me", Some(&token), json!({})).await.0,
        StatusCode::UNAUTHORIZED
    );
    let creds = json!({"email":"mfa@example.test","password":"correct horse battery staple"});
    let (status, required) = f.req("POST", "/auth/login", None, creds.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(required["requires_otp"], true);
    let mut replay = creds.clone();
    replay["otp_code"] = json!(code);
    assert_eq!(
        f.req("POST", "/auth/login", None, replay).await.0,
        StatusCode::UNAUTHORIZED
    );
    let mut recovery = creds;
    recovery["otp_code"] = enabled["recovery_codes"][0].clone();
    let (status, session) = f.req("POST", "/auth/login", None, recovery.clone()).await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert_eq!(
        f.req("POST", "/auth/login", None, recovery).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.req(
            "GET",
            "/api/v1/users/me/otp_qr",
            session["token"].as_str(),
            json!({})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        f.req(
            "PUT",
            "/api/v1/users/me/two_factor",
            session["token"].as_str(),
            json!({"enable_2fa":false,"otp_code":enabled["recovery_codes"][1]})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT otp_secret_encrypted FROM users WHERE id=$1"
        )
        .bind(id)
        .fetch_one(&f.st.pg)
        .await
        .unwrap()
        .is_none()
    );
    f.finish().await;
}

async fn smtp_server() -> (u16, tokio::task::JoinHandle<String>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (read, mut write) = stream.into_split();
        write
            .write_all(b"220 localhost test SMTP\r\n")
            .await
            .unwrap();
        let mut reader = BufReader::new(read);
        let mut collected = String::new();
        let mut data = false;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).await.unwrap() == 0 {
                break;
            }
            if data {
                if line == ".\r\n" {
                    write.write_all(b"250 queued\r\n").await.unwrap();
                    data = false;
                } else {
                    collected.push_str(&line)
                }
                continue;
            }
            let command = line.to_ascii_uppercase();
            if command.starts_with("EHLO") {
                write
                    .write_all(b"250-localhost\r\n250 8BITMIME\r\n")
                    .await
                    .unwrap();
            } else if command.starts_with("DATA") {
                data = true;
                write.write_all(b"354 send data\r\n").await.unwrap();
            } else if command.starts_with("QUIT") {
                write.write_all(b"221 bye\r\n").await.unwrap();
                break;
            } else {
                write.write_all(b"250 OK\r\n").await.unwrap();
            }
        }
        collected
    });
    (port, task)
}
#[tokio::test]
#[ignore = "requires PostgreSQL and TRISIXT_ENCRYPTION_KEY"]
async fn smtp_outbox_delivers_once_retries_and_never_fakes_success() {
    let f = Fixture::new().await;
    let mut tx = f.st.pg.begin().await.unwrap();
    let mail = accounts::Mail {
        to: "recipient@example.test".into(),
        subject: "Local delivery test".into(),
        text: "Only the local SMTP test server receives this.".into(),
    };
    let id = accounts::enqueue_mail(&mut tx, &mail, Some("deduplicated"))
        .await
        .unwrap();
    assert_eq!(
        accounts::enqueue_mail(&mut tx, &mail, Some("deduplicated"))
            .await
            .unwrap(),
        id
    );
    tx.commit().await.unwrap();
    let options = accounts::SmtpOptions {
        host: "127.0.0.1".into(),
        port: 1,
        from: "sender@example.test".into(),
        username: None,
        password: None,
        plaintext_local: true,
    };
    assert!(accounts::dispatch_mail_with(&f.st, &options).await.is_err());
    let row = sqlx::query(
        "SELECT attempts,sent_at,available_at>now() AS delayed FROM mail_outbox WHERE id=$1",
    )
    .bind(id)
    .fetch_one(&f.st.pg)
    .await
    .unwrap();
    assert_eq!(row.get::<i32, _>("attempts"), 1);
    assert!(
        row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("sent_at")
            .is_none()
    );
    assert!(row.get::<bool, _>("delayed"));
    sqlx::query("UPDATE mail_outbox SET available_at=now() WHERE id=$1")
        .bind(id)
        .execute(&f.st.pg)
        .await
        .unwrap();
    let (port, server) = smtp_server().await;
    let options = accounts::SmtpOptions { port, ..options };
    assert_eq!(
        accounts::dispatch_mail_with(&f.st, &options).await.unwrap(),
        1
    );
    let received = tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    assert!(received.contains("Local delivery test"));
    assert!(received.contains("Message-ID:"));
    assert_eq!(
        accounts::dispatch_mail_with(&f.st, &options).await.unwrap(),
        0
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL and TRISIXT_ENCRYPTION_KEY"]
async fn confirmations_scim_sso_and_alert_delivery_integrate_with_sessions() {
    let f = Fixture::new().await;
    let (owner, token, session) = f.user("policy@example.test").await;
    let (status, _) = f
        .req(
            "POST",
            "/api/v1/users/confirmation",
            None,
            json!({"email":"policy@example.test"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let confirm = f.mail_token("policy@example.test").await;
    assert_eq!(
        f.req(
            "POST",
            "/api/v1/users/confirm",
            None,
            json!({"token":confirm})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        f.req(
            "POST",
            "/api/v1/users/confirm",
            None,
            json!({"token":confirm})
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let (_, instance) = f
        .req(
            "POST",
            "/api/v1/instances",
            Some(&token),
            json!({"name":"Policy tenant"}),
        )
        .await;
    let instance = Uuid::parse_str(instance["id"].as_str().unwrap()).unwrap();
    // Billing alerts become delivered only after their actual durable SMTP job succeeds.
    sqlx::query("DELETE FROM mail_outbox")
        .execute(&f.st.pg)
        .await
        .unwrap();
    sqlx::query("INSERT INTO billing_alerts(instance_id,kind,quantity,limit_value) VALUES($1,'warning',90,100)").bind(instance).execute(&f.st.pg).await.unwrap();
    assert_eq!(accounts::enqueue_alerts(&f.st).await.unwrap(), 1);
    assert_eq!(accounts::enqueue_alerts(&f.st).await.unwrap(), 0);
    assert!(
        sqlx::query_scalar::<_, Option<chrono::DateTime<chrono::Utc>>>(
            "SELECT delivered_at FROM billing_alerts"
        )
        .fetch_one(&f.st.pg)
        .await
        .unwrap()
        .is_none()
    );
    let (port, server) = smtp_server().await;
    let opts = accounts::SmtpOptions {
        host: "127.0.0.1".into(),
        port,
        from: "sender@example.test".into(),
        username: None,
        password: None,
        plaintext_local: true,
    };
    assert_eq!(accounts::dispatch_mail_with(&f.st, &opts).await.unwrap(), 1);
    assert!(server.await.unwrap().contains("Trisixt usage warning"));
    accounts::enqueue_alerts(&f.st).await.unwrap();
    assert!(
        sqlx::query_scalar::<_, Option<chrono::DateTime<chrono::Utc>>>(
            "SELECT delivered_at FROM billing_alerts"
        )
        .fetch_one(&f.st.pg)
        .await
        .unwrap()
        .is_some()
    );
    let (status, scim) = f
        .req(
            "POST",
            &format!("/api/v1/instances/{instance}/scim-token"),
            Some(&token),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{scim}");
    let scim = scim["token"].as_str().unwrap();
    let (status, managed) = f
        .req(
            "POST",
            "/scim/v2/Users",
            Some(scim),
            json!({"userName":"managed@other.test","active":true}),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{managed}");
    let managed_id = Uuid::parse_str(managed["id"].as_str().unwrap()).unwrap();
    let managed_session = accounts::issue_session(&f.st, managed_id).await.unwrap();
    let path = format!("/scim/v2/Users/{managed_id}");
    let (status, result) = f
        .req(
            "PATCH",
            &path,
            Some(scim),
            json!({"Operations":[{"op":"replace","path":"active","value":false}]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert!(
        accounts::rotate_refresh(&f.st, managed_session["refresh_token"].as_str().unwrap())
            .await
            .is_err()
    );
    f.req(
        "PATCH",
        &path,
        Some(scim),
        json!({"Operations":[{"op":"replace","path":"active","value":true}]}),
    )
    .await;
    assert!(
        accounts::rotate_refresh(&f.st, managed_session["refresh_token"].as_str().unwrap())
            .await
            .is_err(),
        "reactivation must not restore old sessions"
    );
    sqlx::query("INSERT INTO instance_sso(instance_id,provider_key,enabled,enforced) VALUES($1,'test',true,true)").bind(instance).execute(&f.st.pg).await.unwrap();
    sqlx::query("INSERT INTO instance_sso_domains(instance_id,domain,verification_token,verified_at) VALUES($1,'example.test','proof',now())").bind(instance).execute(&f.st.pg).await.unwrap();
    assert!(
        accounts::rotate_refresh(&f.st, session["refresh_token"].as_str().unwrap())
            .await
            .is_err()
    );
    assert_eq!(
        f.req(
            "POST",
            "/auth/login",
            None,
            json!({"email":"policy@example.test","password":"correct horse battery staple"})
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.req(
            "POST",
            "/auth/register",
            None,
            json!({"email":"new@example.test","password":"correct horse battery staple"})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    // Sessions established through the enforced provider keep rotating normally.
    let (raw, hash) = trisixt::auth::new_token();
    sqlx::query("INSERT INTO refresh_sessions(user_id,family_id,token_hash,auth_method) VALUES($1,$2,$3,'oidc')").bind(owner).bind(Uuid::new_v4()).bind(hash).execute(&f.st.pg).await.unwrap();
    assert!(accounts::rotate_refresh(&f.st, &raw).await.is_ok());
    f.finish().await;
}
