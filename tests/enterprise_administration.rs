mod support;
use axum::http::StatusCode;
use serde_json::{Value, json};
use support::Fixture;
use uuid::Uuid;
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn audit_export_token_is_read_only_scoped_revocable_and_never_relisted() {
    let f = Fixture::new().await;
    let path = format!("/api/v1/instances/{}/audit_export_tokens", f.instance);
    let (s, b) = f.call("POST", &path, json!({"name":"SIEM"})).await;
    assert_eq!(s, StatusCode::CREATED, "{b}");
    let token = b["token"].as_str().unwrap();
    let id = b["audit_export_token"]["id"].as_str().unwrap();
    let (s, body, _) = f
        .raw(
            "GET",
            &format!(
                "/api/v1/instances/{}/audit_events?order=desc&limit=2",
                f.instance
            ),
            Value::Null,
            token,
            "",
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["events"].as_array().unwrap().len(), 2);
    assert!(body["events"][0]["sequence"].as_i64() > body["events"][1]["sequence"].as_i64());
    let (s, _, _) = f
        .raw(
            "GET",
            &format!("/api/v1/instances/{}/audit_events", Uuid::new_v4()),
            Value::Null,
            token,
            "",
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, b) = f.call("GET", &path, Value::Null).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!b.to_string().contains(token));
    let (s, _) = f.call("DELETE", &format!("{path}/{id}"), Value::Null).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _, _) = f
        .raw(
            "GET",
            &format!("/api/v1/instances/{}/audit_events/head", f.instance),
            Value::Null,
            token,
            "",
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    f.close().await;
}
#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn verified_domains_required_for_enforcement_and_jit_does_not_claim_unmanaged_user() {
    let f = Fixture::new().await;
    sqlx::query("INSERT INTO instance_sso(instance_id,provider_key) VALUES($1,'fixture')")
        .bind(f.instance)
        .execute(&f.pool)
        .await
        .unwrap();
    let path = format!("/api/v1/instances/{}/sso/policy", f.instance);
    let payload = json!({"enforced":false,"jit_provision":true,"admin_claim_value":"admins","domains":["company.test"]});
    let (s, b) = f.call("PUT", &path, payload.clone()).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let (s, _) = f
        .call(
            "PUT",
            &path,
            json!({"enforced":true,"jit_provision":true,"domains":["company.test"]}),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (id, token) = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT id,verification_token FROM instance_sso_domains WHERE instance_id=$1",
    )
    .bind(f.instance)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(
        !trisixt::enterprise_admin::verify_domain_records(&f.state, id, &["wrong".into()])
            .await
            .unwrap()
    );
    assert!(
        trisixt::enterprise_admin::verify_domain_records(
            &f.state,
            id,
            &[format!("trisixt-sso={token}")]
        )
        .await
        .unwrap()
    );
    let(s,b)=f.call("PUT",&path,json!({"enforced":true,"jit_provision":true,"admin_claim_value":"admins","domains":["company.test"]})).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert!(
        !trisixt::enterprise_admin::password_email_allowed(&f.state, "new@company.test")
            .await
            .unwrap()
    );
    assert!(
        trisixt::enterprise_admin::password_email_allowed(&f.state, "elsewhere@example.test")
            .await
            .unwrap()
    );
    let identity = trisixt::oidc::VerifiedIdentity {
        issuer: "https://idp.example.test".into(),
        subject: "subject-one".into(),
        email: "new@company.test".into(),
        name: Some("New".into()),
        groups: vec!["admins".into()],
    };
    let mut tx = f.pool.begin().await.unwrap();
    let user = trisixt::enterprise_admin::provision_identity(&mut tx, f.instance, &identity)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM instance_roles WHERE instance_id=$1 AND user_id=$2",
    )
    .bind(f.instance)
    .bind(user)
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(role, "admin");
    sqlx::query("INSERT INTO users(email) VALUES('unmanaged@company.test')")
        .execute(&f.pool)
        .await
        .unwrap();
    let mut tx = f.pool.begin().await.unwrap();
    let unsafe_identity = trisixt::oidc::VerifiedIdentity {
        subject: "second".into(),
        email: "unmanaged@company.test".into(),
        ..identity
    };
    assert!(
        trisixt::enterprise_admin::provision_identity(&mut tx, f.instance, &unsafe_identity)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    let (s, _) = f
        .call(
            "DELETE",
            &format!("/api/v1/instances/{}/sso", f.instance),
            Value::Null,
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn enforcing_new_verified_domain_waits_for_user_and_revokes_concurrent_sessions() {
    let f = Fixture::new().await;
    sqlx::query(
        "INSERT INTO instance_sso(instance_id,provider_key,enforced) VALUES($1,'fixture',true)",
    )
    .bind(f.instance)
    .execute(&f.pool)
    .await
    .unwrap();
    let id = sqlx::query_scalar::<_,Uuid>("INSERT INTO instance_sso_domains(instance_id,domain,verification_token) VALUES($1,'company.test','proof') RETURNING id").bind(f.instance).fetch_one(&f.pool).await.unwrap();
    let user = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO users(email) VALUES('race@company.test') RETURNING id",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    let client = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO mcp_clients(name,redirect_uris) VALUES('fixture','[]') RETURNING id",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    let mut issuer = f.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM users WHERE id=$1 FOR UPDATE")
        .bind(user)
        .execute(&mut *issuer)
        .await
        .unwrap();
    let state = f.state.clone();
    let mut verification = tokio::spawn(async move {
        trisixt::enterprise_admin::verify_domain_records(&state, id, &["trisixt-sso=proof".into()])
            .await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(150), &mut verification)
            .await
            .is_err(),
        "domain revocation must wait for the in-flight user transaction"
    );
    let access=sqlx::query_scalar::<_,Uuid>("INSERT INTO access_tokens(user_id,token_hash,expires_at) VALUES($1,'race-access',now()+interval '1 hour') RETURNING id").bind(user).fetch_one(&mut *issuer).await.unwrap();
    sqlx::query("INSERT INTO refresh_sessions(user_id,family_id,token_hash,access_token_id) VALUES($1,gen_random_uuid(),'race-refresh',$2)").bind(user).bind(access).execute(&mut *issuer).await.unwrap();
    sqlx::query("INSERT INTO mcp_tokens(family_id,client_id,user_id,access_hash,refresh_hash,scope,issuer,audience,project_ids,expires_at,refresh_expires_at) VALUES(gen_random_uuid(),$1,$2,'mcp-access','mcp-refresh','read','https://api.example.test','mcp','{}',now()+interval '1 hour',now()+interval '7 days')").bind(client).bind(user).execute(&mut *issuer).await.unwrap();
    issuer.commit().await.unwrap();
    assert!(verification.await.unwrap().unwrap());
    for query in [
        "SELECT count(*) FROM access_tokens WHERE user_id=$1",
        "SELECT count(*) FROM refresh_sessions WHERE user_id=$1 AND revoked_at IS NULL",
        "SELECT count(*) FROM mcp_tokens WHERE user_id=$1 AND revoked_at IS NULL",
    ] {
        assert_eq!(
            sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(query))
                .bind(user)
                .fetch_one(&f.pool)
                .await
                .unwrap(),
            0
        );
    }
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn linked_identity_rechecks_verified_domain_and_applies_new_admin_claim() {
    let f = Fixture::new().await;
    sqlx::query("INSERT INTO instance_sso(instance_id,provider_key,admin_claim_value) VALUES($1,'fixture','administrators')").bind(f.instance).execute(&f.pool).await.unwrap();
    let user = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO users(email) VALUES('linked@company.test') RETURNING id",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO instance_roles(instance_id,user_id,role) VALUES($1,$2,'member')")
        .bind(f.instance)
        .bind(user)
        .execute(&f.pool)
        .await
        .unwrap();
    let mut identity = trisixt::oidc::VerifiedIdentity {
        issuer: "https://id.example.test".into(),
        subject: "linked-subject".into(),
        email: "linked@company.test".into(),
        name: None,
        groups: vec![],
    };
    let mut tx = f.pool.begin().await.unwrap();
    trisixt::enterprise_admin::apply_identity_policy(&mut tx, f.instance, user, &identity)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    sqlx::query("INSERT INTO instance_sso_domains(instance_id,domain,verification_token) VALUES($1,'company.test','proof')").bind(f.instance).execute(&f.pool).await.unwrap();
    let mut tx = f.pool.begin().await.unwrap();
    assert!(
        trisixt::enterprise_admin::apply_identity_policy(&mut tx, f.instance, user, &identity)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    sqlx::query("UPDATE instance_sso_domains SET verified_at=now() WHERE instance_id=$1")
        .bind(f.instance)
        .execute(&f.pool)
        .await
        .unwrap();
    identity.groups = vec!["administrators".into()];
    let mut tx = f.pool.begin().await.unwrap();
    trisixt::enterprise_admin::apply_identity_policy(&mut tx, f.instance, user, &identity)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT role FROM instance_roles WHERE instance_id=$1 AND user_id=$2"
        )
        .bind(f.instance)
        .bind(user)
        .fetch_one(&f.pool)
        .await
        .unwrap(),
        "admin"
    );
    identity.email = "linked@outsider.test".into();
    let mut tx = f.pool.begin().await.unwrap();
    assert!(
        trisixt::enterprise_admin::apply_identity_policy(&mut tx, f.instance, user, &identity)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    f.close().await;
}
