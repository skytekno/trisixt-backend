mod support;

use axum::http::StatusCode;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use support::Fixture;
use uuid::Uuid;

async fn token(f: &Fixture, scope: &str, projects: &[Uuid]) -> String {
    let client: Uuid = sqlx::query_scalar(
        "INSERT INTO mcp_clients(name,redirect_uris) VALUES('Search fixture','[]') RETURNING id",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    let (raw, hash) = trisixt::auth::new_token();
    sqlx::query("INSERT INTO mcp_tokens(family_id,client_id,user_id,access_hash,refresh_hash,scope,issuer,audience,project_ids,expires_at,refresh_expires_at) VALUES($1,$2,$3,$4,$5,$6,'https://example.test','https://example.test/api/v1/mcp',$7,now()+interval '1 hour',now()+interval '1 day')")
        .bind(Uuid::new_v4()).bind(client).bind(f.user).bind(hash)
        .bind(Uuid::new_v4().to_string()).bind(scope).bind(projects)
        .execute(&f.pool).await.unwrap();
    raw
}

async fn rpc(f: &Fixture, token: &str, method: &str, params: Value) -> (StatusCode, Value) {
    let (status, body, _) = f
        .raw(
            "POST",
            "/api/v1/mcp",
            json!({
                "jsonrpc":"2.0","id":7,"method":method,"params":params
            }),
            token,
            "",
        )
        .await;
    (status, body)
}

fn result_body(reply: &Value) -> Value {
    let text = reply["result"]["content"][0]["text"].as_str().unwrap();
    serde_json::from_str(text).unwrap_or_else(|_| json!({"raw":text}))
}

async fn parity(f: &Fixture, token: &str, entity: &str, query: Value) -> Value {
    let (status, expected) = f
        .call("POST", &f.path(&format!("{entity}/search")), query.clone())
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "native {entity} {query}: {expected}"
    );
    let mut args = query.clone();
    args["project_id"] = json!(f.project);
    let (status, actual, _) = f
        .raw(
            "POST",
            &format!("/api/v1/mcp/{entity}/search"),
            args.clone(),
            token,
            "",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "REST {entity} {query}: {actual}");
    assert_eq!(actual, expected, "REST {entity} {query}");
    let (status, reply) = rpc(
        f,
        token,
        "tools/call",
        json!({"name":format!("search_{entity}"),"arguments":args}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    assert_eq!(result_body(&reply), expected, "RPC {entity} {query}");
    expected
}

struct Data {
    links: Vec<Value>,
    campaigns: Vec<Value>,
    day: String,
}
impl Data {
    fn query(&self, extra: Value) -> Value {
        let mut query =
            json!({"start_date":self.day,"end_date":self.day,"sort_by":"name","sort_order":"asc"});
        query
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        query
    }
}

async fn seed(f: &Fixture) -> Data {
    let mut campaigns = vec![];
    for name in ["Alpha campaign", "Beta campaign", "Empty campaign"] {
        let (s, c) = f
            .call("POST", &f.path("campaigns"), json!({"name":name}))
            .await;
        assert_eq!(s, StatusCode::CREATED, "{c}");
        campaigns.push(c);
    }
    let mut links = vec![];
    for (i, (name, tag, ad, sdk)) in [
        ("Alpha apple", "Summer", "google", false),
        ("Beta berry", "Winter", "facebook", true),
        ("Gamma grape", "Summer", "facebook", true),
        ("Delta dormant", "Winter", "google", false),
    ]
    .into_iter()
    .enumerate()
    {
        let campaign = if i == 3 {
            Value::Null
        } else {
            campaigns[usize::from(i == 1)]["id"].clone()
        };
        let (s, l) = f.call("POST", &f.path("links"), json!({
            "name":name,"path":format!("search-{i}"),"campaign_id":campaign,
            "metadata":{"title":format!("Title {i}"),"tags":[tag],"ads_platform":ad,"sdk_generated":sdk}
        })).await;
        assert_eq!(s, StatusCode::CREATED, "{l}");
        links.push(l);
    }
    let at = (Utc::now() - Duration::days(2))
        .date_naive()
        .and_hms_opt(12, 0, 0)
        .unwrap()
        .and_utc();
    for (index, platform, count) in [(0, "ios", 2), (0, "android", 1), (1, "ios", 1)] {
        let visitor = f.visitor().await;
        for _ in 0..count {
            f.event(
                visitor,
                "view",
                at,
                json!({"link_id":links[index]["id"],"platform":platform}),
            )
            .await;
        }
    }
    f.event(
        f.visitor().await,
        "time_spent",
        at,
        json!({"link_id":links[0]["id"],"platform":"ios","engagement_time":1250}),
    )
    .await;
    f.event(
        f.visitor().await,
        "view",
        at - Duration::days(1),
        json!({"link_id":links[1]["id"],"platform":"ios"}),
    )
    .await;
    sqlx::query("UPDATE links SET archived_at=now() WHERE id=$1")
        .bind(links[3]["id"].as_str().unwrap().parse::<Uuid>().unwrap())
        .execute(&f.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE campaigns SET archived_at=now() WHERE id=$1")
        .bind(
            campaigns[1]["id"]
                .as_str()
                .unwrap()
                .parse::<Uuid>()
                .unwrap(),
        )
        .execute(&f.pool)
        .await
        .unwrap();
    Data {
        links,
        campaigns,
        day: at.date_naive().to_string(),
    }
}

fn ids(response: &Value, entity: &str) -> Vec<Value> {
    response[entity]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].clone())
        .collect()
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run scripts/integration.sh"]
async fn mcp_link_search_preserves_filters_and_exact_native_metrics() {
    let f = Fixture::new().await;
    let data = seed(&f).await;
    let access = token(&f, "mcp:read", &[f.project]).await;
    for (query, expected) in [
        (json!({}), vec![0, 1, 3, 2]),
        (json!({"term":"apple"}), vec![0]),
        (json!({"search":"Title 1"}), vec![1]),
        (json!({"query":"Summer"}), vec![0, 2]),
        (json!({"campaign_id":data.campaigns[0]["id"]}), vec![0, 2]),
        (json!({"link_id":data.links[1]["id"]}), vec![1]),
        (json!({"sdk":true}), vec![1, 2]),
        (json!({"active":true}), vec![0, 1, 2]),
        (json!({"archived":true}), vec![3]),
        (
            json!({"tags":["Summer"],"ads_platform":"facebook"}),
            vec![2],
        ),
        (
            json!({"ids":[data.links[0]["id"],data.links[1]["id"]]}),
            vec![0, 1],
        ),
        (json!({"term":"does-not-exist"}), vec![]),
    ] {
        let result = parity(&f, &access, "links", data.query(query)).await;
        assert_eq!(
            ids(&result, "links"),
            expected
                .into_iter()
                .map(|i| data.links[i]["id"].clone())
                .collect::<Vec<_>>()
        );
    }
    for (platform, views) in [("ios", 2), ("android", 1), ("web", 0)] {
        let result = parity(
            &f,
            &access,
            "links",
            data.query(json!({"ids":[data.links[0]["id"]],"platform":platform})),
        )
        .await;
        assert_eq!(result["links"][0]["total_views"], views);
        assert_eq!(
            result["links"][0]["total_time_spent"],
            if platform == "ios" { 1250.0 } else { 0.0 }
        );
    }
    let result = parity(
        &f,
        &access,
        "links",
        data.query(json!({"sort_by":"views","sort_order":"desc","limit":1})),
    )
    .await;
    assert_eq!(result["links"][0]["id"], data.links[0]["id"]);
    assert_eq!(result["links"][0]["total_views"], 3);
    assert_eq!(result["meta"]["total_entries"], 4);
    assert_eq!(result["next_offset"], 1);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run scripts/integration.sh"]
async fn mcp_campaign_search_preserves_filters_dates_and_zero_activity() {
    let f = Fixture::new().await;
    let data = seed(&f).await;
    let access = token(&f, "mcp:read", &[f.project]).await;
    for (query, expected) in [
        (json!({}), vec![0, 1, 2]),
        (json!({"term":"Alpha"}), vec![0]),
        (json!({"active":true}), vec![0, 2]),
        (json!({"archived":true}), vec![1]),
        (json!({"ids":[data.campaigns[2]["id"]]}), vec![2]),
        (json!({"term":"missing"}), vec![]),
    ] {
        let result = parity(&f, &access, "campaigns", data.query(query)).await;
        assert_eq!(
            ids(&result, "campaigns"),
            expected
                .into_iter()
                .map(|i| data.campaigns[i]["id"].clone())
                .collect::<Vec<_>>()
        );
    }
    let result = parity(
        &f,
        &access,
        "campaigns",
        data.query(json!({"platform":"ios","sort_by":"views","sort_order":"desc"})),
    )
    .await;
    assert_eq!(
        ids(&result, "campaigns"),
        data.campaigns
            .iter()
            .map(|c| c["id"].clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(result["campaigns"][0]["total_views"], 2);
    assert_eq!(result["campaigns"][1]["total_views"], 1);
    assert_eq!(result["campaigns"][2]["total_views"], 0);
    let result = parity(
        &f,
        &access,
        "campaigns",
        data.query(
            json!({"from":format!("{}T13:00:00Z",data.day),"to":format!("{}T14:00:00Z",data.day)}),
        ),
    )
    .await;
    assert!(
        result["campaigns"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["total_views"] == 0)
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run scripts/integration.sh"]
async fn mcp_search_paginates_tied_rows_without_gaps() {
    let f = Fixture::new().await;
    let access = token(&f, "mcp:read", &[f.project]).await;
    for entity in ["links", "campaigns"] {
        let mut expected = vec![];
        for i in 1..=5 {
            let id = Uuid::from_u128(i);
            if entity == "links" {
                sqlx::query("INSERT INTO links(id,project_id,name,path,target_url) VALUES($1,$2,'Tied',$3,'https://example.test')")
                    .bind(id)
                    .bind(f.project)
                    .bind(format!("tie-{i}"))
                    .execute(&f.pool)
                    .await
                    .unwrap();
            } else {
                sqlx::query("INSERT INTO campaigns(id,project_id,name) VALUES($1,$2,'Tied')")
                    .bind(id)
                    .bind(f.project)
                    .execute(&f.pool)
                    .await
                    .unwrap();
            }
            expected.push(json!(id));
        }
        for order in ["asc", "desc"] {
            let mut found = vec![];
            for page in 1..=3 {
                let result = parity(
                    &f,
                    &access,
                    entity,
                    json!({"sort_by":"name","sort_order":order,"per_page":2,"page":page}),
                )
                .await;
                assert_eq!(
                    result["meta"],
                    json!({"page":page,"per_page":2,"total_entries":5,"total_pages":3})
                );
                assert_eq!(
                    result["next_offset"],
                    if page < 3 {
                        json!(page * 2)
                    } else {
                        Value::Null
                    }
                );
                found.extend(ids(&result, entity));
            }
            assert_eq!(
                found, expected,
                "UUID tie breaker must be stable for {entity} {order}"
            );
        }
        let empty = parity(&f, &access, entity, json!({"offset":5,"limit":2})).await;
        assert!(empty[entity].as_array().unwrap().is_empty());
    }
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run scripts/integration.sh"]
async fn malformed_search_filters_match_native_errors_without_mutation() {
    let f = Fixture::new().await;
    let access = token(&f, "mcp:read", &[f.project]).await;
    for entity in ["links", "campaigns"] {
        for query in [
            json!({"limit":0}),
            json!({"limit":1001}),
            json!({"page":0}),
            json!({"offset":-1}),
            json!({"sort_by":"name; DROP TABLE links"}),
            json!({"sort_order":"up"}),
            json!({"timezone":"invalid"}),
            json!({"start_date":"invalid"}),
            json!({"ids":["not-a-uuid"]}),
            json!({"tags":"Summer"}),
            json!({"active":"true"}),
        ] {
            let (expected_status, expected) = f
                .call("POST", &f.path(&format!("{entity}/search")), query.clone())
                .await;
            assert!(expected_status.is_client_error(), "{query}: {expected}");
            let mut args = query.clone();
            args["project_id"] = json!(f.project);
            let (status, body, _) = f
                .raw(
                    "POST",
                    &format!("/api/v1/mcp/{entity}/search"),
                    args.clone(),
                    &access,
                    "",
                )
                .await;
            assert_eq!(status, expected_status, "{entity} {query}: {body}");
            assert_eq!(body, expected);
            let (_, reply) = rpc(
                &f,
                &access,
                "tools/call",
                json!({"name":format!("search_{entity}"),"arguments":args}),
            )
            .await;
            assert_eq!(reply["result"]["isError"], true, "{reply}");
            assert_eq!(result_body(&reply), expected);
        }
    }
    let count:i64=sqlx::query_scalar("SELECT (SELECT count(*) FROM links)+(SELECT count(*) FROM campaigns)+(SELECT count(*) FROM events)").fetch_one(&f.pool).await.unwrap();
    assert_eq!(count, 0);
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run scripts/integration.sh"]
async fn search_scopes_grants_revocation_and_current_membership_are_enforced() {
    let f = Fixture::new().await;
    let access = token(&f, "mcp:read", &[f.project]).await;
    let ungranted = token(&f, "mcp:read", &[]).await;
    let write_only = token(&f, "mcp:write", &[f.project]).await;
    let foreign_instance: Uuid =
        sqlx::query_scalar("INSERT INTO instances(name) VALUES('Foreign') RETURNING id")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    let foreign:Uuid=sqlx::query_scalar("INSERT INTO projects(instance_id,environment,domain) VALUES($1,'test','foreign.example.test') RETURNING id").bind(foreign_instance).fetch_one(&f.pool).await.unwrap();
    let foreign_grant = token(&f, "mcp:read", &[foreign]).await;
    for entity in ["links", "campaigns"] {
        parity(&f, &access, entity, json!({})).await;
        for (credential, project) in [
            (&ungranted, f.project),
            (&write_only, f.project),
            (&access, foreign),
            (&foreign_grant, foreign),
        ] {
            let args = json!({"project_id":project});
            let (s, _, _) = f
                .raw(
                    "POST",
                    &format!("/api/v1/mcp/{entity}/search"),
                    args.clone(),
                    credential,
                    "",
                )
                .await;
            assert_eq!(s, StatusCode::FORBIDDEN);
            let (_, r) = rpc(
                &f,
                credential,
                "tools/call",
                json!({"name":format!("search_{entity}"),"arguments":args}),
            )
            .await;
            assert_eq!(r["result"]["isError"], true, "{r}");
            assert_eq!(result_body(&r), json!({"error":"forbidden"}));
        }
        let (s, _, _) = f
            .raw(
                "POST",
                &format!("/api/v1/mcp/{entity}"),
                json!({"project_id":f.project,"name":"Denied"}),
                &access,
                "",
            )
            .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
    }
    sqlx::query("DELETE FROM instance_roles WHERE user_id=$1")
        .bind(f.user)
        .execute(&f.pool)
        .await
        .unwrap();
    let (s, _, _) = f
        .raw(
            "POST",
            "/api/v1/mcp/links/search",
            json!({"project_id":f.project}),
            &access,
            "",
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    sqlx::query("UPDATE mcp_tokens SET revoked_at=now()")
        .execute(&f.pool)
        .await
        .unwrap();
    let (s, _, headers) = f
        .raw(
            "POST",
            "/api/v1/mcp/campaigns/search",
            json!({"project_id":f.project}),
            &access,
            "",
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(headers.contains_key("www-authenticate"));
    assert_eq!(
        rpc(
            &f,
            &access,
            "tools/call",
            json!({"name":"search_links","arguments":{"project_id":f.project}})
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    f.close().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL; run scripts/integration.sh"]
async fn search_tools_advertise_typed_filters_and_preserve_legacy_date_aliases() {
    let f = Fixture::new().await;
    let data = seed(&f).await;
    let access = token(&f, "mcp:read", &[f.project]).await;
    let (status, listed) = rpc(&f, &access, "tools/list", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let tools = listed["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 14);
    for entity in ["links", "campaigns"] {
        let name = format!("search_{entity}");
        let tool = tools.iter().find(|t| t["name"] == name).unwrap();
        assert_eq!(tool["annotations"]["readOnlyHint"], true);
        assert_eq!(tool["annotations"]["destructiveHint"], false);
        assert_eq!(tool["inputSchema"]["required"], json!(["project_id"]));
        let properties = &tool["inputSchema"]["properties"];
        assert_eq!(properties["ids"]["items"]["format"], "uuid");
        assert_eq!(properties["active"]["type"], "boolean");
        assert_eq!(properties["limit"]["maximum"], 1000);
        assert_eq!(properties["offset"]["maximum"], 100000);
        for field in [
            "term",
            "query",
            "search",
            "archived",
            "sort_by",
            "sort_order",
            "ascending",
            "from",
            "to",
            "timezone",
            "platform",
            "date_from",
            "date_to",
        ] {
            assert!(!properties[field].is_null(), "missing {field} in {tool}");
        }
        if entity == "links" {
            assert_eq!(properties["tags"]["type"], "array");
            assert_eq!(properties["sdk"]["type"], "boolean");
            assert_eq!(properties["campaign_id"]["format"], "uuid");
        } else {
            assert!(
                properties["tags"].is_null(),
                "campaigns do not support link-only filters"
            );
        }
        let expected = parity(&f, &access, entity, data.query(json!({"platform":"ios"}))).await;
        let args = json!({"project_id":f.project,"date_from":data.day,"date_to":data.day,"platform":"ios","sort_by":"name","ascending":true});
        let (status, rest, _) = f
            .raw(
                "POST",
                &format!("/api/v1/mcp/{entity}/search"),
                args.clone(),
                &access,
                "",
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(rest, expected);
        let (_, reply) = rpc(
            &f,
            &access,
            "tools/call",
            json!({"name":name,"arguments":args}),
        )
        .await;
        assert_eq!(reply["result"]["isError"], false, "{reply}");
        assert_eq!(result_body(&reply), expected);
        for body in [json!([]), json!(true), json!("invalid")] {
            let (status, _, _) = f
                .raw(
                    "POST",
                    &format!("/api/v1/mcp/{entity}/search?project_id={}", f.project),
                    body.clone(),
                    &access,
                    "",
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            let (_, reply) = rpc(
                &f,
                &access,
                "tools/call",
                json!({"name":name,"arguments":body}),
            )
            .await;
            assert_eq!(reply["error"]["code"], -32602);
        }
    }
    f.close().await;
}
