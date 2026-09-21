//! The same deterministic contract is shared by native and external runners.
use chrono::{DateTime, Duration, Utc};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

use super::Fixture;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::json;
use tower::ServiceExt;

pub struct Baseline {
    pub fixture: Fixture,
    pub contract: Contract,
    owner_b_token: String,
    project_b_key: String,
}

fn uuid(value: &Value) -> Uuid {
    value.as_str().unwrap().parse().unwrap()
}

impl Baseline {
    pub async fn new(run_id: &str, anchor: DateTime<Utc>) -> Self {
        let contract = Contract::load(run_id, anchor);
        let fixture = Fixture::with_ids(
            contract.id("owner_a"),
            contract.id("instance_a"),
            contract.id("project_a"),
        )
        .await;
        let pool = &fixture.pool;
        for owner in contract.data["owners"].as_array().unwrap() {
            sqlx::query("INSERT INTO users(id,email) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET email=excluded.email")
                .bind(uuid(&owner["id"])).bind(owner["email"].as_str().unwrap())
                .execute(pool).await.unwrap();
        }
        for instance in contract.data["instances"].as_array().unwrap() {
            sqlx::query("INSERT INTO instances(id,name,revenue_collection_enabled) VALUES($1,$2,true) ON CONFLICT(id) DO UPDATE SET name=excluded.name,revenue_collection_enabled=true")
                .bind(uuid(&instance["id"])).bind(instance["name"].as_str().unwrap())
                .execute(pool).await.unwrap();
            sqlx::query("INSERT INTO instance_roles(user_id,instance_id,role) VALUES($1,$2,'owner') ON CONFLICT DO NOTHING")
                .bind(uuid(&instance["owner_id"])).bind(uuid(&instance["id"]))
                .execute(pool).await.unwrap();
        }
        for project in contract.data["projects"].as_array().unwrap() {
            sqlx::query("INSERT INTO projects(id,instance_id,name,environment,domain) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET name=excluded.name,environment=excluded.environment,domain=excluded.domain")
                .bind(uuid(&project["id"])).bind(uuid(&project["instance_id"]))
                .bind(project["name"].as_str().unwrap()).bind(project["environment"].as_str().unwrap())
                .bind(project["domain"].as_str().unwrap()).execute(pool).await.unwrap();
        }
        let (owner_b_token, token_hash) = trisixt::auth::new_token();
        sqlx::query("INSERT INTO access_tokens(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '1 hour')")
            .bind(contract.id("owner_b")).bind(token_hash).execute(pool).await.unwrap();
        let (project_b_key, key_hash) = trisixt::auth::new_token();
        sqlx::query(
            "INSERT INTO project_api_keys(project_id,name,token_hash) VALUES($1,'baseline',$2)",
        )
        .bind(contract.id("project_b"))
        .bind(key_hash)
        .execute(pool)
        .await
        .unwrap();
        for visitor in contract.data["visitors"].as_array().unwrap() {
            sqlx::query(
                "INSERT INTO visitors(project_id,id,external_id,attributes) VALUES($1,$2,$3,$4)",
            )
            .bind(uuid(&visitor["project_id"]))
            .bind(uuid(&visitor["id"]))
            .bind(visitor["external_id"].as_str())
            .bind(&visitor["attributes"])
            .execute(pool)
            .await
            .unwrap();
        }
        // SQL seeding preserves fixture IDs. Public creation routes assign IDs;
        // external runners must retain their response-to-logical-ID mapping.
        for campaign in contract.data["campaigns"].as_array().unwrap() {
            sqlx::query("INSERT INTO campaigns(id,project_id,name,metadata) VALUES($1,$2,$3,$4)")
                .bind(uuid(&campaign["id"]))
                .bind(uuid(&campaign["project_id"]))
                .bind(campaign["request"]["name"].as_str().unwrap())
                .bind(&campaign["request"]["metadata"])
                .execute(pool)
                .await
                .unwrap();
        }
        for link in contract.data["links"].as_array().unwrap() {
            let request = &link["request"];
            sqlx::query("INSERT INTO links(id,project_id,campaign_id,name,path,target_url,metadata) VALUES($1,$2,$3,$4,$5,$6,$7)")
                .bind(uuid(&link["id"])).bind(uuid(&link["project_id"]))
                .bind(uuid(&request["campaign_id"])).bind(request["name"].as_str().unwrap())
                .bind(request["path"].as_str().unwrap()).bind(request["target_url"].as_str().unwrap())
                .bind(json!({"tracking_source":request["tracking_source"],"tracking_medium":request["tracking_medium"],"tracking_campaign":request["tracking_campaign"],"data":request["data"]}))
                .execute(pool).await.unwrap();
        }
        let baseline = Self {
            fixture,
            contract,
            owner_b_token,
            project_b_key,
        };
        for configuration in baseline.contract.data["sdk_configurations"]
            .as_array()
            .unwrap()
        {
            let project = uuid(&configuration["project_id"]);
            let path = format!(
                "/api/v1/projects/{project}/configurations/{}",
                configuration["platform"].as_str().unwrap()
            );
            let (status, body) = baseline
                .call(project, "PUT", &path, configuration["request"].clone())
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
        }
        baseline
    }

    /// Project selects its owner/key pair; path can deliberately target another
    /// tenant when checking denial. Never print or serialize these credentials.
    pub async fn call(
        &self,
        project: Uuid,
        method: &str,
        path: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let (token, key) = if project == self.contract.id("project_a") {
            (&self.fixture.token, &self.fixture.key)
        } else {
            assert_eq!(project, self.contract.id("project_b"));
            (&self.owner_b_token, &self.project_b_key)
        };
        let configuration = self.contract.data["sdk_configurations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["project_id"] == project.to_string() && c["platform"] == "ios")
            .expect("baseline calls use the declared iOS app");
        let identifier = configuration["request"]["bundle_id"].as_str().unwrap();
        let response = self
            .fixture
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("authorization", format!("Bearer {token}"))
                    .header("x-project-key", key)
                    .header("platform", "ios")
                    .header("identifier", identifier)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 2_000_000).await.unwrap();
        let value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&bytes)}));
        (status, value)
    }
}

pub struct Contract {
    pub data: Value,
    pub ids: BTreeMap<String, Uuid>,
}

impl Contract {
    pub fn load(run_id: &str, anchor: DateTime<Utc>) -> Self {
        assert!(!run_id.is_empty() && run_id.len() <= 40);
        assert!(run_id.as_bytes()[0].is_ascii_lowercase());
        assert!(
            run_id
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        );
        assert_eq!(anchor.time(), chrono::NaiveTime::MIN);
        let raw: Value =
            serde_json::from_str(include_str!("../fixtures/baseline/manifest.v1.json")).unwrap();
        assert_eq!(raw["contract_version"], 1);
        let namespace = raw["namespace"].as_str().unwrap();
        let keys = raw["id_keys"].as_array().unwrap();
        let ids: BTreeMap<_, _> = keys
            .iter()
            .map(|key| {
                let key = key.as_str().unwrap();
                let digest = Sha256::digest(format!("{namespace}/{run_id}/{key}"));
                let mut bytes: [u8; 16] = digest[..16].try_into().unwrap();
                bytes[6] = (bytes[6] & 0x0f) | 0x80;
                bytes[8] = (bytes[8] & 0x3f) | 0x80;
                (key.to_owned(), Uuid::from_bytes(bytes))
            })
            .collect();
        assert_eq!(ids.len(), keys.len(), "duplicate logical identity");

        fn render(
            value: &Value,
            ids: &BTreeMap<String, Uuid>,
            run_id: &str,
            anchor: DateTime<Utc>,
        ) -> Value {
            match value {
                Value::Object(values) => Value::Object(
                    values
                        .iter()
                        .map(|(k, v)| (k.clone(), render(v, ids, run_id, anchor)))
                        .collect::<Map<_, _>>(),
                ),
                Value::Array(values) => Value::Array(
                    values
                        .iter()
                        .map(|v| render(v, ids, run_id, anchor))
                        .collect(),
                ),
                Value::String(value) => {
                    let mut rest = value.as_str();
                    let mut result = String::new();
                    while let Some((prefix, token_and_rest)) = rest.split_once("{{") {
                        result.push_str(prefix);
                        let (token, suffix) = token_and_rest.split_once("}}").unwrap();
                        if token == "run_id" {
                            result.push_str(run_id);
                        } else if let Some(key) = token.strip_prefix("id:") {
                            result.push_str(&ids[key].to_string());
                        } else if let Some(seconds) = token.strip_prefix("time:") {
                            result.push_str(
                                &(anchor + Duration::seconds(seconds.parse().unwrap()))
                                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                            );
                        } else {
                            panic!("unknown contract token: {token}");
                        }
                        rest = suffix;
                    }
                    result.push_str(rest);
                    assert!(!result.contains("{{") && !result.contains("}}"));
                    Value::String(result)
                }
                _ => value.clone(),
            }
        }
        Self {
            data: render(&raw, &ids, run_id, anchor),
            ids,
        }
    }

    pub fn id(&self, key: &str) -> Uuid {
        self.ids[key]
    }
}
