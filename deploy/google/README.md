# Google Cloud providers

This Terraform configuration provisions the Pub/Sub topic, BigQuery export subscription and table, scoped runtime IAM, and an optional private GCS bucket. It does not deploy the application or create service-account keys.

```sh
cd deploy/google
terraform init
terraform plan -var='project_id=YOUR_PROJECT' -var='bucket_name=YOUR_UNIQUE_BUCKET'
terraform apply -var='project_id=YOUR_PROJECT' -var='bucket_name=YOUR_UNIQUE_BUCKET'
```

Configure the runtime with `ANALYTICS_BACKEND=bigquery`, `GOOGLE_CLOUD_PROJECT`, `PUBSUB_TOPIC` from Terraform output, `BIGQUERY_DATASET=trisixt`, `BIGQUERY_TABLE=events`, and `BIGQUERY_LOCATION=US` (matching the chosen location). For storage choose `STORAGE_BACKEND=gcs` and `STORAGE_BUCKET`. Attach the created runtime service account through your deployment's workload identity, or supply Application Default Credentials. `GCS_CREDENTIALS` can point to a service-account JSON file for environments without workload identity. The storage SDK supports service-account files, authorized-user ADC and metadata credentials; impersonated-service-account ADC files are not supported by its GCS credential loader. Do not commit credentials or Terraform state.

The application publishes JSON messages through Pub/Sub. `properties` is an escaped JSON string on the wire to satisfy the BigQuery JSON-column contract. The subscription uses the table schema and rejects unknown fields rather than silently dropping them. Export is asynchronous and at least once: preserve `event_id`, deduplicate reads, and monitor subscription backlog and export errors. A Pub/Sub publish acknowledgement does not prove arrival in BigQuery. See [Google's BigQuery subscription documentation](https://docs.cloud.google.com/pubsub/docs/create-bigquery-subscription).

Real cloud verification requires a billed Google Cloud project and credentials. The local Pub/Sub emulator cannot validate BigQuery export, IAM, ADC, or actual GCS access.
