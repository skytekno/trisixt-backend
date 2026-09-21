terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google      = { source = "hashicorp/google", version = "~> 7.0" }
    google-beta = { source = "hashicorp/google-beta", version = "~> 7.0" }
  }
}

variable "project_id" { type = string }
variable "location" {
  type    = string
  default = "US"
}
variable "dataset_id" {
  type    = string
  default = "trisixt"
}
variable "bucket_name" {
  description = "Globally unique GCS bucket, or null to provision analytics only."
  type        = string
  default     = null
}
provider "google" { project = var.project_id }
provider "google-beta" { project = var.project_id }

resource "google_project_service" "apis" {
  for_each           = toset(["pubsub.googleapis.com", "bigquery.googleapis.com", "storage.googleapis.com", "iam.googleapis.com"])
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}
resource "google_project_service_identity" "pubsub" {
  provider   = google-beta
  project    = var.project_id
  service    = "pubsub.googleapis.com"
  depends_on = [google_project_service.apis]
}
resource "google_service_account" "runtime" {
  account_id   = "trisixt-runtime"
  display_name = "Trisixt runtime"
  depends_on   = [google_project_service.apis]
}
resource "google_bigquery_dataset" "analytics" {
  dataset_id                 = var.dataset_id
  location                   = var.location
  delete_contents_on_destroy = false
  depends_on                 = [google_project_service.apis]
}
resource "google_bigquery_table" "events" {
  dataset_id          = google_bigquery_dataset.analytics.dataset_id
  table_id            = "events"
  deletion_protection = true
  clustering          = ["project_id", "event_type"]
  time_partitioning {
    type  = "DAY"
    field = "occurred_at"
  }
  schema = jsonencode([
    { name = "id", type = "STRING", mode = "REQUIRED" },
    { name = "event_id", type = "STRING", mode = "REQUIRED" },
    { name = "project_id", type = "STRING", mode = "REQUIRED" },
    { name = "visitor_id", type = "STRING", mode = "REQUIRED" },
    { name = "event_type", type = "STRING", mode = "REQUIRED" },
    { name = "occurred_at", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "properties", type = "JSON", mode = "REQUIRED" }
  ])
}
resource "google_bigquery_table_iam_member" "pubsub_writer" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.analytics.dataset_id
  table_id   = google_bigquery_table.events.table_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_project_service_identity.pubsub.email}"
}
resource "google_pubsub_topic" "events" {
  name       = "trisixt-events"
  depends_on = [google_project_service.apis]
}
resource "google_pubsub_subscription" "bigquery" {
  name                       = "trisixt-events-bigquery"
  topic                      = google_pubsub_topic.events.id
  message_retention_duration = "604800s"
  expiration_policy { ttl = "" }
  bigquery_config {
    table               = "${var.project_id}.${google_bigquery_table.events.dataset_id}.${google_bigquery_table.events.table_id}"
    use_table_schema    = true
    write_metadata      = false
    drop_unknown_fields = false
  }
  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }
  depends_on = [google_bigquery_table_iam_member.pubsub_writer]
}
resource "google_pubsub_topic_iam_member" "runtime_publisher" {
  topic  = google_pubsub_topic.events.name
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:${google_service_account.runtime.email}"
}
resource "google_bigquery_dataset_iam_member" "runtime_reader" {
  dataset_id = google_bigquery_dataset.analytics.dataset_id
  role       = "roles/bigquery.dataViewer"
  member     = "serviceAccount:${google_service_account.runtime.email}"
}
resource "google_project_iam_member" "runtime_queries" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}
resource "google_storage_bucket" "assets" {
  count                       = var.bucket_name == null ? 0 : 1
  name                        = var.bucket_name
  location                    = var.location
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  depends_on                  = [google_project_service.apis]
}
resource "google_storage_bucket_iam_member" "runtime_storage" {
  count  = var.bucket_name == null ? 0 : 1
  bucket = google_storage_bucket.assets[0].name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.runtime.email}"
}
output "pubsub_topic" { value = google_pubsub_topic.events.id }
output "bigquery_dataset" { value = google_bigquery_dataset.analytics.dataset_id }
output "runtime_service_account" { value = google_service_account.runtime.email }
output "storage_bucket" { value = var.bucket_name }
