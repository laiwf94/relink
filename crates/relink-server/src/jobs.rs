//! Background jobs: CSV and NDJSON imports and exports of a workspace's
//! links, and one change applied to many links (migration 0024,
//! docs/DESIGN.md "Bulk jobs").
//!
//! - `POST /v1/jobs/import` takes the file itself as the body (`text/csv` or
//!   `application/x-ndjson`), up to `RELINK_JOB_MAX_UPLOAD_MB`. It is read
//!   as it arrives and cut into chunks of whole records ([`Splitter`]), each
//!   at most [`CHUNK_ROWS`] records, written in the same transaction as the
//!   job: an upload that fails half-way leaves nothing behind, and no more
//!   than one chunk is ever in memory. A CSV file's header names its columns
//!   ([`Column`]) and is checked before anything else is stored. Each record
//!   is checked when the job reaches it, by the same rules as
//!   `POST /v1/links`; a record that fails is reported by number and the
//!   others still go in.
//! - `POST /v1/jobs/export` writes every link of the workspace, or of one of
//!   its domains, as CSV or NDJSON (each line a link as `GET /v1/links`
//!   shows it). `GET /v1/jobs/{id}/output` streams the file once the job
//!   has succeeded.
//! - `POST /v1/jobs/patch` applies one `PATCH /v1/links/{code}` body to the
//!   links a filter picks: up to [`MAX_PATCH_CODES`] codes, or every link
//!   (on one domain).
//! - `GET /v1/jobs/{id}` is the progress: state, rows done out of the total,
//!   and the first [`MAX_STORED_ERRORS`] rows that failed;
//!   `POST /v1/jobs/{id}/cancel` stops a job between two steps.
//!
//! [`JobWorker`] claims the runnable job that ran least recently with
//! `SKIP LOCKED`, under a lease and a random token. It works through the job
//! in steps (one import chunk, or a page of links), each in one transaction
//! of the job's workspace that first locks the job row and checks the token
//! is still the job's, then does the step's work with everything a single
//! API call would write (audit entries, versions, webhook events, change
//! notifications), and moves the job's cursor and counters on. A worker
//! that dies, or loses its lease, loses at most the step it was on: the step
//! rolls back and the next worker does it again from the cursor, so every
//! record is done exactly once. After [`JobConfig::slice`] the worker lets
//! the job go so that one big job does not hold up a workspace's other
//! jobs, or other workspaces'. A step that fails is retried after a backoff;
//! [`MAX_FAILURES`] in a row fail the job.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::postgres::PgRow;
use sqlx::types::Json;
use sqlx::{Postgres, Row, Transaction};
use tokio::sync::watch;

use crate::api::{
    ApiError, CreateLink, LinkView, ListQuery, PatchLink, StrictJson, StrictQuery, decode_cursor,
    domain_param, encode_cursor, json, validate_create, validate_patch,
};
use crate::audit::{self, Action, Actor, Change, Via};
use crate::config::JobConfig;
use crate::metrics::DbOp;
use crate::server::App;
use crate::store::{Db, DbError, StoredLink, api_columns, columns, link_key};
use crate::tenant::{Allowed, Edit, LinksRead, LinksWrite, Tenant};
use crate::util::{fast_random, stopped};

/// Records per import chunk.
pub const CHUNK_ROWS: usize = 500;
/// An import chunk, or an export's output chunk, is cut once it holds this
/// many bytes.
pub const CHUNK_BYTES: usize = 1 << 20;
/// Longest record in an import, in bytes.
pub const MAX_RECORD: usize = 64 * 1024;
/// Failed rows kept per job, with their reasons; later ones are counted.
pub const MAX_STORED_ERRORS: i64 = 100;
/// Jobs a workspace may have queued or running at once.
pub const MAX_ACTIVE_JOBS: i64 = 10;
/// Most codes a bulk patch may name.
pub const MAX_PATCH_CODES: usize = 1_000;
/// Steps that may fail in a row before the job does.
pub const MAX_FAILURES: i32 = 5;
/// Links an export step reads at most.
const EXPORT_PAGE: i64 = 1_000;
/// Links a patch step changes at most.
const PATCH_PAGE: i64 = 200;
/// Longest wait for the next piece of an upload.
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Longest message kept for a row or a job.
const MAX_MESSAGE: usize = 300;
/// How often finished jobs past their retention are deleted.
const PURGE_EVERY: Duration = Duration::from_secs(60);
const PURGE_BATCH: i64 = 1_000;

/// What a job does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Import,
    Export,
    Patch,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Import => "import",
            Kind::Export => "export",
            Kind::Patch => "patch",
        }
    }

    fn parse(s: &str) -> Option<Kind> {
        [Kind::Import, Kind::Export, Kind::Patch]
            .into_iter()
            .find(|k| k.as_str() == s)
    }
}

/// The file format of an import or export.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Csv,
    Ndjson,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Csv => "csv",
            Format::Ndjson => "ndjson",
        }
    }

    fn parse(s: &str) -> Option<Format> {
        [Format::Csv, Format::Ndjson]
            .into_iter()
            .find(|f| f.as_str() == s)
    }

    fn content_type(self) -> &'static str {
        match self {
            Format::Csv => "text/csv; charset=utf-8",
            Format::Ndjson => "application/x-ndjson",
        }
    }

    /// The format a `Content-Type` names, if it names one of them.
    pub fn from_content_type(value: &str) -> Option<Format> {
        let essence = value.split(';').next()?.trim();
        if essence.eq_ignore_ascii_case("text/csv") {
            Some(Format::Csv)
        } else if [
            "application/x-ndjson",
            "application/ndjson",
            "application/jsonl",
        ]
        .iter()
        .any(|t| essence.eq_ignore_ascii_case(t))
        {
            Some(Format::Ndjson)
        } else {
            None
        }
    }
}

// Records: CSV (RFC 4180) and NDJSON.

/// Finds the end of the record that starts at `bytes[0]`, given whether
/// the scan is inside a quoted CSV field (`quoted`, carried between calls).
/// Returns the index of its `\n`. NDJSON records are lines; CSV records end
/// at a newline outside quotes, so a quoted field may hold newlines.
fn record_end(bytes: &[u8], csv: bool, quoted: &mut bool) -> Option<usize> {
    if !csv {
        return bytes.iter().position(|&b| b == b'\n');
    }
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            // A doubled quote inside a quoted field flips twice.
            b'"' => *quoted = !*quoted,
            b'\n' if !*quoted => return Some(i),
            _ => {}
        }
    }
    None
}

/// A record without its line ending, or `None` for a blank one.
fn trim_record(mut r: &[u8]) -> Option<&[u8]> {
    if let [rest @ .., b'\r'] = r {
        r = rest;
    }
    (!r.iter().all(u8::is_ascii_whitespace)).then_some(r)
}

/// Why an upload was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SplitError {
    /// Record `n` is longer than [`MAX_RECORD`].
    TooLong(i64),
    /// The file ends inside a quoted field.
    Unterminated,
}

impl fmt::Display for SplitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SplitError::TooLong(0) => write!(f, "the header is longer than {MAX_RECORD} bytes"),
            SplitError::TooLong(n) => write!(f, "row {n} is longer than {MAX_RECORD} bytes"),
            SplitError::Unterminated => f.write_str("the file ends inside a quoted field"),
        }
    }
}

/// A chunk of whole records, ready to store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk {
    /// The number of its first record (1 is the first after a header).
    pub first_row: i64,
    pub rows: usize,
    /// The records, each followed by `\n`.
    pub data: Vec<u8>,
}

/// Cuts an upload, piece by piece, into records and the records into
/// [`Chunk`]s. A UTF-8 byte order mark at the start and blank records are
/// dropped; with `header`, the first record is kept apart as the header.
pub struct Splitter {
    csv: bool,
    header: Option<Option<Vec<u8>>>,
    quoted: bool,
    /// The record being read, up to where it has been scanned.
    partial: Vec<u8>,
    started: bool,
    rows: i64,
    current: Chunk,
    ready: Vec<Chunk>,
}

impl Splitter {
    pub fn new(format: Format) -> Splitter {
        let csv = format == Format::Csv;
        Splitter {
            csv,
            header: csv.then_some(None),
            quoted: false,
            partial: Vec::new(),
            started: false,
            rows: 0,
            current: Chunk {
                first_row: 1,
                rows: 0,
                data: Vec::new(),
            },
            ready: Vec::new(),
        }
    }

    /// Takes the next piece of the upload.
    pub fn push(&mut self, mut data: &[u8]) -> Result<(), SplitError> {
        while !data.is_empty() {
            match record_end(data, self.csv, &mut self.quoted) {
                Some(i) => {
                    self.partial.extend_from_slice(&data[..i]);
                    data = &data[i + 1..];
                    self.check_length()?;
                    let record = std::mem::take(&mut self.partial);
                    self.record(&record);
                    // The buffer's capacity is reused for the next record.
                    self.partial = record;
                    self.partial.clear();
                }
                None => {
                    self.partial.extend_from_slice(data);
                    self.check_length()?;
                    data = &[];
                }
            }
        }
        Ok(())
    }

    /// Ends the upload: the last record may lack its newline.
    pub fn finish(&mut self) -> Result<(), SplitError> {
        if self.csv && self.quoted {
            return Err(SplitError::Unterminated);
        }
        if !self.partial.is_empty() {
            let record = std::mem::take(&mut self.partial);
            self.record(&record);
        }
        if self.current.rows > 0 {
            let next = self.rows + 1;
            self.ready.push(std::mem::replace(
                &mut self.current,
                Chunk {
                    first_row: next,
                    rows: 0,
                    data: Vec::new(),
                },
            ));
        }
        Ok(())
    }

    fn check_length(&self) -> Result<(), SplitError> {
        if self.partial.len() > MAX_RECORD + 1 {
            let n = if self.header == Some(None) {
                0
            } else {
                self.rows + 1
            };
            return Err(SplitError::TooLong(n));
        }
        Ok(())
    }

    fn record(&mut self, mut record: &[u8]) {
        if !self.started {
            self.started = true;
            if let Some(rest) = record.strip_prefix(b"\xef\xbb\xbf") {
                record = rest;
            }
        }
        let Some(record) = trim_record(record) else {
            return;
        };
        if self.header == Some(None) {
            self.header = Some(Some(record.to_vec()));
            return;
        }
        self.rows += 1;
        self.current.data.extend_from_slice(record);
        self.current.data.push(b'\n');
        self.current.rows += 1;
        if self.current.rows >= CHUNK_ROWS || self.current.data.len() >= CHUNK_BYTES {
            let next = self.rows + 1;
            self.ready.push(std::mem::replace(
                &mut self.current,
                Chunk {
                    first_row: next,
                    rows: 0,
                    data: Vec::new(),
                },
            ));
        }
    }

    /// The CSV header, once it has been read.
    pub fn header(&self) -> Option<&[u8]> {
        self.header.as_ref()?.as_deref()
    }

    /// Records so far, the header not counted.
    pub fn rows(&self) -> i64 {
        self.rows
    }

    /// The chunks completed since the last call.
    pub fn take_ready(&mut self) -> Vec<Chunk> {
        std::mem::take(&mut self.ready)
    }
}

/// The records of a stored chunk, in order.
pub fn chunk_records(data: &[u8], format: Format) -> Vec<&[u8]> {
    let csv = format == Format::Csv;
    let mut out = Vec::new();
    let mut rest = data;
    let mut quoted = false;
    while !rest.is_empty() {
        match record_end(rest, csv, &mut quoted) {
            Some(i) => {
                out.push(&rest[..i]);
                rest = &rest[i + 1..];
            }
            None => {
                out.push(rest);
                break;
            }
        }
    }
    out
}

/// Splits one CSV record into its fields (RFC 4180: fields in double
/// quotes may hold commas, newlines and doubled quotes).
pub fn parse_csv_record(record: &[u8]) -> Result<Vec<String>, String> {
    let text = std::str::from_utf8(record).map_err(|_| "the row is not valid UTF-8".to_owned())?;
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut chars = text.chars().peekable();
    loop {
        if chars.peek() == Some(&'"') {
            chars.next();
            loop {
                match chars.next() {
                    Some('"') if chars.peek() == Some(&'"') => {
                        chars.next();
                        field.push('"');
                    }
                    Some('"') => break,
                    Some(c) => field.push(c),
                    None => return Err("a quoted field is not closed".into()),
                }
            }
            match chars.next() {
                None => {
                    fields.push(field);
                    return Ok(fields);
                }
                Some(',') => fields.push(std::mem::take(&mut field)),
                Some(_) => return Err("a quoted field must be followed by a comma".into()),
            }
        } else {
            loop {
                match chars.next() {
                    None => {
                        fields.push(field);
                        return Ok(fields);
                    }
                    Some(',') => {
                        fields.push(std::mem::take(&mut field));
                        break;
                    }
                    Some('"') => return Err("a quote inside a field that is not quoted".into()),
                    Some(c) => field.push(c),
                }
            }
        }
    }
}

/// Appends `field` to a CSV line, quoted when it has to be.
pub fn write_csv_field(out: &mut Vec<u8>, field: &str) {
    if field.contains([',', '"', '\n', '\r']) {
        out.push(b'"');
        out.extend_from_slice(field.replace('"', "\"\"").as_bytes());
        out.push(b'"');
    } else {
        out.extend_from_slice(field.as_bytes());
    }
}

fn write_csv_line<S: AsRef<str>>(out: &mut Vec<u8>, fields: &[S]) {
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        write_csv_field(out, f.as_ref());
    }
    out.push(b'\n');
}

// Columns.

/// A CSV column an import understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Column {
    /// The alias; a random code when empty.
    Code,
    Url,
    Domain,
    RedirectType,
    ExpiresAt,
    MaxClicks,
    Enabled,
    HealthCheck,
    FallbackUrl,
    ConversionWindowDays,
    /// A column of an export that an import has no use for.
    Ignored,
}

/// Columns an import takes, in the order an export writes them. `url` is
/// the only one a file must have.
pub const IMPORT_COLUMNS: [(&str, Column); 10] = [
    ("code", Column::Code),
    ("domain", Column::Domain),
    ("url", Column::Url),
    ("redirect_type", Column::RedirectType),
    ("expires_at", Column::ExpiresAt),
    ("max_clicks", Column::MaxClicks),
    ("enabled", Column::Enabled),
    ("health_check", Column::HealthCheck),
    ("fallback_url", Column::FallbackUrl),
    ("conversion_window_days", Column::ConversionWindowDays),
];

/// Columns an export writes that an import skips.
pub const IGNORED_COLUMNS: [&str; 4] = ["short_url", "version", "created_at", "updated_at"];

/// The columns an export writes.
pub const EXPORT_COLUMNS: [&str; 14] = [
    "code",
    "domain",
    "short_url",
    "url",
    "redirect_type",
    "expires_at",
    "max_clicks",
    "enabled",
    "health_check",
    "fallback_url",
    "conversion_window_days",
    "version",
    "created_at",
    "updated_at",
];

/// Checks a CSV header: known names, each once, `url` among them.
pub fn parse_header(record: &[u8]) -> Result<Vec<String>, String> {
    let names = parse_csv_record(record).map_err(|e| format!("the header: {e}"))?;
    let mut seen: Vec<&str> = Vec::with_capacity(names.len());
    for name in &names {
        let name = name.trim();
        if column(name).is_none() {
            let known: Vec<&str> = IMPORT_COLUMNS.iter().map(|(n, _)| *n).collect();
            return Err(format!(
                "the header names an unknown column {name:?}; the columns are {}",
                known.join(", ")
            ));
        }
        if seen.contains(&name) {
            return Err(format!("the header names {name:?} twice"));
        }
        seen.push(name);
    }
    if !seen.contains(&"url") {
        return Err("the header has no url column".into());
    }
    Ok(seen.into_iter().map(str::to_owned).collect())
}

fn column(name: &str) -> Option<Column> {
    IMPORT_COLUMNS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, c)| *c)
        .or_else(|| IGNORED_COLUMNS.contains(&name).then_some(Column::Ignored))
}

/// One CSV record as the create request it stands for. Empty fields are
/// left out.
pub fn csv_row(columns: &[String], record: &[u8]) -> Result<CreateLink, String> {
    let fields = parse_csv_record(record)?;
    if fields.len() != columns.len() {
        return Err(format!(
            "the row has {} fields; the header has {}",
            fields.len(),
            columns.len()
        ));
    }
    let mut req = CreateLink::default();
    for (name, value) in columns.iter().zip(fields) {
        let v = value.trim();
        if v.is_empty() {
            continue;
        }
        let number = |what: &str| format!("{name}: must be {what}");
        let boolean = || match v {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(format!("{name}: must be true or false")),
        };
        match column(name).unwrap_or(Column::Ignored) {
            Column::Code => req.alias = Some(v.to_owned()),
            Column::Url => req.url = Some(v.to_owned()),
            Column::Domain => req.domain = Some(v.to_owned()),
            Column::RedirectType => {
                req.redirect_type = Some(v.parse().map_err(|_| number("301, 302, 307 or 308"))?)
            }
            Column::ExpiresAt => {
                req.expires_at = Some(
                    DateTime::parse_from_rfc3339(v)
                        .map_err(|_| format!("{name}: must be an RFC 3339 time"))?
                        .with_timezone(&Utc),
                )
            }
            Column::MaxClicks => req.max_clicks = Some(v.parse().map_err(|_| number("a number"))?),
            Column::Enabled => req.enabled = Some(boolean()?),
            Column::HealthCheck => req.health_check = Some(boolean()?),
            Column::FallbackUrl => req.fallback_url = Some(v.to_owned()),
            Column::ConversionWindowDays => {
                req.conversion_window_days = Some(v.parse().map_err(|_| number("a number"))?)
            }
            Column::Ignored => {}
        }
    }
    Ok(req)
}

/// One NDJSON line as a create request: the body `POST /v1/links` takes.
pub fn ndjson_row(record: &[u8]) -> Result<CreateLink, String> {
    serde_json::from_slice(record).map_err(|e| format!("invalid JSON: {e}"))
}

/// A link as one CSV line of an export ([`EXPORT_COLUMNS`]). A link with
/// several destinations shows its first; NDJSON keeps them all.
pub fn export_csv_line(out: &mut Vec<u8>, link: &StoredLink, base_url: &str) {
    let view = LinkView::new(link, base_url);
    let opt = |v: Option<String>| v.unwrap_or_default();
    write_csv_line(
        out,
        &[
            view.code,
            opt(view.domain),
            view.short_url,
            view.destinations
                .first()
                .map(|d| d.url.clone())
                .unwrap_or_default(),
            view.redirect_type.to_string(),
            opt(view.expires_at.map(|t| t.to_rfc3339())),
            opt(view.max_clicks.map(|m| m.to_string())),
            view.enabled.to_string(),
            view.health_check.to_string(),
            opt(view.fallback_url),
            opt(view.conversion_window_days.map(|d| d.to_string())),
            view.version.to_string(),
            view.created_at.to_rfc3339(),
            view.updated_at.to_rfc3339(),
        ],
    );
}

// Jobs in the database.

/// A job as the API shows it.
#[derive(Clone, Debug, Serialize)]
pub struct JobView {
    pub id: i64,
    pub kind: Kind,
    pub format: Option<Format>,
    pub state: String,
    /// Rows (links) the job covers, and how many it has done: those that
    /// succeeded plus those that failed.
    pub total: i64,
    pub processed: i64,
    pub succeeded: i64,
    pub failed: i64,
    /// `processed / total`, from 0 to 1.
    pub progress: f64,
    /// Why the job failed, when it did.
    pub error: Option<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    /// Where a finished export's file is.
    pub output_url: Option<String>,
    /// The first rows that failed, on `GET /v1/jobs/{id}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<RowError>>,
}

/// A row a job could not do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RowError {
    /// The record number: 1 is the first after a CSV header, or a patch's
    /// first code.
    pub row: i64,
    /// The API error code the same request would get.
    pub code: String,
    pub message: String,
}

macro_rules! job_columns {
    () => {
        "id, kind, format, state, total, processed, succeeded, failed, error, created_by, \
         created_at, started_at, finished_at"
    };
}

fn row_to_view(r: &PgRow) -> Result<JobView, sqlx::Error> {
    let kind: String = r.try_get("kind")?;
    let format: Option<String> = r.try_get("format")?;
    let state: String = r.try_get("state")?;
    let total: i64 = r.try_get("total")?;
    let processed: i64 = r.try_get("processed")?;
    let id: i64 = r.try_get("id")?;
    let kind = Kind::parse(&kind).ok_or_else(|| sqlx::Error::Decode("unknown job kind".into()))?;
    let progress = if total > 0 {
        ((processed as f64 / total as f64).min(1.0) * 10_000.0).floor() / 10_000.0
    } else if state == "succeeded" {
        1.0
    } else {
        0.0
    };
    Ok(JobView {
        id,
        kind,
        format: format.as_deref().and_then(Format::parse),
        output_url: (kind == Kind::Export && state == "succeeded")
            .then(|| format!("/v1/jobs/{id}/output")),
        state,
        total,
        processed,
        succeeded: r.try_get("succeeded")?,
        failed: r.try_get("failed")?,
        progress,
        error: r.try_get("error")?,
        created_by: r.try_get("created_by")?,
        created_at: r.try_get("created_at")?,
        started_at: r.try_get("started_at")?,
        finished_at: r.try_get("finished_at")?,
        errors: None,
    })
}

fn clip(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Writes up to the stored limit of `errors`, given that the job already
/// has `failed` failed rows.
async fn store_errors(
    tx: &mut Transaction<'static, Postgres>,
    job: i64,
    failed: i64,
    errors: &[RowError],
) -> Result<(), sqlx::Error> {
    let room = (MAX_STORED_ERRORS - failed).max(0) as usize;
    let kept = &errors[..errors.len().min(room)];
    if kept.is_empty() {
        return Ok(());
    }
    let rows: Vec<i64> = kept.iter().map(|e| e.row).collect();
    let codes: Vec<&str> = kept.iter().map(|e| e.code.as_str()).collect();
    let messages: Vec<String> = kept.iter().map(|e| clip(&e.message, MAX_MESSAGE)).collect();
    sqlx::query(
        "INSERT INTO job_errors (job_id, row, code, message) \
         SELECT $1, * FROM unnest($2::bigint[], $3::text[], $4::text[]) \
         ON CONFLICT DO NOTHING",
    )
    .bind(job)
    .bind(rows)
    .bind(codes)
    .bind(messages)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Refuses a new job when the workspace already has [`MAX_ACTIVE_JOBS`]
/// others queued or running. The workspace row is locked, so concurrent
/// requests cannot both take the last slot; it is taken last, just before
/// the commit, so an upload does not hold it.
async fn admit(
    tx: &mut Transaction<'static, Postgres>,
    job: i64,
) -> Result<Option<DbError>, sqlx::Error> {
    sqlx::query("SELECT 1 FROM workspaces FOR NO KEY UPDATE")
        .execute(&mut **tx)
        .await?;
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM jobs WHERE state IN ('queued', 'running') AND id <> $1",
    )
    .bind(job)
    .fetch_one(&mut **tx)
    .await?;
    Ok((n >= MAX_ACTIVE_JOBS).then(|| {
        DbError::Precondition(format!(
            "a workspace can have at most {MAX_ACTIVE_JOBS} jobs queued or running; \
             wait for one to finish or cancel one"
        ))
    }))
}

async fn record_create(
    tx: &mut Transaction<'static, Postgres>,
    t: &Tenant<'_>,
    job: &JobView,
) -> Result<(), sqlx::Error> {
    let change = Change {
        workspace_id: t.workspace_id(),
        action: Action::JobCreate,
        target: format!("job:{}", job.id),
        before: None,
        after: Some(json!({
            "kind": job.kind,
            "format": job.format,
            "total": job.total,
        })),
    };
    audit::record(tx, t.actor(), change).await
}

async fn insert_job(
    tx: &mut Transaction<'static, Postgres>,
    t: &Tenant<'_>,
    kind: Kind,
    format: Option<Format>,
    params: &Value,
) -> Result<i64, sqlx::Error> {
    let actor = t.actor();
    sqlx::query_scalar(
        "INSERT INTO jobs (kind, format, params, created_by, via) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(kind.as_str())
    .bind(format.map(Format::as_str))
    .bind(Json(params))
    .bind(actor.member.as_deref().unwrap_or("system"))
    .bind(actor.via.to_string())
    .fetch_one(&mut **tx)
    .await
}

async fn view_in(tx: &mut Transaction<'static, Postgres>, id: i64) -> Result<JobView, sqlx::Error> {
    let row = sqlx::query(concat!(
        "SELECT ",
        job_columns!(),
        " FROM jobs WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(&mut **tx)
    .await?;
    row_to_view(&row)
}

/// Where a bulk patch applies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PatchTarget {
    /// The codes, or every link when `None`.
    codes: Option<Vec<String>>,
    /// Only links on this domain (0 for the default domain); any domain
    /// when `None`.
    domain_id: Option<i64>,
    /// The newest link when the job was made: later links are not changed.
    max_id: i64,
}

/// What an export covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ExportTarget {
    domain_id: Option<i64>,
    max_id: i64,
}

/// The ID of `host`, a domain of this workspace, or 0 for `None` (the
/// default domain).
async fn domain_id(
    tx: &mut Transaction<'static, Postgres>,
    host: Option<&str>,
) -> Result<Result<i64, DbError>, sqlx::Error> {
    let Some(host) = host else { return Ok(Ok(0)) };
    let id: Option<i64> = sqlx::query_scalar("SELECT id FROM domains WHERE hostname = $1")
        .bind(host)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(id.ok_or_else(|| {
        DbError::Invalid(format!("domain: {host} is not a domain of this workspace"))
    }))
}

impl Tenant<'_> {
    /// Stores an import: the job and its chunks, read from `body` as it
    /// arrives, in one transaction.
    pub async fn create_import(
        &self,
        format: Format,
        body: Body,
        max_upload: u64,
    ) -> Result<JobView, ApiError> {
        let db = |e: sqlx::Error| ApiError::from(DbError::from(e));
        let mut tx = self.begin().await.map_err(db)?;
        let id = insert_job(&mut tx, self, Kind::Import, Some(format), &json!({}))
            .await
            .map_err(db)?;
        let mut split = Splitter::new(format);
        let mut columns: Option<Vec<String>> = None;
        let mut seq = 0i32;
        let mut bytes = 0u64;
        let mut stream = body.into_data_stream();
        loop {
            let piece: Bytes = match tokio::time::timeout(READ_TIMEOUT, stream.next()).await {
                Err(_) => return Err(ApiError::invalid("the upload stalled")),
                Ok(None) => break,
                Ok(Some(Err(_))) => {
                    return Err(ApiError::invalid("could not read the request body"));
                }
                Ok(Some(Ok(b))) => b,
            };
            bytes += piece.len() as u64;
            if bytes > max_upload {
                return Err(ApiError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "payload_too_large",
                    format!("an import is at most {} MB", max_upload >> 20),
                ));
            }
            split
                .push(&piece)
                .map_err(|e| ApiError::invalid(e.to_string()))?;
            if columns.is_none()
                && let Some(h) = split.header()
            {
                columns = Some(parse_header(h).map_err(ApiError::invalid)?);
            }
            for chunk in split.take_ready() {
                insert_chunk(&mut tx, id, "input", seq, &chunk)
                    .await
                    .map_err(db)?;
                seq += 1;
            }
        }
        split
            .finish()
            .map_err(|e| ApiError::invalid(e.to_string()))?;
        if format == Format::Csv && columns.is_none() {
            return Err(ApiError::invalid("the file has no header"));
        }
        for chunk in split.take_ready() {
            insert_chunk(&mut tx, id, "input", seq, &chunk)
                .await
                .map_err(db)?;
            seq += 1;
        }
        if split.rows() == 0 {
            return Err(ApiError::invalid("the file has no rows"));
        }
        sqlx::query("UPDATE jobs SET total = $2, params = $3 WHERE id = $1")
            .bind(id)
            .bind(split.rows())
            .bind(Json(json!({ "columns": columns })))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        if let Some(e) = admit(&mut tx, id).await.map_err(db)? {
            return Err(e.into());
        }
        let view = view_in(&mut tx, id).await.map_err(db)?;
        record_create(&mut tx, self, &view).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(view)
    }

    /// Queues an export of the workspace's links, or of those on `domain`.
    pub async fn create_export(
        &self,
        format: Format,
        domain: Option<&str>,
    ) -> Result<JobView, DbError> {
        self.db()
            .timed(async {
                let mut tx = self.begin().await?;
                let domain_id = match domain {
                    None => None,
                    Some(_) => match domain_id(&mut tx, domain).await? {
                        Ok(id) => Some(id),
                        Err(e) => return Ok(Err(e)),
                    },
                };
                let (total, max_id): (i64, Option<i64>) = sqlx::query_as(
                    "SELECT count(*), max(id) FROM links \
                      WHERE $1::bigint IS NULL OR COALESCE(domain_id, 0) = $1",
                )
                .bind(domain_id)
                .fetch_one(&mut *tx)
                .await?;
                let target = ExportTarget {
                    domain_id,
                    max_id: max_id.unwrap_or(0),
                };
                let params = serde_json::to_value(&target).unwrap_or_default();
                let id = insert_job(&mut tx, self, Kind::Export, Some(format), &params).await?;
                sqlx::query("UPDATE jobs SET total = $2 WHERE id = $1")
                    .bind(id)
                    .bind(total)
                    .execute(&mut *tx)
                    .await?;
                if let Some(e) = admit(&mut tx, id).await? {
                    return Ok(Err(e));
                }
                let view = view_in(&mut tx, id).await?;
                record_create(&mut tx, self, &view).await?;
                tx.commit().await?;
                Ok(Ok(view))
            })
            .await?
    }

    /// Queues `patch` (a `PATCH /v1/links/{code}` body, already checked)
    /// for `codes` on `domain`, or for every link (on `domain`). Codes the
    /// workspace does not have are reported as failed rows at once.
    pub async fn create_patch(
        &self,
        codes: Option<Vec<String>>,
        domain: Option<&str>,
        patch: &Value,
    ) -> Result<JobView, DbError> {
        self.db()
            .timed(async {
                let mut tx = self.begin().await?;
                let domain_id = match (&codes, domain) {
                    (None, None) => None,
                    _ => match domain_id(&mut tx, domain).await? {
                        Ok(id) => Some(id),
                        Err(e) => return Ok(Err(e)),
                    },
                };
                let max_id: i64 = sqlx::query_scalar("SELECT COALESCE(max(id), 0) FROM links")
                    .fetch_one(&mut *tx)
                    .await?;
                let (total, missing) = match &codes {
                    None => {
                        let n: i64 = sqlx::query_scalar(
                            "SELECT count(*) FROM links \
                              WHERE $1::bigint IS NULL OR COALESCE(domain_id, 0) = $1",
                        )
                        .bind(domain_id)
                        .fetch_one(&mut *tx)
                        .await?;
                        (n, Vec::new())
                    }
                    Some(codes) => {
                        let found: Vec<String> = sqlx::query_scalar(
                            "SELECT code FROM links WHERE code = ANY ($1) \
                               AND COALESCE(domain_id, 0) = $2",
                        )
                        .bind(codes)
                        .bind(domain_id.unwrap_or(0))
                        .fetch_all(&mut *tx)
                        .await?;
                        let missing: Vec<RowError> = codes
                            .iter()
                            .enumerate()
                            .filter(|(_, c)| !found.contains(c))
                            .map(|(i, c)| RowError {
                                row: i as i64 + 1,
                                code: "not_found".into(),
                                message: format!("no link {c}"),
                            })
                            .collect();
                        (codes.len() as i64, missing)
                    }
                };
                let target = PatchTarget {
                    codes,
                    domain_id,
                    max_id,
                };
                let params = json!({ "target": target, "patch": patch });
                let id = insert_job(&mut tx, self, Kind::Patch, None, &params).await?;
                let n = missing.len() as i64;
                sqlx::query(
                    "UPDATE jobs SET total = $2, processed = $3, failed = $3 WHERE id = $1",
                )
                .bind(id)
                .bind(total)
                .bind(n)
                .execute(&mut *tx)
                .await?;
                store_errors(&mut tx, id, 0, &missing).await?;
                if let Some(e) = admit(&mut tx, id).await? {
                    return Ok(Err(e));
                }
                let view = view_in(&mut tx, id).await?;
                record_create(&mut tx, self, &view).await?;
                tx.commit().await?;
                Ok(Ok(view))
            })
            .await?
    }

    /// The workspace's jobs, newest first, after the cursor (a job ID).
    pub async fn jobs(&self, before: Option<i64>, limit: i64) -> Result<Vec<JobView>, DbError> {
        let rows = self
            .db()
            .timed(async {
                let mut tx = self.begin().await?;
                let rows = sqlx::query(concat!(
                    "SELECT ",
                    job_columns!(),
                    " FROM jobs WHERE ($1::bigint IS NULL OR id < $1) ORDER BY id DESC LIMIT $2"
                ))
                .bind(before)
                .bind(limit)
                .fetch_all(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(rows)
            })
            .await?;
        rows.iter()
            .map(row_to_view)
            .collect::<Result<_, _>>()
            .map_err(DbError::from)
    }

    /// One job with its stored failed rows.
    pub async fn job(&self, id: i64) -> Result<JobView, DbError> {
        self.db()
            .timed(async {
                let mut tx = self.begin().await?;
                let row = sqlx::query(concat!(
                    "SELECT ",
                    job_columns!(),
                    " FROM jobs WHERE id = $1"
                ))
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(sqlx::Error::RowNotFound)?;
                let mut view = row_to_view(&row)?;
                let errors = sqlx::query(
                    "SELECT row, code, message FROM job_errors WHERE job_id = $1 ORDER BY row",
                )
                .bind(id)
                .fetch_all(&mut *tx)
                .await?;
                tx.commit().await?;
                view.errors = Some(
                    errors
                        .iter()
                        .map(|r| {
                            Ok(RowError {
                                row: r.try_get("row")?,
                                code: r.try_get("code")?,
                                message: r.try_get("message")?,
                            })
                        })
                        .collect::<Result<_, sqlx::Error>>()?,
                );
                Ok(view)
            })
            .await
    }

    /// Cancels a queued or running job. Steps already done stay done.
    pub async fn cancel_job(&self, id: i64) -> Result<JobView, DbError> {
        self.db()
            .timed(async {
                let mut tx = self.begin().await?;
                let state: Option<String> =
                    sqlx::query_scalar("SELECT state FROM jobs WHERE id = $1 FOR UPDATE")
                        .bind(id)
                        .fetch_optional(&mut *tx)
                        .await?;
                match state.as_deref() {
                    None => return Err(sqlx::Error::RowNotFound),
                    Some("queued" | "running") => {}
                    Some(s) => {
                        return Ok(Err(DbError::Precondition(format!("the job has {s}"))));
                    }
                }
                sqlx::query(
                    "UPDATE jobs SET state = 'cancelled', finished_at = now(), lease_token = NULL \
                     WHERE id = $1",
                )
                .bind(id)
                .execute(&mut *tx)
                .await?;
                sqlx::query("DELETE FROM job_chunks WHERE job_id = $1 AND part = 'input'")
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                let view = view_in(&mut tx, id).await?;
                let change = Change {
                    workspace_id: self.workspace_id(),
                    action: Action::JobCancel,
                    target: format!("job:{id}"),
                    before: None,
                    after: Some(json!({"processed": view.processed, "total": view.total})),
                };
                audit::record(&mut tx, self.actor(), change).await?;
                tx.commit().await?;
                Ok(Ok(view))
            })
            .await?
    }

    /// Output chunk `seq` of export `id`, if there is one.
    pub async fn output_chunk(&self, id: i64, seq: i32) -> Result<Option<Vec<u8>>, DbError> {
        self.db()
            .timed(async {
                let mut tx = self.begin().await?;
                let data: Option<Vec<u8>> = sqlx::query_scalar(
                    "SELECT data FROM job_chunks WHERE job_id = $1 AND part = 'output' AND seq = $2",
                )
                .bind(id)
                .bind(seq)
                .fetch_optional(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(data)
            })
            .await
    }
}

async fn insert_chunk(
    tx: &mut Transaction<'static, Postgres>,
    job: i64,
    part: &str,
    seq: i32,
    chunk: &Chunk,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO job_chunks (job_id, part, seq, first_row, rows, data) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(job)
    .bind(part)
    .bind(seq)
    .bind(chunk.first_row)
    .bind(chunk.rows as i32)
    .bind(&chunk.data)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

// The worker.

/// A job a worker holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claim {
    pub id: i64,
    pub workspace_id: i64,
    pub token: i64,
}

/// What one step did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Rows done; the job goes on.
    Progress(usize),
    /// The job finished, in this state.
    Finished(&'static str),
    /// The job is no longer this worker's: cancelled, or taken over after
    /// the lease ran out.
    Lost,
}

/// Why a step failed.
#[derive(Debug)]
enum StepError {
    /// Worth trying again.
    Retry(DbError),
    /// The job cannot go on, for this reason.
    Fatal(String),
}

impl From<sqlx::Error> for StepError {
    fn from(e: sqlx::Error) -> StepError {
        StepError::Retry(DbError::from(e))
    }
}

/// The job row as a step reads it, locked.
struct Locked {
    kind: Kind,
    format: Option<Format>,
    params: Value,
    cursor: i64,
    output_chunks: i32,
    failed: i64,
}

impl Db {
    /// Claims the runnable job that ran least recently, for `lease`, under
    /// a fresh token.
    pub async fn claim_job(&self, lease: Duration) -> Result<Option<Claim>, DbError> {
        let token = (fast_random() >> 1) as i64;
        let row: Option<(i64, i64)> = self
            .timed(
                sqlx::query_as(
                    "UPDATE jobs SET state = 'running', started_at = COALESCE(started_at, now()), \
                            last_run_at = clock_timestamp(), \
                            lease_until = now() + make_interval(secs => $1), lease_token = $2 \
                      WHERE id = (SELECT id FROM jobs \
                                   WHERE state IN ('queued', 'running') AND lease_until <= now() \
                                   ORDER BY last_run_at NULLS FIRST, id LIMIT 1 \
                                     FOR UPDATE SKIP LOCKED) \
                  RETURNING id, workspace_id",
                )
                .bind(lease.as_secs_f64())
                .bind(token)
                .fetch_optional(self.pool()),
            )
            .await?;
        Ok(row.map(|(id, workspace_id)| Claim {
            id,
            workspace_id,
            token,
        }))
    }

    /// Lets a claimed job go, so any worker may take it at once.
    pub async fn release_job(&self, claim: Claim) -> Result<(), DbError> {
        self.timed(
            sqlx::query(
                "UPDATE jobs SET lease_until = now() \
                  WHERE id = $1 AND lease_token = $2 AND state = 'running'",
            )
            .bind(claim.id)
            .bind(claim.token)
            .execute(self.pool()),
        )
        .await
        .map(|_| ())
    }

    /// Counts a failed step: the job waits `retry_in`, or fails with
    /// `error` once it has failed [`MAX_FAILURES`] steps in a row (or at
    /// once with `fatal`). Returns whether the job failed.
    async fn job_step_failed(
        &self,
        claim: Claim,
        error: &str,
        fatal: bool,
        retry_in: Duration,
    ) -> Result<bool, DbError> {
        let state: Option<String> = self
            .timed(
                sqlx::query_scalar(
                    "UPDATE jobs SET failures = failures + 1, \
                            lease_until = now() + make_interval(secs => $4), \
                            state = CASE WHEN $3 OR failures + 1 >= $5 THEN 'failed' ELSE state END, \
                            error = CASE WHEN $3 OR failures + 1 >= $5 THEN $6 ELSE error END, \
                            finished_at = CASE WHEN $3 OR failures + 1 >= $5 THEN now() END, \
                            lease_token = CASE WHEN $3 OR failures + 1 >= $5 THEN NULL \
                                               ELSE lease_token END \
                      WHERE id = $1 AND lease_token = $2 AND state = 'running' \
                  RETURNING state",
                )
                .bind(claim.id)
                .bind(claim.token)
                .bind(fatal)
                .bind(retry_in.as_secs_f64())
                .bind(MAX_FAILURES)
                .bind(clip(error, MAX_MESSAGE))
                .fetch_optional(self.pool()),
            )
            .await?;
        if state.as_deref() == Some("failed") {
            // An import's input is no use any more.
            self.timed(
                sqlx::query("DELETE FROM job_chunks WHERE job_id = $1 AND part = 'input'")
                    .bind(claim.id)
                    .execute(self.pool()),
            )
            .await?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Deletes up to `limit` jobs that finished more than `days` days ago,
    /// with their chunks and errors. Returns how many.
    pub async fn purge_jobs(&self, days: u32, limit: i64) -> Result<u64, DbError> {
        self.timed(
            sqlx::query(
                "DELETE FROM jobs WHERE id = ANY (ARRAY( \
                    SELECT id FROM jobs WHERE finished_at < now() - make_interval(days => $1) \
                     LIMIT $2))",
            )
            .bind(days as i32)
            .bind(limit)
            .execute(self.pool()),
        )
        .await
        .map(|r| r.rows_affected())
    }
}

/// Runs imports, exports and patches.
pub struct JobWorker {
    app: Arc<App>,
    cfg: JobConfig,
}

impl JobWorker {
    pub fn new(app: Arc<App>) -> JobWorker {
        let cfg = app.cfg.jobs;
        JobWorker { app, cfg }
    }

    /// Claims one job and works on it for up to a slice. Returns whether
    /// there was a job.
    pub async fn round(&self) -> bool {
        let claim = match self.app.db.claim_job(self.cfg.lease).await {
            Ok(Some(c)) => c,
            Ok(None) => return false,
            Err(e) => {
                self.app.metrics.db_error(DbOp::Job);
                tracing::warn!(error = %e, "could not claim a job");
                return false;
            }
        };
        let started = Instant::now();
        loop {
            match self.step_bounded(claim).await {
                Ok(Step::Progress(n)) => {
                    self.app.metrics.job_rows.add(n as u64);
                    if started.elapsed() < self.cfg.slice {
                        continue;
                    }
                    if let Err(e) = self.app.db.release_job(claim).await {
                        // The lease runs out by itself.
                        self.app.metrics.db_error(DbOp::Job);
                        tracing::warn!(error = %e, job = claim.id, "could not release a job");
                    }
                }
                Ok(Step::Finished(state)) => {
                    if state == "succeeded" {
                        self.app.metrics.jobs_succeeded.inc();
                    }
                    tracing::info!(job = claim.id, state, "job finished");
                }
                Ok(Step::Lost) => {
                    tracing::debug!(job = claim.id, "job cancelled or taken over");
                }
                Err(e) => {
                    let (message, fatal) = match &e {
                        StepError::Retry(e) => (e.to_string(), false),
                        StepError::Fatal(m) => (m.clone(), true),
                    };
                    let retry_in = self.cfg.poll.max(Duration::from_millis(100));
                    match self
                        .app
                        .db
                        .job_step_failed(claim, &message, fatal, retry_in)
                        .await
                    {
                        Ok(true) => {
                            self.app.metrics.jobs_failed.inc();
                            tracing::info!(job = claim.id, error = %message, "job failed");
                        }
                        Ok(false) => {
                            tracing::warn!(job = claim.id, error = %message, "job step failed; it will be retried");
                        }
                        Err(e) => {
                            self.app.metrics.db_error(DbOp::Job);
                            tracing::warn!(error = %e, job = claim.id, "could not record a failed job step");
                        }
                    }
                }
            }
            return true;
        }
    }

    /// One step of the claimed job, bounded by half the lease.
    pub async fn step_once(&self, claim: Claim) -> Result<Step, StepErrorView> {
        self.step_bounded(claim).await.map_err(StepErrorView)
    }

    async fn step_bounded(&self, claim: Claim) -> Result<Step, StepError> {
        match tokio::time::timeout(self.cfg.lease / 2, self.step(claim)).await {
            Ok(r) => r,
            Err(_) => Err(StepError::Retry(DbError::Unavailable(
                "the step took longer than half the lease".into(),
            ))),
        }
    }

    async fn step(&self, claim: Claim) -> Result<Step, StepError> {
        let db = &self.app.db;
        let mut tx = db.begin_tenant_untimed(claim.workspace_id).await?;
        let row = sqlx::query(
            "SELECT kind, format, params, state, cursor, output_chunks, failed, created_by, via, \
                    lease_token FROM jobs WHERE id = $1 FOR UPDATE",
        )
        .bind(claim.id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            return Ok(Step::Lost);
        };
        let state: String = row.try_get("state")?;
        let token: Option<i64> = row.try_get("lease_token")?;
        if state != "running" || token != Some(claim.token) {
            return Ok(Step::Lost);
        }
        let kind: String = row.try_get("kind")?;
        let format: Option<String> = row.try_get("format")?;
        let created_by: String = row.try_get("created_by")?;
        let via: String = row.try_get("via")?;
        let job = Locked {
            kind: Kind::parse(&kind).ok_or_else(|| StepError::Fatal("unknown job kind".into()))?,
            format: format.as_deref().and_then(Format::parse),
            params: row.try_get("params")?,
            cursor: row.try_get("cursor")?,
            output_chunks: row.try_get("output_chunks")?,
            failed: row.try_get("failed")?,
        };
        let actor = Actor {
            member: Some(created_by),
            via: Via::parse(&via).unwrap_or(Via::System),
        };
        let tenant = db.tenant(claim.workspace_id).acting_as(actor);
        let step = match job.kind {
            Kind::Import => self.import_step(&tenant, &mut tx, claim, &job).await?,
            Kind::Export => self.export_step(&mut tx, claim, &job).await?,
            Kind::Patch => self.patch_step(&tenant, &mut tx, claim, &job).await?,
        };
        let (step, changed) = step;
        if let Step::Finished(state) = step {
            sqlx::query(
                "UPDATE jobs SET state = $2, finished_at = now(), lease_token = NULL, \
                        total = GREATEST(total, processed), failures = 0 \
                  WHERE id = $1",
            )
            .bind(claim.id)
            .bind(state)
            .execute(&mut *tx)
            .await?;
            if job.kind == Kind::Export || job.kind == Kind::Patch {
                // Links deleted while the job ran were never reached.
                sqlx::query("UPDATE jobs SET total = processed WHERE id = $1")
                    .bind(claim.id)
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query("DELETE FROM job_chunks WHERE job_id = $1 AND part = 'input'")
                .bind(claim.id)
                .execute(&mut *tx)
                .await?;
        } else {
            sqlx::query(
                "UPDATE jobs SET failures = 0, lease_until = now() + make_interval(secs => $2) \
                  WHERE id = $1",
            )
            .bind(claim.id)
            .bind(self.cfg.lease.as_secs_f64())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        // Change notifications reach the other instances; this one drops
        // its copies now.
        for (id, key) in changed {
            self.app.resolver.invalidate(&key);
            if let Some(id) = id {
                self.app.limiter.invalidate(id).await;
            }
        }
        Ok(step)
    }

    /// Imports the next chunk. A record that is refused (by the checks of
    /// `POST /v1/links`, a taken code, the plan's limit) is refused before
    /// anything of it is written, so the rest of the chunk goes in with
    /// it in one transaction, and with no subtransaction per record.
    async fn import_step(
        &self,
        tenant: &Tenant<'_>,
        tx: &mut Transaction<'static, Postgres>,
        claim: Claim,
        job: &Locked,
    ) -> Result<(Step, Vec<(Option<i64>, String)>), StepError> {
        let format = job
            .format
            .ok_or_else(|| StepError::Fatal("an import needs a format".into()))?;
        let chunk: Option<(i64, Vec<u8>)> = sqlx::query_as(
            "SELECT first_row, data FROM job_chunks \
              WHERE job_id = $1 AND part = 'input' AND seq = $2",
        )
        .bind(claim.id)
        .bind(job.cursor as i32)
        .fetch_optional(&mut **tx)
        .await?;
        let Some((first_row, data)) = chunk else {
            return Ok((Step::Finished("succeeded"), Vec::new()));
        };
        let columns: Vec<String> = match format {
            Format::Csv => serde_json::from_value(job.params["columns"].clone())
                .map_err(|_| StepError::Fatal("the import has no columns".into()))?,
            Format::Ndjson => Vec::new(),
        };
        let owner = tenant.actor().member.clone().unwrap_or_default();
        let records = chunk_records(&data, format);
        let mut errors: Vec<RowError> = Vec::new();
        let mut created = Vec::new();
        for (i, record) in records.iter().enumerate() {
            let row = first_row + i as i64;
            let fail = |code: &str, message: String| RowError {
                row,
                code: code.into(),
                message,
            };
            let parsed = match format {
                Format::Csv => csv_row(&columns, record),
                Format::Ndjson => ndjson_row(record),
            };
            let req = match parsed {
                Ok(r) => r,
                Err(m) => {
                    errors.push(fail("invalid_argument", m));
                    continue;
                }
            };
            let new = match validate_create(&self.app, owner.clone(), req).await {
                Ok(n) => n,
                Err(e) => {
                    errors.push(fail(e.code, e.message));
                    continue;
                }
            };
            // A taken random code is drawn again; nothing was written.
            let tries = if new.alias.is_some() { 1 } else { 5 };
            for attempt in 1..=tries {
                let code = new
                    .alias
                    .clone()
                    .unwrap_or_else(|| crate::code::random_code(self.app.cfg.code_length));
                match tenant.insert_in(tx, &new, &code).await? {
                    Ok(link) => {
                        created.push((None, link_key(link.domain_id, &link.code)));
                        break;
                    }
                    Err(DbError::Conflict) if attempt < tries => {}
                    Err(DbError::Conflict) if new.alias.is_none() => {
                        errors.push(fail(
                            "already_exists",
                            "could not allocate a unique code".into(),
                        ));
                    }
                    Err(e) => {
                        let e = ApiError::from(e);
                        errors.push(fail(e.code, e.message));
                        break;
                    }
                }
            }
        }
        let n = records.len() as i64;
        let bad = errors.len() as i64;
        store_errors(tx, claim.id, job.failed, &errors).await?;
        sqlx::query(
            "UPDATE jobs SET cursor = cursor + 1, processed = processed + $2, \
                    succeeded = succeeded + $3, failed = failed + $4 WHERE id = $1",
        )
        .bind(claim.id)
        .bind(n)
        .bind(n - bad)
        .bind(bad)
        .execute(&mut **tx)
        .await?;
        Ok((Step::Progress(records.len()), created))
    }

    /// Writes the next page of links as one output chunk.
    async fn export_step(
        &self,
        tx: &mut Transaction<'static, Postgres>,
        claim: Claim,
        job: &Locked,
    ) -> Result<(Step, Vec<(Option<i64>, String)>), StepError> {
        let format = job
            .format
            .ok_or_else(|| StepError::Fatal("an export needs a format".into()))?;
        let target: ExportTarget = serde_json::from_value(job.params.clone())
            .map_err(|_| StepError::Fatal("the export has no target".into()))?;
        let rows = sqlx::query(concat!(
            "SELECT ",
            api_columns!(),
            " FROM links WHERE id > $1 AND id <= $2 \
               AND ($3::bigint IS NULL OR COALESCE(domain_id, 0) = $3) \
             ORDER BY id LIMIT $4"
        ))
        .bind(job.cursor)
        .bind(target.max_id)
        .bind(target.domain_id)
        .bind(EXPORT_PAGE)
        .fetch_all(&mut **tx)
        .await?;
        if rows.is_empty() && job.output_chunks > 0 {
            return Ok((Step::Finished("succeeded"), Vec::new()));
        }
        let mut data = Vec::new();
        if job.output_chunks == 0 && format == Format::Csv {
            write_csv_line(&mut data, &EXPORT_COLUMNS);
        }
        let mut last = job.cursor;
        let mut n = 0usize;
        let base = self.app.db.base_url();
        for row in &rows {
            let link = self.app.db.row_to_link(row)?;
            match format {
                Format::Csv => export_csv_line(&mut data, &link, base),
                Format::Ndjson => {
                    let view = LinkView::new(&link, base);
                    serde_json::to_writer(&mut data, &view)
                        .map_err(|e| StepError::Fatal(e.to_string()))?;
                    data.push(b'\n');
                }
            }
            last = link.id;
            n += 1;
            if data.len() >= CHUNK_BYTES {
                break;
            }
        }
        let chunk = Chunk {
            first_row: job.cursor.max(0) + 1,
            rows: n,
            data,
        };
        insert_chunk(tx, claim.id, "output", job.output_chunks, &chunk).await?;
        sqlx::query(
            "UPDATE jobs SET cursor = $2, output_chunks = output_chunks + 1, \
                    processed = processed + $3, succeeded = succeeded + $3 WHERE id = $1",
        )
        .bind(claim.id)
        .bind(last)
        .bind(n as i64)
        .execute(&mut **tx)
        .await?;
        if rows.is_empty() {
            // An empty export: its file is the header alone.
            return Ok((Step::Finished("succeeded"), Vec::new()));
        }
        Ok((Step::Progress(n), Vec::new()))
    }

    /// Applies the patch to the next page of links, each as one
    /// `PATCH /v1/links/{code}` would.
    async fn patch_step(
        &self,
        tenant: &Tenant<'_>,
        tx: &mut Transaction<'static, Postgres>,
        claim: Claim,
        job: &Locked,
    ) -> Result<(Step, Vec<(Option<i64>, String)>), StepError> {
        let target: PatchTarget = serde_json::from_value(job.params["target"].clone())
            .map_err(|_| StepError::Fatal("the patch has no target".into()))?;
        let req: PatchLink = serde_json::from_value(job.params["patch"].clone())
            .map_err(|e| StepError::Fatal(format!("patch: {e}")))?;
        // Checked again: a time in the future when the job was made may
        // have passed.
        let patch = validate_patch(&self.app, req)
            .await
            .map_err(|e| StepError::Fatal(format!("patch: {}", e.message)))?;
        let rows = sqlx::query(concat!(
            "SELECT ",
            columns!(),
            " FROM links WHERE id > $1 AND id <= $2 \
               AND ($3::text[] IS NULL OR code = ANY ($3)) \
               AND ($4::bigint IS NULL OR COALESCE(domain_id, 0) = $4) \
             ORDER BY id LIMIT $5 FOR NO KEY UPDATE"
        ))
        .bind(job.cursor)
        .bind(target.max_id)
        .bind(&target.codes)
        .bind(target.domain_id)
        .bind(PATCH_PAGE)
        .fetch_all(&mut **tx)
        .await?;
        if rows.is_empty() {
            return Ok((Step::Finished("succeeded"), Vec::new()));
        }
        let mut changed = Vec::with_capacity(rows.len());
        let mut last = job.cursor;
        for row in &rows {
            let link = tenant.apply_patch(tx, row, &patch, Edit::UPDATE).await?;
            last = link.id;
            changed.push((Some(link.id), link_key(link.domain_id, &link.code)));
        }
        let n = rows.len() as i64;
        sqlx::query(
            "UPDATE jobs SET cursor = $2, processed = processed + $3, succeeded = succeeded + $3 \
              WHERE id = $1",
        )
        .bind(claim.id)
        .bind(last)
        .bind(n)
        .execute(&mut **tx)
        .await?;
        Ok((Step::Progress(rows.len()), changed))
    }

    /// Runs until `stop` turns true: a round after another while there are
    /// jobs, otherwise one every `poll`.
    pub async fn run(self, mut stop: watch::Receiver<bool>) {
        let mut last_purge: Option<Instant> = None;
        loop {
            if last_purge.is_none_or(|t| t.elapsed() >= PURGE_EVERY) {
                last_purge = Some(Instant::now());
                match self
                    .app
                    .db
                    .purge_jobs(self.cfg.retention_days, PURGE_BATCH)
                    .await
                {
                    Ok(0) => {}
                    Ok(n) => tracing::debug!(jobs = n, "old jobs purged"),
                    Err(e) => {
                        self.app.metrics.db_error(DbOp::Job);
                        tracing::warn!(error = %e, "could not purge old jobs");
                    }
                }
            }
            let busy = tokio::select! {
                b = self.round() => b,
                _ = stopped(&mut stop) => return,
            };
            if !busy {
                tokio::select! {
                    _ = tokio::time::sleep(self.cfg.poll) => {}
                    _ = stopped(&mut stop) => return,
                }
            }
        }
    }
}

/// A failed step, for tests: its message and whether it was final.
#[derive(Debug)]
pub struct StepErrorView(StepError);

impl StepErrorView {
    pub fn is_fatal(&self) -> bool {
        matches!(self.0, StepError::Fatal(_))
    }
}

impl fmt::Display for StepErrorView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            StepError::Retry(e) => e.fmt(f),
            StepError::Fatal(m) => f.write_str(m),
        }
    }
}

// The API.

fn job_not_found(id: i64) -> impl Fn(DbError) -> ApiError {
    move |e| match e {
        DbError::NotFound => ApiError::not_found_msg(format!("no job {id}")),
        e => e.into(),
    }
}

fn accepted(view: &JobView) -> Response {
    let mut resp = json(StatusCode::ACCEPTED, view);
    if let Ok(v) = HeaderValue::from_str(&format!("/v1/jobs/{}", view.id)) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}

/// `POST /v1/jobs/import`: the file is the body.
pub async fn create_import(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksWrite>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    let format = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(Format::from_content_type)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                "Content-Type must be text/csv or application/x-ndjson",
            )
        })?;
    let view = ws
        .tenant(&app.db)
        .create_import(format, body, app.cfg.jobs.max_upload)
        .await?;
    tracing::info!(job = view.id, rows = view.total, "import queued");
    Ok(accepted(&view))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateExport {
    pub format: Format,
    /// Only the links on this domain; every link when absent.
    pub domain: Option<String>,
}

/// `POST /v1/jobs/export`.
pub async fn create_export(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksRead>,
    StrictJson(req): StrictJson<CreateExport>,
) -> Result<Response, ApiError> {
    let domain = domain_param(req.domain);
    let view = ws
        .tenant(&app.db)
        .create_export(req.format, domain.as_deref())
        .await?;
    Ok(accepted(&view))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchFilter {
    /// These codes, on `domain` (the default domain when absent).
    pub codes: Option<Vec<String>>,
    /// Every link, or every link on `domain`.
    pub all: Option<bool>,
    pub domain: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatePatch {
    pub filter: PatchFilter,
    /// A `PATCH /v1/links/{code}` body.
    pub patch: Value,
}

/// `POST /v1/jobs/patch`.
pub async fn create_patch(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksWrite>,
    StrictJson(req): StrictJson<CreatePatch>,
) -> Result<Response, ApiError> {
    let codes = match (req.filter.codes, req.filter.all) {
        (Some(_), Some(true)) => {
            return Err(ApiError::invalid("filter: give codes or all, not both"));
        }
        (Some(codes), _) => {
            if codes.is_empty() || codes.len() > MAX_PATCH_CODES {
                return Err(ApiError::invalid(format!(
                    "filter.codes must have 1 to {MAX_PATCH_CODES} entries"
                )));
            }
            let mut unique: Vec<String> = Vec::with_capacity(codes.len());
            for c in codes {
                if !unique.contains(&c) {
                    unique.push(c);
                }
            }
            Some(unique)
        }
        (None, Some(true)) => None,
        (None, _) => return Err(ApiError::invalid("filter: give codes, or all: true")),
    };
    let parsed: PatchLink = serde_json::from_value(req.patch.clone())
        .map_err(|e| ApiError::invalid(format!("patch: {e}")))?;
    // Checked now, so a bad patch is refused rather than failing later.
    validate_patch(&app, parsed)
        .await
        .map_err(|e| ApiError::invalid(format!("patch: {}", e.message)))?;
    let domain = domain_param(req.filter.domain);
    let view = ws
        .tenant(&app.db)
        .create_patch(codes, domain.as_deref(), &req.patch)
        .await?;
    Ok(accepted(&view))
}

#[derive(Debug, Serialize)]
struct JobList {
    jobs: Vec<JobView>,
    next_cursor: Option<String>,
}

/// `GET /v1/jobs`.
pub async fn list_jobs(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksRead>,
    StrictQuery(q): StrictQuery<ListQuery>,
) -> Result<Response, ApiError> {
    let limit = q.limit.unwrap_or(crate::api::DEFAULT_PAGE);
    if !(1..=crate::api::MAX_PAGE).contains(&limit) {
        return Err(ApiError::invalid(format!(
            "limit must be 1 to {}",
            crate::api::MAX_PAGE
        )));
    }
    let before = match q.cursor.as_deref() {
        None => None,
        Some(c) => Some(decode_cursor(c).ok_or_else(|| ApiError::invalid("cursor is not valid"))?),
    };
    let mut jobs = app
        .db
        .tenant(ws.id)
        .jobs(before, i64::from(limit) + 1)
        .await?;
    let next_cursor = if jobs.len() > limit as usize {
        jobs.truncate(limit as usize);
        jobs.last().map(|j| encode_cursor(j.id))
    } else {
        None
    };
    Ok(json(StatusCode::OK, &JobList { jobs, next_cursor }))
}

/// `GET /v1/jobs/{id}`.
pub async fn get_job(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksRead>,
    Path(id): Path<i64>,
) -> Result<Response, ApiError> {
    let view = app
        .db
        .tenant(ws.id)
        .job(id)
        .await
        .map_err(job_not_found(id))?;
    Ok(json(StatusCode::OK, &view))
}

/// `POST /v1/jobs/{id}/cancel`.
pub async fn cancel_job(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksWrite>,
    Path(id): Path<i64>,
) -> Result<Response, ApiError> {
    let view = ws
        .tenant(&app.db)
        .cancel_job(id)
        .await
        .map_err(job_not_found(id))?;
    tracing::info!(job = id, "job cancelled");
    Ok(json(StatusCode::OK, &view))
}

/// `GET /v1/jobs/{id}/output`: a finished export's file, streamed one
/// chunk at a time.
pub async fn job_output(
    State(app): State<Arc<App>>,
    ws: Allowed<LinksRead>,
    Path(id): Path<i64>,
) -> Result<Response, ApiError> {
    let tenant = app.db.tenant(ws.id);
    let view = tenant.job(id).await.map_err(job_not_found(id))?;
    let (Kind::Export, Some(format)) = (view.kind, view.format) else {
        return Err(ApiError::failed_precondition("only an export has a file"));
    };
    if view.state != "succeeded" {
        return Err(ApiError::failed_precondition(format!(
            "the export has not succeeded; it is {}",
            view.state
        )));
    }
    let first = tenant
        .output_chunk(id, 0)
        .await?
        .ok_or_else(|| ApiError::not_found_msg("the export's file is gone"))?;
    let db = app.db.clone();
    let workspace = ws.id;
    let rest = futures_util::stream::unfold(1i32, move |seq| {
        let db = db.clone();
        async move {
            match db.tenant(workspace).output_chunk(id, seq).await {
                Ok(Some(data)) => Some((Ok::<_, DbError>(Bytes::from(data)), seq + 1)),
                Ok(None) => None,
                Err(e) => {
                    tracing::warn!(error = %e, job = id, "export download cut short");
                    Some((Err(e), i32::MAX))
                }
            }
        }
    });
    let stream = futures_util::stream::once(async move { Ok(Bytes::from(first)) }).chain(rest);
    let filename = format!("attachment; filename=\"links-{id}.{}\"", format.as_str());
    Ok((
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(format.content_type()),
            ),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&filename).unwrap_or(HeaderValue::from_static("attachment")),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        Body::from_stream(stream),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split_all(
        format: Format,
        pieces: &[&[u8]],
    ) -> Result<(Option<Vec<u8>>, Vec<Chunk>), SplitError> {
        let mut s = Splitter::new(format);
        let mut chunks = Vec::new();
        for p in pieces {
            s.push(p)?;
            chunks.extend(s.take_ready());
        }
        s.finish()?;
        chunks.extend(s.take_ready());
        Ok((s.header().map(<[u8]>::to_vec), chunks))
    }

    fn records(chunks: &[Chunk], format: Format) -> Vec<String> {
        chunks
            .iter()
            .flat_map(|c| chunk_records(&c.data, format))
            .map(|r| String::from_utf8(r.to_vec()).unwrap())
            .collect()
    }

    #[test]
    fn csv_records_end_at_newlines_outside_quotes() {
        let file = b"\xef\xbb\xbfcode,url\r\na,\"https://x.test/?q=1,2\"\r\n\r\nb,\"line\none\"\nc,\"say \"\"hi\"\"\"";
        // Every way of cutting the file into two pieces reads the same.
        for cut in 0..=file.len() {
            let (header, chunks) = split_all(Format::Csv, &[&file[..cut], &file[cut..]]).unwrap();
            assert_eq!(header.as_deref(), Some(&b"code,url"[..]), "cut {cut}");
            assert_eq!(
                records(&chunks, Format::Csv),
                [
                    "a,\"https://x.test/?q=1,2\"",
                    "b,\"line\none\"",
                    "c,\"say \"\"hi\"\"\""
                ],
                "cut {cut}"
            );
        }
        let (_, chunks) = split_all(Format::Csv, &[file]).unwrap();
        let fields: Vec<Vec<String>> = records(&chunks, Format::Csv)
            .iter()
            .map(|r| parse_csv_record(r.as_bytes()).unwrap())
            .collect();
        assert_eq!(fields[0], ["a", "https://x.test/?q=1,2"]);
        assert_eq!(fields[1], ["b", "line\none"]);
        assert_eq!(fields[2], ["c", "say \"hi\""]);
    }

    #[test]
    fn ndjson_records_are_lines() {
        let (header, chunks) = split_all(
            Format::Ndjson,
            &[b"{\"url\":\"a\"}\n\n  \n{\"url\":", b"\"b\"}"],
        )
        .unwrap();
        assert_eq!(header, None);
        assert_eq!(
            records(&chunks, Format::Ndjson),
            ["{\"url\":\"a\"}", "{\"url\":\"b\"}"]
        );
    }

    #[test]
    fn chunks_hold_whole_records_and_number_them() {
        let mut file = b"url\n".to_vec();
        for i in 0..1_234 {
            file.extend_from_slice(format!("https://x.test/{i}\n").as_bytes());
        }
        let (_, chunks) = split_all(Format::Csv, &[&file]).unwrap();
        assert_eq!(chunks.len(), 3);
        assert_eq!(
            chunks
                .iter()
                .map(|c| (c.first_row, c.rows))
                .collect::<Vec<_>>(),
            [(1, 500), (501, 500), (1001, 234)]
        );
        assert!(chunks[2].data.ends_with(b"https://x.test/1233\n"));
        // Big records close a chunk before it has CHUNK_ROWS of them.
        let mut big = b"url\n".to_vec();
        for _ in 0..30 {
            big.extend_from_slice(&[b'a'; 50_000]);
            big.push(b'\n');
        }
        let (_, chunks) = split_all(Format::Csv, &[&big]).unwrap();
        assert_eq!(
            chunks
                .iter()
                .map(|c| (c.first_row, c.rows))
                .collect::<Vec<_>>(),
            [(1, 21), (22, 9)]
        );
    }

    #[test]
    fn uploads_are_refused_for_long_records_and_open_quotes() {
        let long = vec![b'a'; MAX_RECORD + 2];
        assert_eq!(
            split_all(Format::Csv, &[&long]).unwrap_err(),
            SplitError::TooLong(0)
        );
        let mut two = b"url\nhttps://x.test/\n".to_vec();
        two.extend_from_slice(&long);
        assert_eq!(
            split_all(Format::Ndjson, &[&two]).unwrap_err(),
            SplitError::TooLong(3)
        );
        assert_eq!(
            split_all(Format::Csv, &[b"url\n\"https://x.test/\n"]).unwrap_err(),
            SplitError::Unterminated
        );
        assert_eq!(
            SplitError::TooLong(0).to_string(),
            "the header is longer than 65536 bytes"
        );
        assert_eq!(
            SplitError::TooLong(3).to_string(),
            "row 3 is longer than 65536 bytes"
        );
        // Exactly the limit is fine, with or without \r.
        let mut ok = vec![b'a'; MAX_RECORD];
        ok.extend_from_slice(b"\r\n");
        assert!(split_all(Format::Ndjson, &[&ok]).is_ok());
    }

    #[test]
    fn malformed_csv_records_are_named() {
        for (bad, why) in [
            (&b"a,b\"c"[..], "a quote inside a field that is not quoted"),
            (b"\"a\"b", "a quoted field must be followed by a comma"),
            (b"\"a", "a quoted field is not closed"),
            (b"\xff", "the row is not valid UTF-8"),
        ] {
            assert_eq!(parse_csv_record(bad).unwrap_err(), why);
        }
        assert_eq!(parse_csv_record(b"").unwrap(), [""]);
        assert_eq!(parse_csv_record(b",").unwrap(), ["", ""]);
        assert_eq!(parse_csv_record(b"\"\",x").unwrap(), ["", "x"]);
    }

    #[test]
    fn csv_fields_round_trip() {
        for fields in [
            vec![
                "plain",
                "with,comma",
                "with \"quotes\"",
                "two\nlines",
                "cr\r",
                "",
            ],
            vec!["", ""],
            vec!["\""],
        ] {
            let mut line = Vec::new();
            write_csv_line(&mut line, &fields);
            assert_eq!(line.pop(), Some(b'\n'));
            assert_eq!(parse_csv_record(&line).unwrap(), fields);
        }
    }

    #[test]
    fn headers_name_known_columns_once() {
        assert_eq!(
            parse_header(b"code, url ,short_url").unwrap(),
            ["code", "url", "short_url"]
        );
        let mut all = Vec::new();
        write_csv_line(&mut all, &EXPORT_COLUMNS);
        all.pop();
        assert_eq!(parse_header(&all).unwrap(), EXPORT_COLUMNS);
        assert!(
            parse_header(b"code,url,colour")
                .unwrap_err()
                .contains("\"colour\"")
        );
        assert_eq!(
            parse_header(b"url,url").unwrap_err(),
            "the header names \"url\" twice"
        );
        assert_eq!(
            parse_header(b"code").unwrap_err(),
            "the header has no url column"
        );
        assert!(
            parse_header(b"\"url")
                .unwrap_err()
                .starts_with("the header: ")
        );
    }

    #[test]
    fn csv_rows_become_create_requests() {
        let columns: Vec<String> = [
            "code",
            "url",
            "domain",
            "redirect_type",
            "expires_at",
            "max_clicks",
            "enabled",
            "health_check",
            "fallback_url",
            "conversion_window_days",
            "version",
        ]
        .map(String::from)
        .to_vec();
        let req = csv_row(
            &columns,
            b"spring,https://x.test/,go.x.test,301,2030-01-02T03:04:05+01:00,10,false,true,https://f.test/,30,7",
        )
        .unwrap();
        assert_eq!(req.alias.as_deref(), Some("spring"));
        assert_eq!(req.url.as_deref(), Some("https://x.test/"));
        assert_eq!(req.domain.as_deref(), Some("go.x.test"));
        assert_eq!(req.redirect_type, Some(301));
        assert_eq!(
            req.expires_at.unwrap().to_rfc3339(),
            "2030-01-02T02:04:05+00:00"
        );
        assert_eq!(req.max_clicks, Some(10));
        assert_eq!(req.enabled, Some(false));
        assert_eq!(req.health_check, Some(true));
        assert_eq!(req.fallback_url.as_deref(), Some("https://f.test/"));
        assert_eq!(req.conversion_window_days, Some(30));
        let empty = csv_row(&columns, b",https://x.test/,,,,,,,,,").unwrap();
        assert_eq!(empty.alias, None);
        assert_eq!(empty.enabled, None);
        for (record, why) in [
            (&b"a,b"[..], "the row has 2 fields; the header has 11"),
            (
                b",u,,x,,,,,,,",
                "redirect_type: must be 301, 302, 307 or 308",
            ),
            (
                b",u,,,tomorrow,,,,,,",
                "expires_at: must be an RFC 3339 time",
            ),
            (b",u,,,,-,,,,,", "max_clicks: must be a number"),
            (b",u,,,,,yes,,,,", "enabled: must be true or false"),
            (b",u,,,,,,1,,,", "health_check: must be true or false"),
            (
                b",u,,,,,,,,month,",
                "conversion_window_days: must be a number",
            ),
        ] {
            assert_eq!(csv_row(&columns, record).unwrap_err(), why);
        }
    }

    #[test]
    fn ndjson_rows_are_create_bodies() {
        let req =
            ndjson_row(br#"{"alias":"a","destinations":[{"url":"https://x.test/","weight":2}]}"#)
                .unwrap();
        assert_eq!(req.alias.as_deref(), Some("a"));
        assert_eq!(req.destinations.unwrap()[0].weight, 2);
        assert!(
            ndjson_row(br#"{"colour":"red"}"#)
                .unwrap_err()
                .starts_with("invalid JSON: ")
        );
    }

    #[test]
    fn content_types_name_formats() {
        assert_eq!(Format::from_content_type("text/csv"), Some(Format::Csv));
        assert_eq!(
            Format::from_content_type("Text/CSV; charset=utf-8"),
            Some(Format::Csv)
        );
        assert_eq!(
            Format::from_content_type("application/x-ndjson"),
            Some(Format::Ndjson)
        );
        assert_eq!(
            Format::from_content_type("application/jsonl"),
            Some(Format::Ndjson)
        );
        assert_eq!(Format::from_content_type("application/json"), None);
        assert_eq!(Format::from_content_type(""), None);
        for k in [Kind::Import, Kind::Export, Kind::Patch] {
            assert_eq!(Kind::parse(k.as_str()), Some(k));
        }
        assert_eq!(Kind::parse("delete"), None);
        assert_eq!(Format::parse("xml"), None);
    }

    proptest::proptest! {
        #[test]
        fn any_cut_of_any_csv_reads_the_same(
            rows in proptest::collection::vec(
                proptest::collection::vec("[a-z,\"\n\r ]{0,6}", 1..4), 1..20),
            cuts in proptest::collection::vec(0usize..400, 0..6),
        ) {
            let mut file = b"url\n".to_vec();
            let mut expected = Vec::new();
            for r in &rows {
                let mut line = Vec::new();
                write_csv_line(&mut line, r);
                file.extend_from_slice(&line);
                line.pop();
                if trim_record(&line).is_some() {
                    expected.push(r.clone());
                }
            }
            let mut cuts: Vec<usize> = cuts.into_iter().map(|c| c.min(file.len())).collect();
            cuts.sort_unstable();
            let mut pieces = Vec::new();
            let mut at = 0;
            for c in cuts {
                pieces.push(&file[at..c]);
                at = c;
            }
            pieces.push(&file[at..]);
            let (_, chunks) = split_all(Format::Csv, &pieces).unwrap();
            let got: Vec<Vec<String>> = chunks
                .iter()
                .flat_map(|c| chunk_records(&c.data, Format::Csv))
                .map(|r| parse_csv_record(r).unwrap())
                .collect();
            proptest::prop_assert_eq!(got, expected);
        }
    }
}
