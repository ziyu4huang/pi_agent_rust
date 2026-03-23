use crate::error::{Error, Result};
use crate::session::{SessionEntry, SessionHeader};
use crate::session_metrics;
use sqlmodel_core::{Error as SqliteError, Row as SqliteRow, Value as SqliteValue};
use sqlmodel_sqlite::{OpenFlags, SqliteConfig, SqliteConnection};
use std::fmt::Write as _;
use std::path::Path;

const INIT_SQL: &str = r"
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS pi_session_header (
  id TEXT PRIMARY KEY,
  json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pi_session_entries (
  seq INTEGER PRIMARY KEY,
  json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pi_session_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
";

#[derive(Debug, Clone)]
pub struct SqliteSessionMeta {
    pub header: SessionHeader,
    pub message_count: u64,
    pub name: Option<String>,
}

fn map_sqlite_result<T>(result: std::result::Result<T, SqliteError>) -> Result<T> {
    result.map_err(|err| Error::session(format!("SQLite session error: {err}")))
}

fn open_sqlite_connection_read_only(path: &Path) -> Result<SqliteConnection> {
    let config = SqliteConfig::file(path.to_string_lossy()).flags(OpenFlags::read_only());
    map_sqlite_result(SqliteConnection::open(&config))
}

fn open_sqlite_connection_read_write(path: &Path) -> Result<SqliteConnection> {
    let config = SqliteConfig::file(path.to_string_lossy()).flags(OpenFlags::create_read_write());
    map_sqlite_result(SqliteConnection::open(&config))
}

fn row_get_string(row: &SqliteRow, column: &str) -> Result<String> {
    row.get_named::<String>(column)
        .map_err(|err| Error::session(format!("SQLite row read failed: {err}")))
}

fn rollback_quietly(conn: &SqliteConnection) {
    let _ = conn.execute_raw("ROLLBACK");
}

fn compute_message_count_and_name(entries: &[SessionEntry]) -> (u64, Option<String>) {
    let mut message_count = 0u64;
    let mut name = None;

    for entry in entries {
        match entry {
            SessionEntry::Message(_) => message_count += 1,
            SessionEntry::SessionInfo(info) => {
                if info.name.is_some() {
                    name.clone_from(&info.name);
                }
            }
            _ => {}
        }
    }

    (message_count, name)
}

pub async fn load_session(path: &Path) -> Result<(SessionHeader, Vec<SessionEntry>)> {
    let metrics = session_metrics::global();
    let _timer = metrics.start_timer(&metrics.sqlite_load);

    if !path.exists() {
        return Err(Error::SessionNotFound {
            path: path.display().to_string(),
        });
    }

    let conn = open_sqlite_connection_read_only(path)?;

    let header_rows =
        map_sqlite_result(conn.query_sync("SELECT json FROM pi_session_header LIMIT 1", &[]))?;
    let header_row = header_rows
        .first()
        .ok_or_else(|| Error::session("SQLite session missing header row"))?;
    let header_json = row_get_string(header_row, "json")?;
    let header: SessionHeader = serde_json::from_str(&header_json)?;
    header
        .validate()
        .map_err(|reason| Error::session(format!("Invalid session header: {reason}")))?;

    let entry_rows = map_sqlite_result(
        conn.query_sync("SELECT json FROM pi_session_entries ORDER BY seq ASC", &[]),
    )?;

    let mut entries = Vec::with_capacity(entry_rows.len());
    for row in entry_rows {
        let json = row_get_string(&row, "json")?;
        let entry: SessionEntry = serde_json::from_str(&json)?;
        entries.push(entry);
    }

    Ok((header, entries))
}

pub async fn load_session_meta(path: &Path) -> Result<SqliteSessionMeta> {
    let metrics = session_metrics::global();
    let _timer = metrics.start_timer(&metrics.sqlite_load_meta);

    if !path.exists() {
        return Err(Error::SessionNotFound {
            path: path.display().to_string(),
        });
    }

    let conn = open_sqlite_connection_read_only(path)?;

    let header_rows =
        map_sqlite_result(conn.query_sync("SELECT json FROM pi_session_header LIMIT 1", &[]))?;
    let header_row = header_rows
        .first()
        .ok_or_else(|| Error::session("SQLite session missing header row"))?;
    let header_json = row_get_string(header_row, "json")?;
    let header: SessionHeader = serde_json::from_str(&header_json)?;
    header
        .validate()
        .map_err(|reason| Error::session(format!("Invalid session header: {reason}")))?;

    let meta_rows = conn
        .query_sync(
            "SELECT key,value FROM pi_session_meta WHERE key IN ('message_count','name')",
            &[],
        )
        .unwrap_or_default();

    let mut message_count: Option<u64> = None;
    let mut name: Option<String> = None;
    for row in meta_rows {
        let key = row_get_string(&row, "key")?;
        let value = row_get_string(&row, "value")?;
        match key.as_str() {
            "message_count" => message_count = value.parse::<u64>().ok(),
            "name" => {
                if !value.is_empty() {
                    name = Some(value);
                }
            }
            _ => {}
        }
    }

    let message_count = if let Some(message_count) = message_count {
        message_count
    } else {
        let entry_rows = map_sqlite_result(
            conn.query_sync("SELECT json FROM pi_session_entries ORDER BY seq ASC", &[]),
        )?;

        let mut entries = Vec::with_capacity(entry_rows.len());
        for row in entry_rows {
            let json = row_get_string(&row, "json")?;
            let entry: SessionEntry = serde_json::from_str(&json)?;
            entries.push(entry);
        }

        let (message_count, fallback_name) = compute_message_count_and_name(&entries);
        if name.is_none() {
            name = fallback_name;
        }
        message_count
    };
    Ok(SqliteSessionMeta {
        header,
        message_count,
        name,
    })
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use crate::model::UserContent;
    use crate::session::{EntryBase, MessageEntry, SessionInfoEntry, SessionMessage};

    fn dummy_base() -> EntryBase {
        EntryBase {
            id: Some("test-id".to_string()),
            parent_id: None,
            timestamp: "2026-01-01T00:00:00.000Z".to_string(),
        }
    }

    fn message_entry() -> SessionEntry {
        SessionEntry::Message(MessageEntry {
            base: dummy_base(),
            message: SessionMessage::User {
                content: UserContent::Text("hello".to_string()),
                timestamp: None,
            },
        })
    }

    fn session_info_entry(name: Option<String>) -> SessionEntry {
        SessionEntry::SessionInfo(SessionInfoEntry {
            base: dummy_base(),
            name,
        })
    }

    #[test]
    fn compute_counts_empty() {
        let (count, name) = compute_message_count_and_name(&[]);
        assert_eq!(count, 0);
        assert!(name.is_none());
    }

    #[test]
    fn compute_counts_messages_only() {
        let entries = vec![message_entry(), message_entry(), message_entry()];
        let (count, name) = compute_message_count_and_name(&entries);
        assert_eq!(count, 3);
        assert!(name.is_none());
    }

    #[test]
    fn compute_counts_session_info_with_name() {
        let entries = vec![
            message_entry(),
            session_info_entry(Some("My Session".to_string())),
            message_entry(),
        ];
        let (count, name) = compute_message_count_and_name(&entries);
        assert_eq!(count, 2);
        assert_eq!(name, Some("My Session".to_string()));
    }

    #[test]
    fn compute_counts_session_info_none_name_ignored() {
        let entries = vec![
            session_info_entry(Some("First".to_string())),
            session_info_entry(None),
            message_entry(),
        ];
        let (count, name) = compute_message_count_and_name(&entries);
        assert_eq!(count, 1);
        // The second SessionInfo has name=None, so it doesn't overwrite.
        assert_eq!(name, Some("First".to_string()));
    }

    #[test]
    fn compute_counts_latest_name_wins() {
        let entries = vec![
            session_info_entry(Some("First".to_string())),
            session_info_entry(Some("Second".to_string())),
        ];
        let (_, name) = compute_message_count_and_name(&entries);
        assert_eq!(name, Some("Second".to_string()));
    }

    // -- Non-message / non-session-info entries are ignored --

    #[test]
    fn compute_counts_ignores_model_change_entries() {
        use crate::session::ModelChangeEntry;
        let entries = vec![
            message_entry(),
            SessionEntry::ModelChange(ModelChangeEntry {
                base: dummy_base(),
                provider: "anthropic".to_string(),
                model_id: "claude-sonnet-4-5".to_string(),
            }),
            message_entry(),
        ];
        let (count, name) = compute_message_count_and_name(&entries);
        assert_eq!(count, 2);
        assert!(name.is_none());
    }

    #[test]
    fn compute_counts_ignores_label_entries() {
        use crate::session::LabelEntry;
        let entries = vec![
            message_entry(),
            SessionEntry::Label(LabelEntry {
                base: dummy_base(),
                target_id: "some-id".to_string(),
                label: Some("important".to_string()),
            }),
        ];
        let (count, name) = compute_message_count_and_name(&entries);
        assert_eq!(count, 1);
        assert!(name.is_none());
    }

    #[test]
    fn compute_counts_ignores_custom_entries() {
        use crate::session::CustomEntry;
        let entries = vec![
            SessionEntry::Custom(CustomEntry {
                base: dummy_base(),
                custom_type: "my_custom".to_string(),
                data: Some(serde_json::json!({"key": "value"})),
            }),
            message_entry(),
        ];
        let (count, name) = compute_message_count_and_name(&entries);
        assert_eq!(count, 1);
        assert!(name.is_none());
    }

    #[test]
    fn compute_counts_ignores_compaction_entries() {
        use crate::session::CompactionEntry;
        let entries = vec![
            message_entry(),
            SessionEntry::Compaction(CompactionEntry {
                base: dummy_base(),
                summary: "summary text".to_string(),
                first_kept_entry_id: "e1".to_string(),
                tokens_before: 500,
                details: None,
                from_hook: None,
            }),
            message_entry(),
            message_entry(),
        ];
        let (count, name) = compute_message_count_and_name(&entries);
        assert_eq!(count, 3);
        assert!(name.is_none());
    }

    #[test]
    fn compute_counts_mixed_entry_types() {
        use crate::session::{CompactionEntry, CustomEntry, LabelEntry, ModelChangeEntry};
        let entries = vec![
            message_entry(),
            SessionEntry::ModelChange(ModelChangeEntry {
                base: dummy_base(),
                provider: "openai".to_string(),
                model_id: "gpt-4".to_string(),
            }),
            session_info_entry(Some("Named".to_string())),
            SessionEntry::Label(LabelEntry {
                base: dummy_base(),
                target_id: "t1".to_string(),
                label: None,
            }),
            message_entry(),
            SessionEntry::Compaction(CompactionEntry {
                base: dummy_base(),
                summary: "s".to_string(),
                first_kept_entry_id: "e1".to_string(),
                tokens_before: 100,
                details: None,
                from_hook: None,
            }),
            SessionEntry::Custom(CustomEntry {
                base: dummy_base(),
                custom_type: "ct".to_string(),
                data: None,
            }),
            message_entry(),
        ];
        let (count, name) = compute_message_count_and_name(&entries);
        assert_eq!(count, 3);
        assert_eq!(name, Some("Named".to_string()));
    }

    // -- map_sqlite_result tests --

    #[test]
    fn map_sqlite_result_ok() {
        let result = map_sqlite_result::<i32>(Ok(42));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn map_sqlite_result_err() {
        let config = SqliteConfig::file("bad\0path").flags(OpenFlags::create_read_write());
        let result = map_sqlite_result::<i32>(SqliteConnection::open(&config).map(|_| 42));
        let err = result.unwrap_err();
        match err {
            Error::Session(message) => {
                assert!(message.contains("SQLite session error"));
            }
            other => unreachable!("Unexpected error: {:?}", other),
        }
    }

    // -- SqliteSessionMeta struct --

    #[test]
    fn sqlite_session_meta_fields() {
        let meta = SqliteSessionMeta {
            header: SessionHeader {
                id: "test-session".to_string(),
                ..SessionHeader::default()
            },
            message_count: 42,
            name: Some("My Session".to_string()),
        };
        assert_eq!(meta.header.id, "test-session");
        assert_eq!(meta.message_count, 42);
        assert_eq!(meta.name.as_deref(), Some("My Session"));
    }

    #[test]
    fn sqlite_session_meta_no_name() {
        let meta = SqliteSessionMeta {
            header: SessionHeader::default(),
            message_count: 0,
            name: None,
        };
        assert_eq!(meta.message_count, 0);
        assert!(meta.name.is_none());
    }

    // -- compute_message_count_and_name: large input --

    #[test]
    fn compute_counts_large_message_set() {
        let entries: Vec<SessionEntry> = (0..1000).map(|_| message_entry()).collect();
        let (count, name) = compute_message_count_and_name(&entries);
        assert_eq!(count, 1000);
        assert!(name.is_none());
    }

    // -- compute_message_count_and_name: name then messages only --

    #[test]
    fn compute_counts_name_set_early_persists() {
        let entries = vec![
            session_info_entry(Some("Early Name".to_string())),
            message_entry(),
            message_entry(),
            message_entry(),
        ];
        let (count, name) = compute_message_count_and_name(&entries);
        assert_eq!(count, 3);
        assert_eq!(name, Some("Early Name".to_string()));
    }

    // -- compute_message_count_and_name: branch summary entry --

    #[test]
    fn compute_counts_ignores_branch_summary() {
        use crate::session::BranchSummaryEntry;
        let entries = vec![
            message_entry(),
            SessionEntry::BranchSummary(BranchSummaryEntry {
                base: dummy_base(),
                from_id: "parent-id".to_string(),
                summary: "branch summary".to_string(),
                details: None,
                from_hook: None,
            }),
        ];
        let (count, name) = compute_message_count_and_name(&entries);
        assert_eq!(count, 1);
        assert!(name.is_none());
    }

    // -- compute_message_count_and_name: thinking level change --

    #[test]
    fn compute_counts_ignores_thinking_level_change() {
        use crate::session::ThinkingLevelChangeEntry;
        let entries = vec![
            SessionEntry::ThinkingLevelChange(ThinkingLevelChangeEntry {
                base: dummy_base(),
                thinking_level: "high".to_string(),
            }),
            message_entry(),
        ];
        let (count, name) = compute_message_count_and_name(&entries);
        assert_eq!(count, 1);
        assert!(name.is_none());
    }

    #[test]
    fn save_session_rejects_semantically_invalid_header() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("invalid.sqlite");
        let header = SessionHeader {
            r#type: "note".to_string(),
            ..SessionHeader::default()
        };

        let err = futures::executor::block_on(async { save_session(&path, &header, &[]).await })
            .expect_err("invalid header should fail");
        let message = err.to_string();
        assert!(
            message.contains("Invalid session header"),
            "expected invalid session header error, got {message}"
        );
    }

    #[test]
    fn load_session_meta_rejects_semantically_invalid_header() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("invalid.sqlite");
        let header = SessionHeader {
            id: "sqlite-test".to_string(),
            ..SessionHeader::default()
        };

        futures::executor::block_on(async { save_session(&path, &header, &[]).await })
            .expect("save sqlite session");

        let invalid_header = SessionHeader {
            r#type: "note".to_string(),
            ..header
        };
        let invalid_json =
            serde_json::to_string(&invalid_header).expect("serialize invalid session header");
        let config = sqlmodel_sqlite::SqliteConfig::file(path.to_string_lossy())
            .flags(sqlmodel_sqlite::OpenFlags::create_read_write());
        let conn = sqlmodel_sqlite::SqliteConnection::open(&config).expect("open sqlite db");
        conn.execute_sync(
            "UPDATE pi_session_header SET json = ?1",
            &[sqlmodel_core::Value::Text(invalid_json)],
        )
        .expect("corrupt sqlite header row");

        let err = futures::executor::block_on(async { load_session_meta(&path).await })
            .expect_err("invalid header should fail");
        let message = err.to_string();
        assert!(
            message.contains("Invalid session header"),
            "expected invalid session header error, got {message}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_paths_accept_read_only_sqlite_files() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("readonly.sqlite");
        let header = SessionHeader {
            id: "sqlite-readonly".to_string(),
            ..SessionHeader::default()
        };
        let entries = vec![
            session_info_entry(Some("Read Only".to_string())),
            message_entry(),
        ];

        futures::executor::block_on(async { save_session(&path, &header, &entries).await })
            .expect("save sqlite session");

        let original_mode = std::fs::metadata(&path)
            .expect("sqlite metadata")
            .permissions()
            .mode();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444))
            .expect("chmod readonly sqlite");

        let (loaded_header, loaded_entries) =
            futures::executor::block_on(async { load_session(&path).await })
                .expect("load readonly sqlite session");
        let meta = futures::executor::block_on(async { load_session_meta(&path).await })
            .expect("load readonly sqlite meta");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(original_mode))
            .expect("restore sqlite permissions");

        assert_eq!(loaded_header.id, header.id);
        assert_eq!(loaded_entries.len(), entries.len());
        assert_eq!(meta.header.id, header.id);
        assert_eq!(meta.message_count, 1);
        assert_eq!(meta.name.as_deref(), Some("Read Only"));
    }
}

pub async fn save_session(
    path: &Path,
    header: &SessionHeader,
    entries: &[SessionEntry],
) -> Result<()> {
    header
        .validate()
        .map_err(|reason| Error::session(format!("Invalid session header: {reason}")))?;
    let metrics = session_metrics::global();
    let _save_timer = metrics.start_timer(&metrics.sqlite_save);

    if let Some(parent) = path.parent() {
        asupersync::fs::create_dir_all(parent).await?;
    }

    let conn = open_sqlite_connection_read_write(path)?;
    map_sqlite_result(conn.execute_raw(INIT_SQL))?;
    map_sqlite_result(conn.execute_raw("BEGIN IMMEDIATE"))?;

    // Serialize header + entries and track serialization time + bytes.
    let save_result = (|| -> Result<()> {
        map_sqlite_result(conn.execute_sync("DELETE FROM pi_session_entries", &[]))?;
        map_sqlite_result(conn.execute_sync("DELETE FROM pi_session_header", &[]))?;
        map_sqlite_result(conn.execute_sync("DELETE FROM pi_session_meta", &[]))?;

        let serialize_timer = metrics.start_timer(&metrics.sqlite_serialize);
        let header_json = serde_json::to_string(header)?;
        let mut total_json_bytes = header_json.len() as u64;

        let mut entry_jsons = Vec::with_capacity(entries.len());
        for entry in entries {
            let json = serde_json::to_string(entry)?;
            total_json_bytes += json.len() as u64;
            entry_jsons.push(json);
        }
        serialize_timer.finish();
        metrics.record_bytes(&metrics.sqlite_bytes, total_json_bytes);

        map_sqlite_result(conn.execute_sync(
            "INSERT INTO pi_session_header (id,json) VALUES (?1,?2)",
            &[
                SqliteValue::Text(header.id.clone()),
                SqliteValue::Text(header_json),
            ],
        ))?;

        let mut seq = 1_i64;
        for chunk in entry_jsons.chunks(200) {
            let mut sql = String::with_capacity(64 + chunk.len() * 16);
            sql.push_str("INSERT INTO pi_session_entries (seq,json) VALUES ");
            let mut params = Vec::with_capacity(chunk.len() * 2);
            for (i, json) in chunk.iter().enumerate() {
                if i > 0 {
                    sql.push(',');
                }
                let _ = write!(sql, "(?{},?{})", i * 2 + 1, i * 2 + 2);
                params.push(SqliteValue::BigInt(seq));
                params.push(SqliteValue::Text(json.clone()));
                seq += 1;
            }
            map_sqlite_result(conn.execute_sync(&sql, &params))?;
        }

        let (message_count, name) = compute_message_count_and_name(entries);
        map_sqlite_result(conn.execute_sync(
            "INSERT INTO pi_session_meta (key,value) VALUES (?1,?2)",
            &[
                SqliteValue::Text("message_count".to_string()),
                SqliteValue::Text(message_count.to_string()),
            ],
        ))?;
        let name_value = name.unwrap_or_default();
        map_sqlite_result(conn.execute_sync(
            "INSERT INTO pi_session_meta (key,value) VALUES (?1,?2)",
            &[
                SqliteValue::Text("name".to_string()),
                SqliteValue::Text(name_value),
            ],
        ))?;

        Ok(())
    })();

    match save_result {
        Ok(()) => {
            map_sqlite_result(conn.execute_raw("COMMIT"))?;
            Ok(())
        }
        Err(err) => {
            rollback_quietly(&conn);
            Err(err)
        }
    }
}

/// Incrementally append new entries to an existing SQLite session database.
///
/// Only the entries in `new_entries` (starting at 1-based sequence `start_seq`)
/// are inserted. The header row is left unchanged, while the `message_count`
/// and `name` meta rows are upserted to reflect the current totals.
///
/// This avoids the DELETE+reinsert cost of [`save_session`] for the common
/// case where a few entries are appended between saves.
pub async fn append_entries(
    path: &Path,
    new_entries: &[SessionEntry],
    start_seq: usize,
    message_count: u64,
    session_name: Option<&str>,
) -> Result<()> {
    let metrics = session_metrics::global();
    let _timer = metrics.start_timer(&metrics.sqlite_append);

    let conn = open_sqlite_connection_read_write(path)?;

    // Ensure WAL mode is active and tables exist (especially pi_session_meta for old DBs).
    map_sqlite_result(conn.execute_raw(INIT_SQL))?;
    map_sqlite_result(conn.execute_raw("BEGIN IMMEDIATE"))?;

    let append_result = (|| -> Result<()> {
        // Serialize and insert only the new entries.
        let serialize_timer = metrics.start_timer(&metrics.sqlite_serialize);
        let mut total_json_bytes = 0u64;
        let mut entry_jsons = Vec::with_capacity(new_entries.len());
        for entry in new_entries {
            let json = serde_json::to_string(entry)?;
            total_json_bytes += json.len() as u64;
            entry_jsons.push(json);
        }
        serialize_timer.finish();
        metrics.record_bytes(&metrics.sqlite_bytes, total_json_bytes);

        let mut seq = i64::try_from(start_seq)
            .unwrap_or(i64::MAX.saturating_sub(1))
            .saturating_add(1);
        for chunk in entry_jsons.chunks(200) {
            let mut sql = String::with_capacity(64 + chunk.len() * 16);
            sql.push_str("INSERT INTO pi_session_entries (seq,json) VALUES ");
            let mut params = Vec::with_capacity(chunk.len() * 2);
            for (i, json) in chunk.iter().enumerate() {
                if i > 0 {
                    sql.push(',');
                }
                let _ = write!(sql, "(?{},?{})", i * 2 + 1, i * 2 + 2);
                params.push(SqliteValue::BigInt(seq));
                params.push(SqliteValue::Text(json.clone()));
                seq += 1;
            }
            map_sqlite_result(conn.execute_sync(&sql, &params))?;
        }

        // Upsert meta counters (INSERT OR REPLACE).
        map_sqlite_result(conn.execute_sync(
            "INSERT OR REPLACE INTO pi_session_meta (key,value) VALUES (?1,?2)",
            &[
                SqliteValue::Text("message_count".to_string()),
                SqliteValue::Text(message_count.to_string()),
            ],
        ))?;
        let name_value = session_name.unwrap_or("");
        map_sqlite_result(conn.execute_sync(
            "INSERT OR REPLACE INTO pi_session_meta (key,value) VALUES (?1,?2)",
            &[
                SqliteValue::Text("name".to_string()),
                SqliteValue::Text(name_value.to_string()),
            ],
        ))?;

        Ok(())
    })();

    match append_result {
        Ok(()) => {
            map_sqlite_result(conn.execute_raw("COMMIT"))?;
            Ok(())
        }
        Err(err) => {
            rollback_quietly(&conn);
            Err(err)
        }
    }
}
